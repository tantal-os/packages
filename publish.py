import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
SHA = re.compile(r"[a-f0-9]{64}")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}")
MAX_APK = 2 * 1024**3
MAX_MODEL = 16 * 1024**3
INDEX_LIMIT = 4 * 1024**2


def load(path):
    return json.loads(path.read_bytes())


def require(valid, message):
    if not valid:
        raise ValueError(message)


def validate():
    definitions = [load(path) for path in sorted((ROOT / "definitions").glob("*.json"))]
    identities = set()
    for row in definitions:
        require(REPO.fullmatch(row["repository"]), "Invalid GitHub repository")
        require(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+", row["package"]),
                "Invalid Android package name")
        require(SHA.fullmatch(row["signer"]), "Invalid APK signer pin")
        require(0 < len(row["title"]) <= 100 and row["publisher"], "Invalid app name or publisher")
        require(row["asset"].count("{version}") == 1 and re.fullmatch(
            r"[A-Za-z0-9_.-]+\.apk", row["asset"].replace("{version}", "0.0.0")), "Invalid APK asset pattern")
        re.compile(row["tagPattern"])
        identity = (row["package"], row["signer"])
        require(identity not in identities, "Duplicate Android package and signer")
        identities.add(identity)

    models = load(ROOT / "models.json")
    for row in models:
        require(REPO.fullmatch(row["repository"]), "Invalid Hugging Face repository")
        require(re.fullmatch(r"[a-f0-9]{40}", row["commit"]), "Expected a full model commit hash")
        require(SHA.fullmatch(row["sha256"]), "Invalid manifest digest")
        require(all(NAME.fullmatch(row[field]) for field in ("package", "variant", "directory")),
                "Invalid model identifier")
        require(0 < len(row["label"]) <= 100 and 0 < len(row["title"]) <= 100, "Invalid model labels")
        require(0 < row["size"] <= MAX_MODEL and row["versionCode"] > 0 and row["minReader"] > 0,
                "Invalid model size or version")
        check_ed25519(row["publisher"])

    withdrawals = load(ROOT / "withdrawals.json")
    for row in withdrawals:
        require(row["kind"] in ("apk", "model") and SHA.fullmatch(row["sha256"]) and
                0 < len(row["reason"]) <= 500, "Invalid withdrawal")

    revocations = load(ROOT / "revocations.json")
    for row in revocations:
        verify_revocation(row)
    return definitions, models, withdrawals, revocations


def openssl(*args, input=None):
    return subprocess.run(["openssl", *map(str, args)], input=input, capture_output=True, check=True).stdout


def check_ed25519(key):
    der = base64.b64decode(key, validate=True)
    require(len(der) == 44 and der.startswith(bytes.fromhex("302a300506032b6570032100")),
            "Expected an Ed25519 SPKI key")
    return der


def verify_ed25519(key, payload, signature):
    require(len(signature) == 64, "Invalid Ed25519 signature size")
    with tempfile.TemporaryDirectory() as folder:
        key_path, payload_path, sig_path = (Path(folder, name) for name in ("key", "payload", "sig"))
        key_path.write_bytes(check_ed25519(key))
        payload_path.write_bytes(payload)
        sig_path.write_bytes(signature)
        openssl("pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", key_path,
                "-rawin", "-in", payload_path, "-sigfile", sig_path)


def verify_revocation(row):
    require(0 < len(row["payload"]) <= 4096 and 0 < len(row["signature"]) <= 2048 and
            0 < len(row["publisher"]) <= 8192, "Invalid revocation envelope")
    payload = base64.b64decode(row["payload"], validate=True)
    signature = base64.b64decode(row["signature"], validate=True)
    value = json.loads(payload)
    require(value["schema"] == 1 and value["statement"] == "revoke" and SHA.fullmatch(value["sha256"]) and
            0 < len(value["reason"]) <= 500, "Invalid revocation")
    if value["kind"] == "model":
        verify_ed25519(row["publisher"], payload, signature)
    else:
        require(value["kind"] == "apk", "Invalid revocation kind")
        certificate = base64.b64decode(row["publisher"], validate=True)
        with tempfile.TemporaryDirectory() as folder:
            public_key, sig_path = (Path(folder, name) for name in ("key", "sig"))
            public_key.write_bytes(openssl("x509", "-inform", "DER", "-pubkey", "-noout", input=certificate))
            sig_path.write_bytes(signature)
            openssl("dgst", "-sha256", "-verify", public_key, "-signature", sig_path, input=payload)


def github_release(row):
    endpoint = f'https://api.github.com/repos/{row["repository"]}/releases?per_page=100'
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "Tantal-Depot-Catalog"}
    token = os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    while endpoint:
        try:
            with urllib.request.urlopen(urllib.request.Request(endpoint, headers=headers), timeout=30) as response:
                releases = json.load(response)
                next_link = re.search(r'<(https://api\.github\.com/[^>]+)>; rel="next"',
                                      response.headers.get("Link", ""))
                endpoint = next_link.group(1) if next_link else None
        except urllib.error.HTTPError as error:
            if error.code == 404:
                print(f'{row["repository"]}: repository has no public releases')
                return None
            raise
        for release in releases:
            if (not release["draft"] and not release["prerelease"] and
                    re.fullmatch(row["tagPattern"], release["tag_name"])):
                return release
    return None


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme == "https" and parsed.hostname in {
            "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"
        } and parsed.port in (None, 443) and parsed.username is None, "Unexpected APK redirect")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def command(*args):
    process = subprocess.run(args, text=True, capture_output=True, check=False)
    if process.returncode:
        raise ValueError(f"{Path(args[0]).name} failed: {process.stderr.strip() or process.stdout.strip()}")
    return process.stdout


def signed_apk(row, release, tools, previous):
    tag = release["tag_name"]
    name = row["asset"].replace("{version}", tag.removeprefix("v"))
    assets = [asset for asset in release["assets"] if asset["name"] == name and asset["state"] == "uploaded"]
    require(len(assets) == 1, f"{tag} has no unique release asset named {name}")
    asset = assets[0]
    url = f'https://github.com/{row["repository"]}/releases/download/{tag}/{name}'
    require(asset["browser_download_url"] == url, "Unexpected APK asset URL")
    size = asset["size"]
    digest = asset["digest"]
    require(0 < size <= MAX_APK and isinstance(digest, str) and
            digest.startswith("sha256:") and SHA.fullmatch(digest[7:]), "Invalid GitHub asset digest or size")
    for build in previous:
        if build["url"] == url and build["sha256"] == digest[7:] and build["size"] == size:
            return {**build, "title": row["title"]}

    with tempfile.TemporaryDirectory() as folder:
        apk = Path(folder, name)
        hasher = hashlib.sha256()
        total = 0
        opener = urllib.request.build_opener(ReleaseRedirect())
        with opener.open(url, timeout=30) as response, apk.open("wb") as output:
            while chunk := response.read(128 * 1024):
                total += len(chunk)
                require(total <= size, "APK download exceeds the declared size")
                hasher.update(chunk)
                output.write(chunk)
        sha = hasher.hexdigest()
        require(total == size and digest == f"sha256:{sha}", "APK digest or size mismatch")

        certs = command("java", "-jar", str(tools / "lib" / "apksigner.jar"), "verify", "--min-sdk-version", "36", "--print-certs", str(apk))
        signer_pattern = r"^(?:Signer #[0-9]+|V[0-9.]+ Signer:) certificate SHA-256 digest: ([a-f0-9]{64})$"
        signers = set(re.findall(signer_pattern, certs, re.MULTILINE))
        require(signers == {row["signer"]} and not re.search(r"^Signer #[2-9][0-9]* ", certs, re.MULTILINE),
                f"Unexpected signer fingerprints: {sorted(signers)}")
        badging = command(str(tools / "aapt2"), "dump", "badging", str(apk))
        package_line = next(line for line in badging.splitlines() if line.startswith("package: "))
        package = re.search(r"\bname='([^']+)'", package_line).group(1)
        code = int(re.search(r"\bversionCode='([0-9]+)'", package_line).group(1))
        major = re.search(r"\bversionCodeMajor='([0-9]+)'", package_line)
        if major:
            code += int(major.group(1)) << 32
        version = re.search(r"\bversionName='([^']+)'", package_line).group(1)
        require(package == row["package"] and code > 0 and version == tag.removeprefix("v"),
                "APK package or version does not match the definition")
        min_sdk = re.search(r"^(?:minSdkVersion|sdkVersion):'([0-9]+)'$", badging, re.MULTILINE)
        max_sdk = re.search(r"^maxSdkVersion:'([0-9]+)'$", badging, re.MULTILINE)
        with zipfile.ZipFile(apk) as archive:
            abis = sorted({parts[1] for name in archive.namelist() if
                           len(parts := name.split("/")) == 3 and parts[0] == "lib" and name.endswith(".so")})
        return dict(package=package, signer=row["signer"], title=row["title"], version=version,
                    versionCode=code, minSdk=int(min_sdk.group(1)) if min_sdk else 1,
                    maxSdk=int(max_sdk.group(1)) if max_sdk else 2147483647, abis=abis,
                    sha256=sha, size=size, url=url)


def validate_model(row):
    base = f'https://huggingface.co/{row["repository"]}/resolve/{row["commit"]}/{row["directory"]}'

    def fetch(name, limit):
        with urllib.request.urlopen(f"{base}/{name}", timeout=30) as response:
            require(urllib.parse.urlsplit(response.url).scheme == "https", "Model manifest left HTTPS")
            data = response.read(limit + 1)
        require(len(data) <= limit, f"{name} exceeds size limit")
        return data

    payload = fetch("manifest.json", 32 * 1024)
    sig = fetch("manifest.sig", 64)
    require(hashlib.sha256(payload).hexdigest() == row["sha256"], "Model manifest digest mismatch")
    verify_ed25519(row["publisher"], payload, sig)
    manifest = json.loads(payload)
    require(manifest["schema"] == 1 and all(manifest[key] == row[key]
            for key in ("package", "variant", "versionCode", "minReader")), "Model manifest identity mismatch")
    assets = manifest["files"]
    require(1 <= len(assets) <= 32 and sum(asset["size"] for asset in assets) == row["size"],
            "Model has an invalid payload size or count")
    for field in ("name", "role"):
        require(len({asset[field] for asset in assets}) == len(assets) and
                all(NAME.fullmatch(asset[field]) for asset in assets), f"Invalid model file {field}")
    require(all(asset["size"] > 0 and SHA.fullmatch(asset["sha256"]) and
                asset["name"] not in ("manifest.json", "manifest.sig", "origin.json") for asset in assets),
            "Invalid model payload metadata")
    require(NAME.fullmatch(manifest["format"]) and
            (manifest["format"] != "tflite" or any(asset["name"].endswith(".tflite") for asset in assets)),
            "Invalid model format")
    for asset in assets:
        with urllib.request.urlopen(f'{base}/{asset["name"]}', timeout=30) as response:
            require(urllib.parse.urlsplit(response.url).scheme == "https", "Model download left HTTPS")
            digest = hashlib.sha256()
            remaining = asset["size"]
            while chunk := response.read(128 * 1024):
                remaining -= len(chunk)
                require(remaining >= 0, "Model payload exceeds declared size")
                digest.update(chunk)
        require(remaining == 0 and digest.hexdigest() == asset["sha256"], "Model payload does not match manifest")


def encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def make_index(config, previous, tools):
    definitions, models, withdrawals, revocations = config
    apks = []
    errors = []
    for row in definitions:
        history = [build for build in previous["apks"] if
                   (build["package"], build["signer"]) == (row["package"], row["signer"])]
        try:
            release = github_release(row)
            if release:
                build = signed_apk(row, release, tools, history)
                require(not history or build["versionCode"] >= max(old["versionCode"] for old in history),
                        "Latest upstream release rolls back the APK")
                history = [old for old in history if old["sha256"] != build["sha256"]]
                history.insert(0, build)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, StopIteration, zipfile.BadZipFile) as error:
            errors.append(f'{row["repository"]}: {error}')
        apks.extend(history)
    accepted_models = []
    for row in models:
        if row not in previous["models"]:
            try:
                validate_model(row)
            except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
                errors.append(f'{row["repository"]}/{row["directory"]}: {error}')
                continue
        accepted_models.append(row)
    historical_models = [row for row in previous["models"] if row not in accepted_models and
                         (row["package"], row["variant"], row["publisher"]) in
                         {(item["package"], item["variant"], item["publisher"]) for item in models}]
    accepted_withdrawals = {(row["kind"], row["sha256"]): row
                            for row in previous["withdrawals"] + withdrawals}
    index = dict(schema=1, revision=previous["revision"], apks=apks,
                 models=accepted_models + historical_models, withdrawals=list(accepted_withdrawals.values()),
                 revocations=[dict(items) for items in dict.fromkeys(
                     tuple(sorted(row.items())) for row in previous["revocations"] + revocations)])
    return index, errors


def publish(config, args):
    key = Path(os.environ["CATALOG_KEY_FILE"])
    published_key = os.environ["CATALOG_PUBLIC_KEY"]
    require(openssl("pkey", "-in", key, "-pubout", "-outform", "DER") == check_ed25519(published_key),
            "The private key does not match the pinned public key")
    previous = dict(revision=0, apks=[], models=[], withdrawals=[], revocations=[])
    if args.previous:
        envelope = load(args.previous)
        payload = base64.b64decode(envelope["payload"], validate=True)
        verify_ed25519(published_key, payload, base64.b64decode(envelope["signature"], validate=True))
        previous = json.loads(payload)
        require(previous["schema"] == 1 and previous["revision"] > 0, "Invalid previous index")
    index, errors = make_index(config, previous, args.tools)
    if index != previous:
        index["revision"] += 1
        payload = encode(index)
        with tempfile.TemporaryDirectory() as folder:
            manifest = Path(folder, "payload")
            manifest.write_bytes(payload)
            sig = openssl("pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", manifest)
        envelope = encode(dict(payload=base64.b64encode(payload).decode(), signature=base64.b64encode(sig).decode()))
        require(len(envelope) <= INDEX_LIMIT, "Signed index exceeds Depot's limit")
        args.output.write_bytes(envelope + b"\n")
    args.report.write_text("\n".join(errors) + ("\n" if errors else ""))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--tools", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        config = validate()
        if not args.check:
            require(args.output and args.tools and args.report, "Publishing requires tools, output and report")
            publish(config, args)
    except (OSError, ValueError, KeyError, TypeError, re.error, subprocess.CalledProcessError) as error:
        print(f"Catalog publication failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
