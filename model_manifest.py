import argparse
import hashlib
import json
from pathlib import Path
import sys

from publish import MAX_MODEL, NAME, encode, openssl, require

D3_FILES = {
    "step": "step.tflite",
    "root": "root.tflite",
    "embeddings": "emb.bin",
    "vocabulary": "vocab.json",
    "config": "config.json",
    "lexicon": "lexicon.tsv",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--package", default="d3")
    parser.add_argument("--variant", required=True)
    parser.add_argument("--version-code", type=int, required=True)
    parser.add_argument("--file", action="append", metavar="ROLE=NAME")
    args = parser.parse_args()
    try:
        require(NAME.fullmatch(args.package) and NAME.fullmatch(args.variant) and args.version_code > 0,
                "Invalid package, variant or version")
        if args.file:
            entries = [item.split("=", 1) for item in args.file]
        elif args.package == "d3":
            entries = list(D3_FILES.items())
        else:
            raise ValueError("Specify the payload files and roles")
        files = []
        for role, name in entries:
            require(NAME.fullmatch(role) and NAME.fullmatch(name) and
                    name not in ("manifest.json", "manifest.sig", "origin.json"), "Invalid payload role or filename")
            file = args.directory / name
            with file.open("rb") as contents:
                digest = hashlib.file_digest(contents, "sha256").hexdigest()
            require(0 < file.stat().st_size <= MAX_MODEL, "Invalid payload size")
            files.append(dict(role=role, name=name, size=file.stat().st_size, sha256=digest))
        size = sum(row["size"] for row in files)
        require(1 <= len(files) <= 32 and size <= MAX_MODEL and
                len({row["name"] for row in files}) == len({row["role"] for row in files}) == len(files) and
                any(row["name"].endswith(".tflite") for row in files), "Invalid TFLite payload")
        manifest = args.directory / "manifest.json"
        signature = args.directory / "manifest.sig"
        require(not manifest.exists() and not signature.exists(), "Use a new output directory for each signed build")
        data = encode(dict(schema=1, package=args.package, variant=args.variant, versionCode=args.version_code,
                           minReader=1, format="tflite", files=files))
        manifest.write_bytes(data)
        signed = openssl("pkeyutl", "-sign", "-rawin", "-inkey", args.key, "-in", manifest)
        require(len(signed) == 64, "Expected an Ed25519 signature")
        signature.write_bytes(signed)
        print(json.dumps(dict(package=args.package, variant=args.variant, versionCode=args.version_code,
                              minReader=1, size=size, sha256=hashlib.sha256(data).hexdigest())))
    except Exception as error:
        print(f"Could not create model manifest: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
