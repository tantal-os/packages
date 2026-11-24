# Tantal packages

Tantal Depot reads a signed index from this repository. The `main` branch
contains reviewed package definitions. GitHub Actions publishes generated
`index.json` to the `index` branch. Each publication is a normal fast-forward
commit. Reviews of third-party definitions must include the license,
the network behavior, and the source of the expected signing certificate.

## APK releases

Add one JSON file to `definitions/` for each Android package and signer.
Set the upstream publisher, GitHub repository, package, display title,
SHA-256 signing certificate digest, stable release tag pattern, and expected
APK asset filename. The release tag is filtered with a full regular expression
match. The selected release is the most recent matching stable release in
GitHub's order. The APK filename contains one `{version}` placeholder for
the tag with the initial `v` removed.

The publisher fetches the original GitHub Release APK, verifies its digest
and signing certificate using `apksigner`, and extracts package, SDK range,
ABIs and version information. A failed check keeps the previously accepted
builds and makes the workflow report a failure. Normal release discovery
runs every six hours and can also be triggered manually.

## Model builds

Each entry in `models.json` names a package family, variant, title, variant
label, numeric version, minimum reader, publisher key (Base64 Ed25519 SPKI
DER), Hugging Face repository, full commit, directory, manifest SHA-256,
and summed payload size. See `publish.py` for the field names. Upload each
build's files together at one immutable commit.

The publisher checks the signed manifest and the payload bytes. For D3,
copy the existing six-file export into a new local directory, test it with
the shipped LiteRT runtime, and use this command with the model publisher's
key stored outside the repository.

```sh
python3 model_manifest.py /path/to/export --key /path/to/private-key.pem \
  --variant en --version-code 1
```

For another TFLite family, supply `--package` and a `--file ROLE=NAME` for
each graph and companion file. The script outputs the metadata derived from
the completed pack. Add the remaining catalog metadata after publishing the
files to Hugging Face. Keep training artifacts out of the publication.

## Withdrawal and revocation

Add a `withdrawals.json` entry with `kind` (`apk` or `model`), `sha256` and
`reason` to withdraw a build from this catalog. APK digests cover the APK
bytes. Model digests cover the complete manifest. A publisher can revoke a
build across catalogs using an independently signed statement. Put its
envelope in `revocations.json`. The envelope contains Base64 `payload` and
`signature` fields and a Base64 DER `publisher` field. The payload is UTF-8
JSON with `schema: 1`, `statement: "revoke"`, `kind`, `sha256` and `reason`.
APK revocations use the APK signing certificate and SHA-256 with RSA or
ECDSA. Model revocations use the model publisher's Ed25519 key.

## Index signing

Set the repository secret `CATALOG_PRIVATE_KEY` to the PEM Ed25519 private
key and the variable `CATALOG_PUBLIC_KEY` to its Base64 SPKI DER public key.
The workflow validates definitions before key setup and enables index
publication once `CATALOG_PUBLIC_KEY` is set.
Supply the same public value to Depot releases. Keep the private key in the
maintainer's signing storage and GitHub Actions secret store.

For a local check, run `python3 publish.py --check`. The signed envelope is
JSON with Base64 `payload` and `signature` fields. Its signature is Ed25519
over the decoded payload bytes. The payload contains `schema: 1`, a strictly
increasing `revision`, and the `apks`, `models`, `withdrawals` and
`revocations` arrays.
