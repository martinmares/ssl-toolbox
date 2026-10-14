# ssl-toolbox

[Česká dokumentace](README.cs.md)

Go CLI for PKCS#12 conversion, Java truststores and binary assets in Kubernetes
ConfigMap YAML manifests. Keystore operations run directly in Go: neither
OpenSSL nor Java is required. Cobra provides separate commands and help.

## Build and discover

Requires Go 1.26 or newer.

```sh
go build -o ssl-toolbox .
./ssl-toolbox
./ssl-toolbox examples
./ssl-toolbox convert --help
./ssl-toolbox truststore --help
./ssl-toolbox configmap set-binary --help
./ssl-toolbox configmap extract-binary --help
./ssl-toolbox inspect --help
./ssl-toolbox extract --help
```

| Command | Purpose |
|---|---|
| `convert` | Convert an existing PKCS#12 identity or truststore to modern PFX or JKS; optionally add trusted CA certificates |
| `truststore` | Create a certificate-only PFX/JKS truststore from CA PEM files |
| `configmap set-binary` | Replace a ConfigMap `binaryData` value with a file's base64-encoded raw bytes |
| `inspect` | Detect the format by content and inspect every certificate and key; optional JSON |
| `extract` | Export a PFX identity as a PEM key, certificate and available CA chain |
| `configmap extract-binary` | Recover the exact binary bytes of a `binaryData` key into a new file |
| `examples` | Print explained command variants and sample YAML, with terminal colors |
| `version` | Version and build metadata; short output is also available through `--version` |

Commands are now required: replace the old `ssl-toolbox --in ... --out ...`
with `ssl-toolbox convert --in ... --out ...`. Use `truststore` to create a
store from CA PEM files without an input PKCS#12 file. The original one-dash
keystore flags (`-in`, `-out`, `-add-ca`, etc.) remain accepted inside those
commands; the documented form uses two dashes.

## Justfile and versions

[just](https://just.systems/) supplies development and build jobs:

```sh
just                 # list jobs
just check           # formatting check + tests + go vet
just build           # native ./ssl-toolbox
just build-all       # Linux amd64, macOS arm64 and Windows amd64 in dist/
just version         # contents of VERSION
./ssl-toolbox --version
./ssl-toolbox version # version, commit, build time, Go and platform
```

| Job | Purpose |
|---|---|
| `build` | Native executable in the repository root |
| `build-linux` | `dist/ssl-toolbox-linux-amd64` |
| `build-macos` | `dist/ssl-toolbox-darwin-arm64` |
| `build-windows` | `dist/ssl-toolbox-windows-amd64.exe` |
| `build-all` | All three release targets |
| `test`, `vet` | Tests and static checks, including the local PKCS#12 library |
| `fmt`, `fmt-check` | Apply formatting, or verify without writing |
| `check` | `fmt-check`, `test` and `vet` |
| `version` | Current version from `VERSION` |
| `notices` | Refresh license notices for dependencies across all release targets |
| `upgrade-modules` | Upgrade external Go modules, refresh checksums/notices, check and build locally |

`VERSION` is the single default source of the version; the current version is
`1.0.2`. Before a release, edit this file, then run `just check` and
`just build-all`. A plain `go build` also contains the version through
`go:embed`. Just builds additionally inject the short Git commit and UTC build
time through linker flags. Without Git or linker metadata, commit/build time
are `unknown`. These jobs do not create commits/tags or publish anything.

Release builds use `CGO_ENABLED=0`. `dist/` also contains `LICENSE`,
`THIRD_PARTY_NOTICES.md`, both READMEs and `VERSION`; include the license files
when distributing binaries. `dist/` is ignored by Git. `upgrade-modules` retains
the locally modified PKCS#12 library through `replace`; it does not automatically
synchronize its source with upstream. Notices are refreshed after dependency upgrades.

## GitLab Releases

The project `.gitlab-ci.yml` follows the same release workflow as `oci-toolbox`:

1. `release_notes` generates notes and metadata from `VERSION` and Git history.
2. `check` and `test` verify compilation, formatting, `go vet` and tests for the application and local PKCS#12 library.
3. `release_binaries` builds six `.tar.gz` archives: Linux, macOS and Windows, each for amd64 and arm64. Every archive includes the executable, both READMEs, `VERSION`, `LICENSE` and `THIRD_PARTY_NOTICES.md`. It also produces `SHA256SUMS`.
4. Archives are uploaded to the GitLab Generic Package Registry and `publish_release` links them from GitLab Release `v<VERSION>`.

Releases run when a push changes `VERSION` on the default branch, or manually
through **Build → Pipelines → New pipeline** on that branch. Other default
branch changes and merge requests run checks. `VERSION` contains a semantic
version without a `v` prefix; publication can create the tag. Existing tags
must reference the same commit, otherwise increment the version.

Build jobs use `golang:1.27-bookworm` and compile directly with Go. This pipeline
has no Dockerfile, buildpack or deployment job. Local `just build-all` still
builds three primary targets; the release script also adds Linux/Windows arm64
and macOS amd64.

Publication uses the standard `CI_JOB_TOKEN`; the project must allow Package
Registry and Release publication. Only small metadata files travel between
jobs as artifacts with a 30-day lifetime. Archives remain in the Package
Registry and are downloadable from Releases. Retrying the same version at the
same commit updates the existing Release and links. Checksum failures or tag
commit mismatches stop publication.

Optional `RELEASE_PUSH_TOKEN` with repository write permission enables committing
the generated `CHANGELOG.md` back to the branch with `[skip ci]`. Without it,
notes stay attached to the Release and the repository is not modified.

Local preparation without uploading:

```sh
bash scripts/ci_release_notes.sh
bash scripts/ci_package_release.sh
(cd dist/release && shasum -a 256 -c SHA256SUMS)
```

The Go module path is `github.com/martinmares/ssl-toolbox`. GitLab builds the
local checkout, so this path does not require access to the GitHub repository.
Publication uses the current GitLab project's API.

## GitHub Releases

`.github/workflows/release.yml` uses the same release notes and packaging scripts
as GitLab. It runs when a push changes `VERSION` on `main`, or manually through
**Actions → Release → Run workflow** with `main` selected. The workflow must
first be present on the default branch to enable manual runs.

The workflow checks formatting, compilation, tests and `go vet` for both modules,
then builds all six platform archives and `SHA256SUMS`. Go is selected from
`go.mod`. Publication uses the built-in `GITHUB_TOKEN` with `contents: write`;
no personal access token or additional secret is required. GitHub Actions must
be enabled and repository or organization policies must permit this permission.

A new release starts as a draft. The archives and checksums are uploaded directly
as release assets, then the release is published. Retrying the same version at
the same commit replaces assets and updates notes. Existing tags pointing to
another commit stop publication; increment `VERSION` instead. Versions containing
a prerelease suffix, such as `1.0.2-rc.1`, are marked as prereleases.

To publish the same version on GitHub and both GitLab servers, push the same
commit containing the `VERSION` change to each repository. Each server publishes
its own release from that commit. Local build jobs do not publish anything.

## Convert a PFX identity

```sh
ssl-toolbox convert --in legacy-client.pfx --out modern-client.pfx

ssl-toolbox convert --in legacy-client.pfx --out client.jks \
  --format jks --alias client
```

The input can use legacy RC2/3DES encryption or supported Windows BER wrappers.
The private key, client certificate and attached CA chain are preserved.
The tool asks for the old password, then asks twice for the new password without
echo. The **same new password protects the output store and private key**.
The old password may be empty; the new password must not be empty.
Decrypted keys are processed in memory without temporary PEM files.

| Flag | Meaning |
|---|---|
| `--in` | Required PKCS#12 input file; its extension is irrelevant |
| `--out` | Required new output file; must not exist |
| `--format` | `pfx` (default) or `jks`; extensions do not select the format |
| `--alias` | JKS private-key alias, default `client`; stored in lowercase |
| `--add-ca` | Repeatable CA PEM file; bundles are supported |
| `--in-pass-env` | Environment variable containing the old password |
| `--in-pass-file` | File containing the input password |
| `--out-pass-file` | File containing the new password |
| `--out-pass-env` | Environment variable containing the new password |

PFX output uses AES-256-CBC, PBKDF2 and a SHA-256 MAC (`Modern2023`).
JKS output is a real Java KeyStore with its own older key protection and SHA-1
integrity check. A file named `.jks` can still contain PKCS#12: the name does
not determine the format. Java has defaulted to PKCS#12 since JDK 9
([keytool documentation](https://docs.oracle.com/en/java/javase/21/docs/specs/man/keytool.html)).

## Trusted CA entries and truststores

A client's CA chain belongs to its identity. A trusted CA entry separately tells
the application which issuers it can trust when verifying its peer.
`--add-ca` creates independent trusted entries; it does not append unrelated
CA certificates to the client's chain.

```sh
ssl-toolbox convert --in client.pfx --out client-with-ca.pfx \
  --add-ca root-ca.pem --add-ca another-ca.pem

ssl-toolbox convert --in client.pfx --out client-with-ca.jks \
  --format jks --alias client --add-ca root-ca.pem
```

To create a pure truststore with no private key:

```sh
ssl-toolbox truststore --out truststore.pfx \
  --add-ca root-ca.pem --add-ca ca-bundle.pem

ssl-toolbox truststore --out truststore.jks --format jks \
  --add-ca ca-bundle.pem
```

`truststore` requires `--out` and at least one `--add-ca`. It also accepts
`--format` and `--out-pass-env`; it asks only for the new password. It does not
accept `--in`, an input password or a private-key alias.

PEM files can contain several certificates. Each imported certificate must have
`CA:TRUE`. Empty files, malformed PEM/DER and non-certificate blocks are rejected
before password prompts. Identical certificates are deduplicated; trusted
entries use `ca-<SHA-256 fingerprint>` aliases. PFX uses Java trust attributes
so Java sees `trustedCertEntry`; JKS contains corresponding trusted entries.
Configure your application to actually use the resulting file as its truststore.

`convert` also reads a pure or mixed PKCS#12 truststore and preserves the trust
roles on another conversion. Trusted aliases are normalized to fingerprints.
JKS is an output format only. PKCS#12 input supports one private identity;
multi-identity stores and distinct input passwords for MAC and key are not
supported. Arbitrary original metadata, such as private-key friendly names,
is not retained. The local SSLMate copy adds targeted BER reading and mixed
identity/trust entry support; see [local changes](third_party/go-pkcs12/LOCAL_CHANGES.md).

## Passwords in automation

Instead of interactive prompts, supply the names of environment variables:

```sh
# Supply these variables through your shell or secret provider first.
ssl-toolbox convert --in client.pfx --out modern.pfx \
  --in-pass-env OLD_PFX_PASSWORD --out-pass-env NEW_PFX_PASSWORD

ssl-toolbox truststore --out truststore.jks --format jks \
  --add-ca root-ca.pem --out-pass-env NEW_PFX_PASSWORD
```

Variable names are arbitrary. A missing variable is an error; an explicitly
empty input variable means an empty old password. Password values are not CLI
arguments. Interactive prompting requires a terminal. Existing output files
are never overwritten; on Unix new keystore files have mode `0600`.

### Password files and GitLab pipelines

Every password source supports ENV and FILE:

| Command | ENV (variable name) | FILE (file path) |
|---|---|---|
| `convert`, input | `--in-pass-env` | `--in-pass-file` |
| `convert` / `truststore`, new password | `--out-pass-env` | `--out-pass-file` |
| `inspect`, store / encrypted PEM or DER | `--pass-env` | `--pass-file` |
| `inspect`, separate JKS key password | `--key-pass-env` | `--key-pass-file` |
| `extract`, input PFX | `--pass-env` | `--pass-file` |

ENV and FILE are mutually exclusive for the same password; sources for different
passwords may be mixed. ENV values are read exactly. FILE removes one trailing
LF or CRLF and preserves other characters, including spaces. Empty files or
variables supply an empty input password; new passwords must not be empty.
ENV/FILE new passwords do not require confirmation. Missing variables,
unreadable files, incorrect passwords or prompting without a terminal fail
with a nonzero exit code. Password contents are never logged.

GitLab CI/CD **File** variables contain paths: pass their expanded values to
FILE flags. For regular variables, pass variable names to ENV flags. This job
assumes the binary and input are available; configure passwords in CI/CD
Variables rather than embedding them in YAML:

```yaml
fix-keystore:
  script:
    - ssl-toolbox convert --in client.pfx --out modern.pfx --in-pass-file "$OLD_PFX_PASSWORD_FILE" --out-pass-file "$NEW_PFX_PASSWORD_FILE"
    - ssl-toolbox inspect modern.pfx --pass-file "$NEW_PFX_PASSWORD_FILE" --json > inspection.json
```

Regular ENV alternatives:

```sh
ssl-toolbox convert --in client.pfx --out modern.pfx --in-pass-env OLD_PFX_PASSWORD --out-pass-env NEW_PFX_PASSWORD
ssl-toolbox inspect modern.pfx --pass-env NEW_PFX_PASSWORD --color never
ssl-toolbox truststore --out truststore.pfx --add-ca root-ca.pem --out-pass-file "$NEW_PFX_PASSWORD_FILE"
```

ConfigMap commands, `version` and `examples` need no passwords. Use new output
paths in pipelines (`set-binary --out`, `extract-binary --out`) or `--dry-run`.
`examples --color never` prints plain text.

## Replace ConfigMap binary data

A ConfigMap's `binaryData` holds base64 strings
([Kubernetes documentation](https://kubernetes.io/docs/concepts/configuration/configmap/)).
The command reads the raw bytes of `--file`, encodes them itself and replaces
exactly the selected key. It does not modify the keystore or contact Kubernetes.

```sh
ssl-toolbox configmap set-binary \
  --manifest assets.yml \
  --key client.jks \
  --file new-client.jks \
  --dry-run
```

Remove `--dry-run` to update `assets.yml` in place. The original bytes are first
saved as `assets.yml.bak`; an existing backup is never overwritten. The
replacement is prepared and synced in the same directory, then renamed
atomically. Original manifest permission bits are retained. The backup has
mode `0600`. In-place updates require a regular file rather than a symlink.
If the value already matches the new file, there is no write and no backup.

| Flag | Meaning |
|---|---|
| `--manifest` | Required input YAML file |
| `--key` | Required `binaryData` key; letters, digits, `.`, `_` and `-` |
| `--file` | Required source binary file |
| `--dry-run` | Show the selected ConfigMap/key and old/new decoded byte counts; write nothing |
| `--out` | Write a new YAML file instead of updating the original; must not exist; no backup |
| `--create` | Allow creating a missing key or `binaryData` mapping |
| `--name` | Select `metadata.name` when several ConfigMaps exist |
| `--namespace` | Further select `metadata.namespace` |

Multiple YAML documents are supported. Selection must identify exactly one
`apiVersion: v1`, `kind: ConfigMap`. The key must already exist unless `--create`
is specified. A conflicting key in `data`, invalid existing base64 and duplicate
YAML mapping keys are rejected. Target mappings and the replaced value must
not use YAML anchors, aliases or merges. ConfigMaps nested inside `List.items`
are not selected. Other documents, values and comments are retained; whitespace,
quoting and formatting may be normalized by the YAML encoder. The binary/base64
payload is not printed, including during dry-run.

Write a separate result or select a resource and add a key:

```sh
ssl-toolbox configmap set-binary --manifest assets.yml \
  --key client.jks --file new-client.jks --out updated-assets.yml

ssl-toolbox configmap set-binary --manifest resources.yml \
  --name client-assets --namespace prod \
  --key root-ca.der --file root-ca.der --create
```

### Project directory example

```sh
ssl-toolbox configmap set-binary \
  --manifest manifests/configmap.yaml \
  --key client.jks \
  --file certificates/client.jks \
  --dry-run
```

Remove the final `--dry-run` after reviewing the target. To update the file
again later, first move or remove the previous `.bak` yourself, or use `--out`.

## Extract a PFX certificate and private key

```sh
ssl-toolbox extract client.pfx --out-dir ./export
ssl-toolbox extract client.pfx --out-dir ./export --pass-env STORE_PASSWORD
ssl-toolbox extract client.pfx --out-dir ./export --pass-file "$STORE_PASSWORD_FILE"
```

These are alternative invocations; choose one password source and an output
directory where the destination files do not yet exist.

Creates `client.key` (unencrypted PKCS#8 PEM), `client.pem` (the matching
certificate), and `client.chain.pem` if CA issuers are present. Names come from
the input filename without its final extension. Output is clean PEM without
OpenSSL bag metadata. All files have permissions `0600`; missing output
directories are created with `0700`. Existing files, including symlinks, are
never overwritten, and all destinations are checked before any file is written.
The private key is exported without password protection; the PFX is unchanged.

An empty PFX password is tried first, then a password is requested if necessary.
`--pass-env` and `--pass-file` work like their `inspect` equivalents and are
mutually exclusive. Supports the same PFX encryption and BER encodings as
`inspect`; private key bytes and passwords are never printed.

For multiple private keys, first run `inspect` and select a key using
`--entry entry-N`. If several different certificates match its public key,
also specify `--cert-entry entry-N`. IDs refer to entries in the unchanged
input PFX. No identity is selected implicitly when multiple keys are present.

```sh
ssl-toolbox inspect identities.pfx
ssl-toolbox extract identities.pfx --out-dir ./export --entry entry-3
```

If certificate selection is also needed, use this instead of the extraction
above. Replace both IDs with the private key and matching certificate IDs
shown by `inspect`:

```sh
ssl-toolbox extract identities.pfx --out-dir ./export --entry entry-3 --cert-entry entry-2
```

The chain contains only available issuers for the selected certificate, ordered
from its immediate issuer toward the root (including the root when present).
Unrelated certificates are excluded. Issuer names and signatures are checked;
ambiguous chains and cycles are rejected. No missing CA certificates are
downloaded, and extraction does not validate dates, trust or revocation.

## Inspect stores, certificates and keys

```sh
ssl-toolbox inspect client.jks
ssl-toolbox inspect ca-bundle.pem
ssl-toolbox inspect client.der
ssl-toolbox inspect client.pfx --pass-env STORE_PASSWORD --json > inspection.json
ssl-toolbox inspect client.jks --pass-env STORE_PASSWORD --key-pass-env KEY_PASSWORD
```

Detection uses file contents, regardless of extension: PKCS#12/PFX (including
supported BER and legacy encryption), real JKS, PEM bundles and DER.
DER may contain a certificate, concatenated certificates, a public key or a
private key. Supported key structures include PKCS#8, RSA PKCS#1 and EC SEC1.
Encrypted PKCS#8 and legacy encrypted PEM are decrypted directly in Go.

Every supported object is listed, including multiple private keys, certificates
from chains and standalone trusted CAs. Certificate details include subject,
issuer, serial, validity dates/status, CA/basic constraints, SAN, KU/EKU,
signature algorithm and SHA-256 fingerprint. Key details include algorithm,
size, EC curve and public-key SPKI SHA-256. Matching keys/certificates are linked
by their public-key fingerprints. Available aliases, localKeyID, creation dates
and encryption/MAC parameters are also shown. Passwords and private key bytes
are never printed. Date validity does not verify trust chains or revocation.

An empty password is tried first; if necessary, the tool prompts without echo.
JKS keys first use the store password, then prompt separately for each alias
that requires another password. `--pass-env` names an environment variable
containing the store or encrypted PEM/DER password; `--key-pass-env` supplies
a separate JKS key password. Missing variables and incorrect supplied passwords
are errors. `--json` prints structured metadata; prompts remain on stderr.
PFX/JKS integrity is checked when present. Unsupported PFX bags are identified
by OID. Unsupported PEM blocks, malformed objects or decryption errors fail
without a partial report. PEM accepts whitespace and OpenSSL export metadata
(`Bag Attributes`, `Key Attributes`, `subject=`, `issuer=`) before and between
blocks. Other text outside PEM blocks is rejected.

### Colors and expiration

`inspect` supports `--color auto|always|never`. `auto` colors terminals only
and respects `NO_COLOR` and `TERM=dumb`; `always` forces ANSI colors. JSON
always stays plain. Headings/labels are cyan, private keys yellow and trusted
certificates blue; aliases and subjects are emphasized, fingerprints subdued.
`EXPIRED` is red, `EXPIRING SOON` and `NOT YET VALID` yellow, valid dates green.
Explicit status labels remain visible without colors.

A summary of problematic certificate dates appears first. Each certificate
includes its expiry date and remaining time. The default warning window is
**30 days**; set `--expiry-warning-days 60` to change it or `0` to disable
advance warnings. Expired certificates are always marked. JSON includes
`expiry_warning_days`, `validity` and signed `expires_in_seconds`. Date states
are informational and do not change the exit code; reading/decryption must
still succeed.

```sh
ssl-toolbox inspect client.pfx --expiry-warning-days 60
ssl-toolbox inspect client.pfx --color always
ssl-toolbox inspect client.pfx --pass-env STORE_PASSWORD --color never
```

## Extract a binary file from a ConfigMap

```sh
ssl-toolbox configmap extract-binary assets.yml client.jks --out extracted.jks
ssl-toolbox configmap extract-binary resources.yml client.jks \
  --name client-assets --namespace prod --out client.jks
ssl-toolbox inspect extracted.jks
```

The manifest and key are positional arguments. Required `--out` creates a new
file with permissions `0600`; existing files or symlinks are never overwritten.
The source YAML stays unchanged and no `.bak` is created. `binaryData` is
base64-decoded into the exact original bytes, including an empty file.
Output contains the target, byte count and SHA-256 fingerprint only.

Selection via `--name`/`--namespace` and YAML validation share the rules of
`set-binary`. Exactly one ConfigMap must match and the key must exist in
`binaryData`. This command does not extract `data`. Invalid base64, duplicate
keys, conflicting `data` entries and anchors/aliases in target mappings or
values are rejected.

## Explained examples and colors

```sh
ssl-toolbox examples
ssl-toolbox examples --color always
ssl-toolbox examples --color never > examples.txt
```

The catalogue follows the layout of `oci-toolbox examples`: cyan section
headers, yellow example titles, green shell commands and blue sample files.
Each variant explains its flags and effects. `example` is an alias.
`--color auto` is the default: colors appear only on terminal output; redirects,
`NO_COLOR` and `TERM=dumb` disable them. `always` explicitly forces ANSI colors.
Examples are displayed, never executed.

## Validation and tests

```sh
go test ./... software.sslmate.com/src/go-pkcs12
go vet ./... software.sslmate.com/src/go-pkcs12

# Optional external verification; prompts for the new password.
openssl pkcs12 -in modern.pfx -info -noout
keytool -list -v -storetype JKS -keystore client.jks
keytool -list -v -storetype PKCS12 -keystore truststore.pfx
```

Tests cover legacy/BER decoding, passwords, key and chain preservation, CA
bundles/deduplication, trusted entries and repeated conversions. If available,
OpenSSL/LibreSSL decrypts the generated key and Java `keytool` imports and
verifies both output formats. YAML tests cover document selection, preservation,
base64, create/dry-run/output modes, backup refusal and permissions. Example
output tests cover ANSI modes and output errors. The keystore's validity and
Kafka permissions do not change; test the result in your actual client runtime.

Tests for the new commands cover multiple PFX/JKS identities, separate JKS key
passwords, PEM/DER, OpenSSL PEM metadata, encrypted PKCS#8, metadata-only JSON
and exact binary extraction without changing the manifest. PFX extraction tests
check key/certificate contents, CA chain ordering and ambiguity, identity
selection, password sources, permissions and refusal to overwrite outputs.

## License and project governance

Project code is licensed under the standard [MIT License](LICENSE),
Copyright (c) 2026 Martin Mareš. Software is provided AS IS, without warranty
or entitlement to free community support. External pull requests need not be
accepted or reviewed. These service expectations do not restrict MIT rights.

Dependencies retain their licenses and copyright notices; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The modified PKCS#12 library
retains its original [BSD license](third_party/go-pkcs12/LICENSE).

After publishing on GitHub, disable Issues and Discussions and protect `main`;
grant write access only to the owner and explicitly appointed maintainers.
Configure equivalent governance settings when publishing on GitLab.
The policy application report is in [LICENSING_STATUS.md](LICENSING_STATUS.md).
