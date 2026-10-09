Source: https://github.com/SSLMate/go-pkcs12, tag v0.7.3.
License: BSD-3-Clause (see LICENSE).

This local copy retains upstream cryptography and adds BER normalization
at the `unmarshal` boundary in pkcs12.go. ber.go accepts indefinite
constructed lengths and constructed universal OCTET STRINGs. Primitive
payloads remain untouched. The original authenticated safe bytes are
verified by upstream MAC code before decoding their embedded ASN.1.
No password or integrity verification is bypassed.

Tests are in ber_test.go and the application's main_test.go. This is a
targeted BER reader, not a general ASN.1 canonicalizer (it does not reorder
SET values or normalize every possible BER primitive).

Additional local API: DecodeWithTrust separates a private identity and its
chain from Java trusted certificate entries, and accepts pure truststores.
EncodeWithTrust adds Java trusted entries to an identity container using the
same makeTrustBags helper as upstream EncodeTrustStoreEntries. Existing APIs
remain available; DecodeChain excludes standalone trust entries from the
identity's certificate chain. Cryptographic encoding and verification remain
upstream implementations. End-to-end coverage is in trust_test.go.

Inspect/IsPFX enumerate multiple identities, certificate bags and nested
SafeContents without DecodeChain's single-identity restriction. Integrity
verification and key decryption reuse upstream code. Protection metadata
reports legacy PBE, PBES2 and PBMAC1 parameters. EncryptedKeyProtection and
ParseEncryptedPrivateKey expose the existing decryptor for standalone PKCS#8
inspection. Tests cover multiple identities, nested bags, BER, wrong passwords
and encrypted PKCS#8. JSON on InspectionEntry excludes raw certificate/key
objects; the CLI builds separate metadata-only reports.
