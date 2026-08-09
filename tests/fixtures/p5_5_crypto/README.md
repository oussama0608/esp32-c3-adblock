# P5.5 public cryptographic fixtures

These files contain verification material only. No private signing scalar, PEM
private key, or ECDSA nonce is present.

## NIST verification vector

`nist_p256_sha256_sigver.json` is the first passing case in the
`[P-256,SHA-256]` section of `SigVer.rsp` from the NIST CAVP ECDSA test-vector
archive (updated 2015-05-05). The archive's Readme identifies the contained
tests as FIPS 186-3 material:

- Source: `https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip`
- Archive size: 1,144,603 bytes
- Archive SHA-256: `FE47CC92B4CEE418236125C9FFBCD9BB01C8C34E74A4BA195D954BCB72824752`
- Result in `SigVer.rsp`: `P (0)`

Only the public key, message, signature and expected verification result were
copied from the archive.

## NetShield protocol test vector

`netshield_protocol_test_vector.json` is marked exactly
`TEST ONLY — NOT TRUSTED BY FIRMWARE`. It was generated on 2026-08-09 with
OpenSSL 3.5.5 and the repository's `tools/build_blocklist.py` and
`tools/sign_blocklist.py`:

1. Build a 35-byte, seven-record payload from the local deterministic
   `tests/fixtures/domains.txt` and `tests/fixtures/hosts.txt` inputs.
2. Generate a disposable `prime256v1` key outside the repository.
3. Sign with List ID 1 and sequence 42.
4. Retain only the public SEC1 point, its SHA-256 fingerprint, payload,
   manifest and raw `r || s` proof as hexadecimal text.
5. Destroy the disposable private key and all temporary binary files.

The disposable test public-key SHA-256 is
`B0FB450CC5F61BD3E184DB9187AC1F4530C3FCC0C835253F8220A7FEABB4321C`.
Repository gates ensure this test key is never present in the production
firmware trust table.
