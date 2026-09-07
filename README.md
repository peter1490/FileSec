# FileSec

A native desktop application for encrypted file storage and secure file exchange,
with classical and post-quantum cryptography. The `filesec-pqc` variant also
supports direct peer-to-peer transfers.

## Documentation

All project guides and audit documents are in [`docs/`](docs/).

| Document | Contents |
|---|---|
| [Application guide](docs/README.md) | Features, setup, building, testing, and usage |
| [Security review](docs/SECURITY_AUDIT.md) | Implemented fixes, performance measurements, validation, and remaining risks |
| [Threat model](docs/THREAT_MODEL.md) | Security boundaries, assumptions, and limitations |
| [Release guide](docs/RELEASE.md) | Packaging, signing, and release process |
| [Security roadmap](docs/SECURITY_ROADMAP_V2.md) | Remediation plan and progress |
| [Historical security roadmap](docs/SECURITY_ROADMAP.md) | Earlier findings and context |
| [Fuzzing guide](docs/FUZZING.md) | Parser targets and instructions for running them |

Known dependency exceptions and validation limits are documented in the
[security review](docs/SECURITY_AUDIT.md#dependency-exceptions-explicitly-still-present).
