# OpenTPRM Security Whitepaper (outline)

OpenTPRM is a single-tenant, self-hosted TPRM platform. Security controls are layered: container hardening, sealed keyring, encrypted SQLite (AES-XTS), Cedar default-deny authorization, hash-chained audit, untrusted-content sandbox, and an Agent Gateway that never grants agents approval capability.

This document does not claim certifications (FIPS/SOC 2). Optional FIPS build profile uses the Go Cryptographic Module configuration only.
