# ADR-0004: Defer go-pdfium (wazero) evidence extract

## Status

Accepted (deferral)

## Context

M3 evidence sandbox needs PDF text extract and page counts without CGO (`CGO_ENABLED=0`, distroless static binary). `github.com/klippa-app/go-pdfium` offers a wazero/WebAssembly path that avoids CGO, but embeds `pdfium.wasm` (~5.6 MiB) into the module tree. Pulling that into `opentprm` would inflate release artifacts and slow CI smoke builds relative to the current TXT/JSON extract path.

`pdfcpu` (Apache-2.0, **CGO-free** pure Go) was re-evaluated for committee PDF packs and page counts (`github.com/pdfcpu/pdfcpu` v0.16.x). License and CGO constraints are satisfied, but the module tree remains ~29 MiB source — too heavy for the current static binary / CI smoke budget. A marked text/ZIP export pack satisfies RPT committee packaging without that weight. Revisit when binary-size budget allows a slim create-only import path.

## Decision

- Defer embedding go-pdfium wazero until binary-size and SLSA attestations are budgeted.
- Keep PDFium-free extract for TXT/JSON (and UTF-8 sniff) in `internal/sandbox/extract.go`.
- Ship a no-CGO PDF **page-count stub** that scans PDF object markers (`/Type /Page` not `/Pages`) for viewer/pipeline metadata.
- Ship committee/export **marked text ZIP** packs (`internal/domain/reporting/pack.go`) instead of pdfcpu PDF packs for now.
- Revisit go-pdfium or a slim pdfcpu create path when evidence PDF OCR/text extract becomes a hard gate.

## Consequences

Full PDF text extract remains open in REMAINING.md. Page-count stub is best-effort and may under/over-count unusual PDFs; it must not run untrusted content through an interpreter.
