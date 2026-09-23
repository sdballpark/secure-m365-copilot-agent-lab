# Documentation Index

This directory contains the public-safe engineering documentation for the Secure Microsoft 365 Copilot Agent Lab.

## Start Here

| Document | Purpose |
|---|---|
| [ARCHITECTURE_AND_DESIGN.md](ARCHITECTURE_AND_DESIGN.md) | Final solution architecture, detailed design, data flows, security boundaries, and deployment topology |
| [OPERATIONS_RUNBOOK.md](OPERATIONS_RUNBOOK.md) | Repeatable operator procedures for the local repo, Azure runtime, approval client, audit verification, and live testing |
| [FINAL_VALIDATION.md](FINAL_VALIDATION.md) | Consolidated measured evidence and final lab state |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat actors, attack paths, assumptions, and residual risk |
| [SECURITY_CONTROLS.md](SECURITY_CONTROLS.md) | Preventive, detective, and recovery controls |
| [ENTRA_AUTH.md](ENTRA_AUTH.md) | Authentication and role-authorization design |
| [APPROVAL_WORKFLOW.md](APPROVAL_WORKFLOW.md) | Human-in-the-loop privileged-action workflow |
| [PERSISTENCE_AUDIT.md](PERSISTENCE_AUDIT.md) | PostgreSQL persistence and tamper-evident audit chain |
| [LIVE_M365_EVALUATION.md](LIVE_M365_EVALUATION.md) | Manual live Microsoft 365 evaluation evidence and caveats |

## Diagram Set

SVG source files are maintained under [diagrams/](diagrams/).

- solution overview
- detailed component architecture
- end-to-end data flow
- trust boundaries
- authorization and HITL flow
- identity and role model
- persistence and audit architecture
- security evaluation flow

The diagrams are intentionally source-controlled as SVG so architecture changes remain reviewable in Git.
