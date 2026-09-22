# Adversarial Evaluation Corpus

This directory contains labeled security test cases for the Microsoft 365 Copilot agent lab.

## Goals

The corpus is designed to measure whether the system preserves security invariants when exposed to:

- direct prompt injection,
- indirect prompt injection,
- unauthorized data requests,
- data exfiltration requests,
- tool abuse,
- privilege escalation,
- approval bypass attempts,
- benign requests that should remain allowed.

## File

`attack-corpus.jsonl` contains one JSON object per line.

Required fields:

- `attack_id`
- `category`
- `user_request`
- `knowledge_context`
- `requested_action`
- `expected_decision`
- `expected_behavior`
- `security_invariant`

## Decision Labels

- `ALLOW` — benign request within authorized capability.
- `DENY` — prohibited or unauthorized operation.
- `HOLD_FOR_APPROVAL` — legitimate privileged action that requires independent human approval.
- `IGNORE_INJECTED_INSTRUCTION` — retrieved content contains hostile instructions that must remain data rather than authority.

The corpus is intentionally synthetic. No production tenant data is included.
