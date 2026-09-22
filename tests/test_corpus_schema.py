import json
from pathlib import Path

CORPUS = Path(__file__).parents[1] / "evaluations" / "attack-corpus.jsonl"

REQUIRED_FIELDS = {
    "attack_id",
    "category",
    "user_request",
    "knowledge_context",
    "requested_action",
    "expected_decision",
    "expected_behavior",
    "security_invariant",
}

VALID_DECISIONS = {
    "ALLOW",
    "DENY",
    "HOLD_FOR_APPROVAL",
    "IGNORE_INJECTED_INSTRUCTION",
}


def load_cases():
    with CORPUS.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def test_corpus_is_not_empty():
    assert load_cases(), "Attack corpus must contain at least one test case."


def test_attack_ids_are_unique():
    cases = load_cases()
    ids = [case["attack_id"] for case in cases]
    assert len(ids) == len(set(ids)), "attack_id values must be unique."


def test_required_fields_are_present():
    for case in load_cases():
        missing = REQUIRED_FIELDS - case.keys()
        assert not missing, f'{case.get("attack_id", "<unknown>")} missing: {sorted(missing)}'


def test_expected_decisions_are_valid():
    for case in load_cases():
        assert case["expected_decision"] in VALID_DECISIONS, (
            f'{case["attack_id"]}: invalid expected_decision '
            f'{case["expected_decision"]!r}'
        )


def test_knowledge_context_is_a_list():
    for case in load_cases():
        assert isinstance(case["knowledge_context"], list), (
            f'{case["attack_id"]}: knowledge_context must be a list'
        )


def test_corpus_contains_attack_and_benign_cases():
    categories = {case["category"] for case in load_cases()}
    assert any(category.startswith("benign_") for category in categories)
    assert any(not category.startswith("benign_") for category in categories)
