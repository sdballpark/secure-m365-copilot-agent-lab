import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
EVALS = ROOT / "evals" / "evals.json"
CASE_MAP = ROOT / "evals" / "case-map.json"

EXPECTED_ATTACK_IDS = {
    "A003",
    "A004",
    "A011",
    "A012",
    "A016",
    "A017",
    "A020",
}


def load(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_live_eval_dataset_uses_current_documented_schema_version():
    dataset = load(EVALS)
    assert dataset["schemaVersion"] == "1.6.0"


def test_live_eval_dataset_contains_seven_model_dependent_cases():
    dataset = load(EVALS)
    mapping = load(CASE_MAP)

    assert len(dataset["items"]) == 7
    assert len(mapping["items"]) == 7


def test_case_map_covers_expected_corpus_ids():
    mapping = load(CASE_MAP)
    attack_ids = {item["attack_id"] for item in mapping["items"]}
    assert attack_ids == EXPECTED_ATTACK_IDS


def test_case_map_indexes_match_dataset_order():
    dataset = load(EVALS)
    mapping = load(CASE_MAP)

    indexes = [item["index"] for item in mapping["items"]]
    assert indexes == list(range(len(dataset["items"])))


def test_every_live_eval_has_prompt_and_expected_response():
    dataset = load(EVALS)

    for item in dataset["items"]:
        assert isinstance(item["prompt"], str) and item["prompt"].strip()
        assert (
            isinstance(item["expected_response"], str)
            and item["expected_response"].strip()
        )


def test_poisoned_document_cases_confirm_retrieval():
    dataset = load(EVALS)
    mapping = load(CASE_MAP)
    poisoned = {"A003", "A004", "A016", "A017"}

    for meta in mapping["items"]:
        if meta["attack_id"] not in poisoned:
            continue

        item = dataset["items"][meta["index"]]
        retrieval = item["evaluators"]["RetrievalResult"]
        assert retrieval["expected_items"]
        assert retrieval["max_rank"] >= 1


def test_default_quality_evaluators_are_enabled():
    dataset = load(EVALS)
    enabled = set(dataset["default_evaluators"])

    assert {"Relevance", "Groundedness", "Similarity"} <= enabled
