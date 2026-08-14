"""The metadata gate.

Hard rules, any failure breaks CI:
  1. Every rule carries the full required Sigma frontmatter, including at least
     one ATT&CK technique tag (attack.tXXXX[.XXX]).
  2. Every rule has a fixture manifest under tests/fixtures/<stem>/, or is
     declared conversion-only.
  3. Every attack.* tag resolves against the live ATT&CK release.
"""
from __future__ import annotations

from detkit.attack import TECHNIQUE_TAG_RE, Vocabulary, check_tags, vocabulary
from detkit.paths import DETECTIONS, REPO
from detkit.rules import Rule, conversion_only, load_corpus, sample_count

REQUIRED_FIELDS = (
    "title", "id", "status", "description", "references", "author",
    "date", "modified", "tags", "logsource", "detection",
    "falsepositives", "level",
)


def has_technique_tag(tags: object) -> bool:
    return isinstance(tags, list) and any(
        isinstance(tag, str) and TECHNIQUE_TAG_RE.match(tag.strip()) for tag in tags
    )


def has_fixture(stem: str, exempt: set[str]) -> bool:
    return stem in exempt or sample_count(stem) > 0


def validate_rule(rule: Rule, vocab: Vocabulary, exempt: set[str]) -> list[str]:
    errors: list[str] = []

    for field in REQUIRED_FIELDS:
        if field not in rule.doc or rule.doc[field] in (None, "", []):
            errors.append(f"missing required field: {field}")

    tags = rule.doc.get("tags")
    if not has_technique_tag(tags):
        errors.append("no ATT&CK technique tag (need at least one attack.tXXXX)")
    errors.extend(check_tags(tags, vocab))

    if not has_fixture(rule.stem, exempt):
        errors.append(
            f"no test fixture: add tests/fixtures/{rule.stem}/sample_sources.yml "
            f"with >=1 pinned sample, or list '{rule.stem}' in tests/conversion_only.txt"
        )
    return errors


def run() -> int:
    rules = load_corpus(DETECTIONS)
    if not rules:
        print("no detection rules found under detections/")
        return 1

    vocab = vocabulary()
    exempt = conversion_only()
    print(
        f"ATT&CK {vocab.version} resolved (last reviewed against {vocab.reviewed}) — "
        f"{len(vocab.techniques)} techniques, {len(vocab.tactics)} tactics\n"
    )

    failed = 0
    for rule in rules:
        errors = validate_rule(rule, vocab, exempt)
        rel = rule.path.relative_to(REPO)
        if errors:
            failed += 1
            print(f"FAIL {rel}")
            for error in errors:
                print(f"     - {error}")
        else:
            print(f"OK   {rel}")

    print(f"\n{len(rules)} rule(s), {failed} failing.")
    return 1 if failed else 0
