"""ATT&CK tag parsing and vocabulary.

One place for this on purpose. The same regex and alias table used to be copied
into four generators, they drifted, and two of the copies matched tactic tags
with ``[a-z_]+`` — which cannot match a hyphen, so every multi-word ATT&CK
tactic was silently dropped from the reports.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from detkit.paths import ATTACK_VERSION_FILE

TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TACTIC_TAG_RE = re.compile(r"^attack\.([a-z_-]+)$", re.IGNORECASE)
ATTACK_TAG_RE = re.compile(r"^attack\.(.+)$", re.IGNORECASE)

# ATT&CK v19 renamed TA0005 Defense Evasion to "stealth" and split TA0112
# "defense-impairment" out of it. Corpora tagged before that (and older versions
# of these rules) still carry the retired token.
TACTIC_ALIASES = {"defense-evasion": "stealth"}


@dataclass(frozen=True)
class Tactic:
    shortname: str
    label: str
    matrix_label: str


# Kill-chain order, keyed by ATT&CK shortname.
TACTICS: tuple[Tactic, ...] = (
    Tactic("reconnaissance", "Reconnaissance", "Recon"),
    Tactic("resource-development", "Resource Development", "Resource\nDev"),
    Tactic("initial-access", "Initial Access", "Initial\nAccess"),
    Tactic("execution", "Execution", "Execution"),
    Tactic("persistence", "Persistence", "Persistence"),
    Tactic("privilege-escalation", "Privilege Escalation", "Priv\nEsc"),
    Tactic("stealth", "Stealth", "Stealth"),
    Tactic("defense-impairment", "Defense Impairment", "Defense\nImpairment"),
    Tactic("credential-access", "Credential Access", "Cred\nAccess"),
    Tactic("discovery", "Discovery", "Discovery"),
    Tactic("lateral-movement", "Lateral Movement", "Lateral\nMovement"),
    Tactic("collection", "Collection", "Collection"),
    Tactic("command-and-control", "Command & Control", "C2"),
    Tactic("exfiltration", "Exfiltration", "Exfil"),
    Tactic("impact", "Impact", "Impact"),
)

TACTIC_BY_NAME: dict[str, Tactic] = {t.shortname: t for t in TACTICS}


def norm_tactic(token: str) -> str:
    """Normalise a tactic token to its current ATT&CK shortname."""
    token = token.lower().replace("_", "-")
    return TACTIC_ALIASES.get(token, token)


@dataclass(frozen=True)
class Tags:
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]


def parse_tags(tags: object) -> Tags:
    """Extract normalised technique IDs and tactic shortnames from a tag list."""
    techniques: list[str] = []
    tactics: list[str] = []
    if not isinstance(tags, list):
        return Tags((), ())
    for tag in tags:
        if not isinstance(tag, str):
            continue
        stripped = tag.strip()
        technique = TECHNIQUE_TAG_RE.match(stripped)
        if technique:
            techniques.append(technique.group(1).upper())
            continue
        tactic = TACTIC_TAG_RE.match(stripped)
        if tactic:
            tactics.append(norm_tactic(tactic.group(1)))
    return Tags(tuple(techniques), tuple(tactics))


@dataclass(frozen=True)
class Vocabulary:
    version: str
    reviewed: str
    techniques: frozenset[str]
    tactics: frozenset[str]


class AttackDriftError(Exception):
    """The live ATT&CK release moved to a new major version."""


def vocabulary() -> Vocabulary:
    """Load the live ATT&CK vocabulary, refusing a major-version surprise.

    pySigma resolves ATT&CK from MITRE's live STIX feed, so the vocabulary moves
    with no commit here — which is how this repo drifted to 17 invalid tags
    unnoticed. Minor releases ship every few weeks and are content updates;
    failing on those would only train us to bump the pin without reading it.
    Major releases retire techniques and rename tactics, so those stop the build.
    Tag validity is checked against whatever resolves either way.
    """
    from sigma.data.mitre_attack import (
        mitre_attack_tactics,
        mitre_attack_techniques,
        mitre_attack_version,
    )

    reviewed = ATTACK_VERSION_FILE.read_text(encoding="utf-8").strip()
    if str(mitre_attack_version).split(".")[0] != reviewed.split(".")[0]:
        raise AttackDriftError(
            f"ATT&CK major version drift: .attack-version records {reviewed!r} but "
            f"pySigma resolved {mitre_attack_version!r}.\n"
            f"A major ATT&CK release retires techniques and renames tactics. "
            f"Re-validate every rule tag against it, then update .attack-version "
            f"to {mitre_attack_version!r}."
        )
    return Vocabulary(
        version=str(mitre_attack_version),
        reviewed=reviewed,
        techniques=frozenset(mitre_attack_techniques),
        tactics=frozenset(mitre_attack_tactics.values()),
    )


def check_tags(tags: object, vocab: Vocabulary) -> list[str]:
    """Every attack.* tag must resolve to a real technique or tactic."""
    errors: list[str] = []
    if not isinstance(tags, list):
        return errors
    for tag in tags:
        if not isinstance(tag, str):
            continue
        stripped = tag.strip()
        match = ATTACK_TAG_RE.match(stripped)
        if not match:
            continue
        token = match.group(1)
        if TECHNIQUE_TAG_RE.match(stripped):
            if token.upper() not in vocab.techniques:
                errors.append(f"unknown ATT&CK technique in tag: {tag}")
        elif token.lower() not in vocab.tactics:
            errors.append(
                f"unknown ATT&CK tactic in tag: {tag} "
                f"(shortnames are hyphenated, e.g. attack.credential-access)"
            )
    return errors
