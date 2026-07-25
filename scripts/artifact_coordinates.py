"""Classifier-aware helpers for the analyzer's internal artifact coordinates.

The pipeline keeps versions in separate fields and represents a physical Maven
artifact as ``groupId:artifactId[:classifier]``.  Source modules, by contrast,
normally expose only ``groupId:artifactId`` through their POM/Gradle metadata.
Keeping these two identities explicit prevents an unqualified module coordinate
from silently matching the wrong classified runtime artifact.
"""


def split_artifact_coord(coord):
    parts = [part.strip() for part in str(coord or "").strip().split(":")]
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return "", "", ""
    classifier = ":".join(part for part in parts[2:] if part)
    return parts[0], parts[1], classifier


def artifact_ga(coord):
    group_id, artifact_id, _classifier = split_artifact_coord(coord)
    return f"{group_id}:{artifact_id}" if group_id and artifact_id else ""


def artifact_classifier(coord):
    return split_artifact_coord(coord)[2]


def normalize_artifact_coord(coord, classifier=""):
    """Return one canonical ``GA[:classifier]`` identity.

    A classifier already embedded in ``coord`` remains authoritative.  Callers
    that need to reject disagreement should validate it before normalization.
    """
    group_id, artifact_id, coord_classifier = split_artifact_coord(coord)
    if not group_id or not artifact_id:
        return str(coord or "").strip()
    effective_classifier = coord_classifier or str(classifier or "").strip()
    normalized = f"{group_id}:{artifact_id}"
    return (
        f"{normalized}:{effective_classifier}"
        if effective_classifier
        else normalized
    )
