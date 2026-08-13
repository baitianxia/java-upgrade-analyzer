"""Independent closed-graph oracle for the public query CLI fixture.

This deliberately knows nothing about the production query index schema.  It
enumerates an authored one-edge graph and applies only the fixture's public
query rules, so the expected chain set is not copied from analyzer output.
"""

from __future__ import annotations


def expected_chains(edges: tuple[dict, ...], targets: tuple[dict, ...], arguments):
    arguments = list(arguments)
    limit = 20
    if "--limit" in arguments:
        limit = int(arguments[arguments.index("--limit") + 1])

    selected = []
    if "--method" in arguments:
        query = arguments[arguments.index("--method") + 1]
        fuzzy = "--fuzzy" in arguments
        if "(" in query:
            selected = [edge for edge in edges if edge["target"] == query]
        else:
            selected = [
                edge for edge in edges
                if edge["target"].startswith(query + "(")
            ]
        if not selected and fuzzy:
            name = query.split("(", 1)[0].rsplit(".", 1)[-1]
            signature = "(" + query.split("(", 1)[1] if "(" in query else ""
            selected = [
                edge for edge in edges
                if edge["target"].split("(", 1)[0].rsplit(".", 1)[-1] == name
                and (not signature or edge["target"].endswith(signature))
            ]
    elif "--coord" in arguments:
        query = arguments[arguments.index("--coord") + 1]
        coords = sorted({target["coord"] for target in targets})
        if query in coords:
            matched = {query}
        else:
            candidates = {
                coord for coord in coords if coord.rsplit(":", 1)[-1] == query
            }
            matched = candidates if len(candidates) == 1 else set()
        target_names = [
            target["target"] for target in targets
            if target["coord"] in matched
        ]
        selected = [
            edge for target_name in target_names for edge in edges
            if edge["target"] == target_name
        ]
    elif "--package" in arguments:
        prefix = arguments[arguments.index("--package") + 1].removesuffix(".*")
        target_names = [
            target["target"] for target in targets
            if target["api_name"] == prefix
            or target["api_name"].startswith(prefix + ".")
        ]
        selected = [
            edge for target_name in target_names for edge in edges
            if edge["target"] == target_name
        ]

    return [edge["chain"] for edge in selected[:max(0, limit)]]
