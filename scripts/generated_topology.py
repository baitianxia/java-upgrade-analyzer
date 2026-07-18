#!/usr/bin/env python3
"""Deterministic Java topology fixtures with analyzer-independent truth data."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import random
import subprocess


REQUIRED_DIMENSIONS = (
    "same_jar",
    "cross_jar",
    "same_coordinate",
    "overload",
    "inheritance",
    "constant",
    "reflection",
    "callback",
)


@dataclass(frozen=True)
class GenerationDimensions:
    values: tuple[str, ...]

    @classmethod
    def complete(cls) -> "GenerationDimensions":
        return cls(REQUIRED_DIMENSIONS)

    def required_values(self) -> set[str]:
        return set(self.values)


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    coordinate: str
    packaging: str
    ownership: str


@dataclass(frozen=True)
class ApiSpec:
    owner: str
    member: str
    descriptor: str
    kind: str

    @property
    def identity(self) -> str:
        return f"{self.owner}#{self.member}{self.descriptor}:{self.kind}"


@dataclass(frozen=True)
class EdgeSpec:
    caller: str
    target: str
    dimension: str
    evidence_kind: str
    expected_conclusion: str

    @property
    def identity(self) -> str:
        return f"{self.caller}->{self.target}@{self.dimension}:{self.evidence_kind}"


@dataclass(frozen=True)
class ActivationSpec:
    edge_identity: str
    activation_kind: str
    complete: bool


@dataclass(frozen=True)
class TopologySpec:
    seed: int
    token: str
    modules: tuple[ModuleSpec, ...]
    apis: tuple[ApiSpec, ...]
    truth_edges: tuple[EdgeSpec, ...]
    activations: tuple[ActivationSpec, ...]
    sources: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class GeneratedTopology:
    spec: TopologySpec

    def covered_dimensions(self) -> set[str]:
        return {edge.dimension for edge in self.spec.truth_edges}

    def canonical_json(self) -> str:
        payload = asdict(self.spec)
        payload["truth_edges"] = [
            {**asdict(edge), "identity": edge.identity}
            for edge in sorted(self.spec.truth_edges, key=lambda item: item.identity)
        ]
        payload["apis"] = [
            {**asdict(api), "identity": api.identity}
            for api in sorted(self.spec.apis, key=lambda item: item.identity)
        ]
        payload["modules"] = sorted(payload["modules"], key=lambda row: row["name"])
        payload["activations"] = sorted(
            payload["activations"], key=lambda row: row["edge_identity"]
        )
        payload["sources"] = sorted(payload["sources"])
        return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


@dataclass(frozen=True)
class MaterializedTopology:
    root: Path
    source_dir: Path
    classes_dir: Path
    manifest_path: Path


def _source(token: str) -> str:
    return f"""package generated;
import java.lang.reflect.Method;

interface Callback {{ void invoke(); }}
class Base {{ public String inherited() {{ return \"base\"; }} }}
class Provider extends Base implements Callback {{
  static final String CONSTANT = \"{token}\";
  public String target() {{ return CONSTANT; }}
  public String target(String value) {{ return value; }}
  public void invoke() {{ target(); }}
}}
public class Topology{token} {{
  private final Provider provider = new Provider();
  public String sameJar() {{ return provider.target(); }}
  public String crossJar() {{ return bridge(); }}
  private String bridge() {{ return provider.target(); }}
  public String sameCoordinate() {{ return provider.target(); }}
  public String overloaded() {{ return provider.target("x"); }}
  public String inherited() {{ return provider.inherited(); }}
  public String constant() {{ return Provider.CONSTANT; }}
  public Object reflected() throws Exception {{
    Method method = Provider.class.getMethod("target");
    return method.invoke(provider);
  }}
  public void callback(Callback callback) {{ callback.invoke(); }}
}}
"""


def generate_topology(
    seed: int, dimensions: GenerationDimensions
) -> GeneratedTopology:
    unknown = set(dimensions.values) - set(REQUIRED_DIMENSIONS)
    if unknown:
        raise ValueError(f"unknown topology dimensions: {sorted(unknown)}")
    rng = random.Random(seed)
    token = f"T{rng.randrange(1_000_000):06d}"
    owner = f"generated.Topology{token}"
    provider = "generated.Provider"
    api_by_dimension = {
        "same_jar": ApiSpec(provider, "target", "()Ljava/lang/String;", "method"),
        "cross_jar": ApiSpec(provider, "target", "()Ljava/lang/String;", "method"),
        "same_coordinate": ApiSpec(provider, "target", "()Ljava/lang/String;", "method"),
        "overload": ApiSpec(provider, "target", "(Ljava/lang/String;)Ljava/lang/String;", "method"),
        "inheritance": ApiSpec("generated.Base", "inherited", "()Ljava/lang/String;", "method"),
        "constant": ApiSpec(provider, "CONSTANT", "Ljava/lang/String;", "field"),
        "reflection": ApiSpec(provider, "target", "()Ljava/lang/String;", "method"),
        "callback": ApiSpec("generated.Callback", "invoke", "()V", "method"),
    }
    caller_members = {
        "same_jar": "sameJar",
        "cross_jar": "bridge",
        "same_coordinate": "sameCoordinate",
        "overload": "overloaded",
        "inheritance": "inherited",
        "constant": "constant",
        "reflection": "reflected",
        "callback": "callback",
    }
    caller_by_dimension = {
        dimension: f"{owner}#{caller_members[dimension]}()"
        for dimension in dimensions.values
    }
    edges = tuple(
        EdgeSpec(
            caller_by_dimension[dimension],
            api_by_dimension[dimension].identity,
            dimension,
            "semantic" if dimension in {"reflection", "callback"} else "bytecode",
            "uncertain" if dimension == "constant" else "reachable",
        )
        for dimension in dimensions.values
    )
    activations = tuple(
        ActivationSpec(edge.identity, edge.dimension, True)
        for edge in edges
        if edge.evidence_kind == "semantic"
    )
    apis = tuple(
        sorted(set(api_by_dimension[dimension] for dimension in dimensions.values), key=lambda api: api.identity)
    )
    spec = TopologySpec(
        seed=seed,
        token=token,
        modules=(
            ModuleSpec("application", "generated:application:1", "jar", "business"),
            ModuleSpec("library", "generated:application:1", "nested-jar", "internal"),
        ),
        apis=apis,
        truth_edges=edges,
        activations=activations,
        sources=((f"generated/Topology{token}.java", _source(token)),),
    )
    identities = [edge.identity for edge in edges]
    if len(identities) != len(set(identities)):
        raise ValueError("generated truth edge identities are not unique")
    return GeneratedTopology(spec)


def materialize_topology(
    generated: GeneratedTopology, root: Path
) -> MaterializedTopology:
    root = Path(root)
    source_dir = root / "src"
    classes_dir = root / "classes"
    manifest_path = root / "truth.json"
    source_paths = []
    for relative, content in generated.spec.sources:
        path = source_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        source_paths.append(path)
    classes_dir.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        ["javac", "-encoding", "UTF-8", "-d", str(classes_dir), *map(str, source_paths)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"javac failed: {completed.stderr.strip()}")
    manifest_path.write_text(generated.canonical_json(), encoding="utf-8")
    return MaterializedTopology(root, source_dir, classes_dir, manifest_path)
