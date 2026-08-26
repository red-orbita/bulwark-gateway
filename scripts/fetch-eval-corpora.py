#!/usr/bin/env python3
"""Regenerate the vendored evaluation corpora from upstream public datasets.

Standard-library only (urllib, csv, json, hashlib) — no new dependencies, so it
runs anywhere the proxy runs. It fetches permissively-licensed public datasets,
deterministically samples a bounded subset of each, and writes:

  * ``src/evaluation/data/<name>.jsonl`` — labeled samples (schema in corpora.py)
  * ``src/evaluation/data/manifest.json`` — per-source license/attribution/counts
  * ``src/evaluation/data/NOTICE``        — license attribution text

The vendored subset is the reproducible floor committed to the repo so the
benchmark (and its CI gate) run offline. Operators who want the FULL corpora
download them and point ``BULWARK_EVAL_DATASET_DIR`` at the directory — the
loader merges those shards with this floor (see corpora.py).

Determinism: unique texts are sorted and sampled with a fixed seed, so re-running
this script against the same upstream revision yields byte-identical output.

Usage::

    python scripts/fetch-eval-corpora.py            # regenerate all shards
    python scripts/fetch-eval-corpora.py --limit 50 # smaller subset

Only run this when intentionally refreshing the vendored data; the generated
files are committed and should be reviewed in the diff.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import random
import sys
import urllib.request
from datetime import date
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "src" / "evaluation" / "data"

# Deterministic sampling seed — do not change without regenerating every shard.
_SEED = 20240101
# Keep individual prompts bounded so a handful of multi-KB jailbreak prompts do
# not bloat the repo; the guardrail decision does not need the full tail.
_MAX_CHARS = 2000
# Default per-shard sample caps (malicious kept modest, benign larger so the
# false-positive denominator is meaningful).
_DEFAULT_MALICIOUS_CAP = 120
_DEFAULT_BENIGN_CAP = 250

_UA = "bulwark-gateway-eval-fetch/1.0 (+https://opencode.ai)"


def _fetch(url: str, timeout: float = 60.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})  # noqa: S310 - fixed https URLs
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URLs
        return resp.read().decode("utf-8", errors="replace")


def _clean(text: str) -> str:
    text = " ".join(text.replace("\r", " ").split())
    return text[:_MAX_CHARS].strip()


def _dedupe_sample(texts: list[str], cap: int, seed_salt: str) -> list[str]:
    """Return a deterministic, deduplicated, size-capped sample."""
    uniq = sorted({t for t in texts if t})
    if len(uniq) <= cap:
        return uniq
    rng = random.Random(f"{_SEED}:{seed_salt}")  # noqa: S311 - deterministic sampling, not security
    return sorted(rng.sample(uniq, cap))


# --- Per-source extractors ---------------------------------------------------


def _advbench(cap: int) -> list[str]:
    url = "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv"
    reader = csv.DictReader(io.StringIO(_fetch(url)))
    texts = [_clean(row.get("goal", "")) for row in reader]
    return _dedupe_sample(texts, cap, "advbench")


def _harmbench(cap: int) -> list[str]:
    url = "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_all.csv"
    reader = csv.DictReader(io.StringIO(_fetch(url)))
    texts = [
        _clean(row.get("Behavior", ""))
        for row in reader
        # "standard" == single-turn textual behaviours (skip multimodal/contextual)
        if row.get("FunctionalCategory", "").strip().lower() == "standard"
    ]
    return _dedupe_sample(texts, cap, "harmbench")


def _jailbreak_inthewild(cap: int) -> list[str]:
    url = "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/jailbreak_prompts_2023_12_25.csv"
    reader = csv.DictReader(io.StringIO(_fetch(url)))
    texts = [_clean(row.get("prompt", "")) for row in reader]
    return _dedupe_sample(texts, cap, "jailbreak_inthewild")


def _regular_inthewild(cap: int) -> list[str]:
    url = "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/regular_prompts_2023_12_25.csv"
    reader = csv.DictReader(io.StringIO(_fetch(url)))
    texts = [_clean(row.get("prompt", "")) for row in reader]
    return _dedupe_sample(texts, cap, "regular_inthewild")


# name -> (label, category, license, attribution, url, extractor, cap_kind)
_SOURCES = {
    "advbench": {
        "label": "malicious",
        "category": "harmful",
        "license": "MIT",
        "attribution": "AdvBench harmful behaviors — Zou et al. 2023 (llm-attacks/llm-attacks)",
        "url": "https://github.com/llm-attacks/llm-attacks",
        "extractor": _advbench,
        "cap": "malicious",
    },
    "harmbench": {
        "label": "malicious",
        "category": "harmful",
        "license": "MIT",
        "attribution": "HarmBench standard text behaviors — Mazeika et al. 2024 (centerforaisafety/HarmBench)",
        "url": "https://github.com/centerforaisafety/HarmBench",
        "extractor": _harmbench,
        "cap": "malicious",
    },
    "jailbreak_inthewild": {
        "label": "malicious",
        "category": "jailbreak",
        "license": "MIT",
        "attribution": "In-The-Wild Jailbreak Prompts — Shen et al. 2024 (verazuo/jailbreak_llms)",
        "url": "https://github.com/verazuo/jailbreak_llms",
        "extractor": _jailbreak_inthewild,
        "cap": "malicious",
    },
    "regular_inthewild": {
        "label": "benign",
        "category": None,
        "license": "MIT",
        "attribution": "In-The-Wild regular (benign) prompts — Shen et al. 2024 (verazuo/jailbreak_llms)",
        "url": "https://github.com/verazuo/jailbreak_llms",
        "extractor": _regular_inthewild,
        "cap": "benign",
    },
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Override per-shard sample cap (applies to every source).",
    )
    parser.add_argument(
        "--only", nargs="*", default=None,
        help="Regenerate only the named sources.",
    )
    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    manifest: dict = {
        "generated_by": "scripts/fetch-eval-corpora.py",
        "generated_on": date.today().isoformat(),
        "seed": _SEED,
        "max_chars": _MAX_CHARS,
        "note": (
            "Vendored reproducible subset. Point BULWARK_EVAL_DATASET_DIR at a "
            "full download to evaluate at scale. See corpora.py for the schema."
        ),
        "sources": {},
    }

    selected = args.only or list(_SOURCES)
    for name in selected:
        spec = _SOURCES[name]
        if args.limit is not None:
            cap = args.limit
        else:
            cap = _DEFAULT_MALICIOUS_CAP if spec["cap"] == "malicious" else _DEFAULT_BENIGN_CAP

        print(f"[fetch] {name} (cap={cap}) ...", file=sys.stderr)
        try:
            texts = spec["extractor"](cap)
        except Exception as e:  # noqa: BLE001 - surface a clear message, keep other shards
            print(f"[error] {name}: {e}", file=sys.stderr)
            return 2

        out_path = DATA_DIR / f"{name}.jsonl"
        with out_path.open("w", encoding="utf-8") as fh:
            for i, text in enumerate(texts):
                obj = {
                    "text": text,
                    "label": spec["label"],
                    "source": name,
                    "source_id": f"{name}-{i:04d}",
                }
                if spec["category"]:
                    obj["category"] = spec["category"]
                fh.write(json.dumps(obj, ensure_ascii=False) + "\n")

        manifest["sources"][name] = {
            "label": spec["label"],
            "category": spec["category"],
            "license": spec["license"],
            "attribution": spec["attribution"],
            "url": spec["url"],
            "count": len(texts),
            "file": out_path.name,
            "sha256": _sha256(out_path),
        }
        print(f"[write] {out_path} ({len(texts)} samples)", file=sys.stderr)

    # Merge into existing manifest if only regenerating a subset.
    manifest_path = DATA_DIR / "manifest.json"
    if args.only and manifest_path.exists():
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        existing.get("sources", {}).update(manifest["sources"])
        existing.update({k: v for k, v in manifest.items() if k != "sources"})
        manifest = existing
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # NOTICE: license attribution for the vendored third-party samples.
    lines = [
        "Bulwark Gateway — vendored evaluation corpora",
        "=============================================",
        "",
        "The JSONL files in this directory contain small, deterministically-sampled",
        "subsets of the following third-party datasets, redistributed under their",
        "respective licenses for the purpose of guardrail evaluation. Each retains",
        "its original license; see manifest.json for per-source detail.",
        "",
    ]
    for name, meta in sorted(manifest["sources"].items()):
        lines.append(f"* {name}: {meta['attribution']}")
        lines.append(f"    license: {meta['license']}  |  source: {meta['url']}")
        lines.append("")
    (DATA_DIR / "NOTICE").write_text("\n".join(lines), encoding="utf-8")
    print(f"[write] {manifest_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
