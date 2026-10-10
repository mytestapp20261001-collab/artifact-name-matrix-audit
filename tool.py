#!/usr/bin/env python3
"""Offline, bounded contract audit. Python 3.12 standard library only."""
import argparse
import json
import math
import sys
from pathlib import Path

MAX_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 10000
class BadInput(ValueError):
    pass
class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise BadInput("invalid command arguments")

def require(condition, message):
    if not condition:
        raise BadInput(message)

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result

def reject_constant(value):
    raise BadInput("nonfinite JSON number")

def read_text(path):
    require(Path(path).is_file(), "input must be a regular file")
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "input exceeds 2 MiB limit")
    return raw.decode("utf-8-sig")

def finite_float(value):
    parsed = float(value)
    require(math.isfinite(parsed), "nonfinite JSON number")
    return parsed

def load_json(path):
    return json.loads(read_text(path), object_pairs_hook=pairs, parse_constant=reject_constant, parse_float=finite_float)

def report(findings, **summary):
    return {"schema_version": 1, "tool": TOOL, "status": "findings" if findings else "pass", "summary": summary, "findings": findings}

def finding(code, **where):
    return {"code": code, **where}

def run(build_parser, action):
    try:
        parser = Parser(description=__doc__)
        build_parser(parser)
        result = action(parser.parse_args())
        status = 1 if result["status"] == "findings" else 0
    except (ValueError, OSError, UnicodeError, RecursionError, OverflowError) as exc:
        message = str(exc) if isinstance(exc, BadInput) else "unreadable or malformed input"
        result = {"schema_version": 1, "tool": TOOL, "status": "error", "error": message}
        status = 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, allow_nan=False))
    return status

import itertools
import hashlib
import re
import string
TOOL = "artifact-name-matrix-audit"

def audit(data):
    require(isinstance(data, dict) and set(data) <= {"matrix", "template", "max_artifacts"}, "expected matrix/template/budget object")
    matrix, template, budget = data.get("matrix"), data.get("template"), data.get("max_artifacts", 1000)
    require(isinstance(matrix, dict) and 1 <= len(matrix) <= 12, "matrix needs 1..12 dimensions")
    require(isinstance(template, str) and 0 < len(template) <= 1024, "template must be a nonempty bounded string")
    require(type(budget) is int and 1 <= budget <= 10000, "max_artifacts must be 1..10000")
    size = 1
    for key, values in matrix.items():
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is not None, "dimension names must be identifiers")
        require(isinstance(values, list) and 1 <= len(values) <= 100, "dimension needs 1..100 string values")
        require(all(isinstance(v, str) and 0 < len(v) <= 128 for v in values), "dimension values must be bounded nonempty strings")
        size *= len(values)
    findings, used = [], set()
    try:
        fields = list(string.Formatter().parse(template))
    except ValueError:
        raise BadInput("malformed name template") from None
    for _, field, spec, conversion in fields:
        if field is not None:
            require(field in matrix and not spec and conversion is None, "only simple named dimension placeholders are supported")
            used.add(field)
    for index, dimension in enumerate(matrix):
        if dimension not in used:
            findings.append(finding("unreferenced_dimension", dimension_index=index))
    if size > budget:
        findings.append(finding("artifact_budget_exceeded", count=size, budget=budget))
        return report(findings, combinations=size, generated=0, names=[])
    names, seen, portable_seen = [], {}, {}
    for index, values in enumerate(itertools.product(*matrix.values())):
        name = template.format_map(dict(zip(matrix, values)))
        names.append(name if len(name) <= 255 else None)
        exact_key = hashlib.sha256(name.encode()).hexdigest()
        if exact_key in seen:
            findings.append(finding("name_collision", combination_index=index, first_index=seen[exact_key]))
        else:
            seen[exact_key] = index
        portable = hashlib.sha256(name.casefold().rstrip(" .").encode()).hexdigest()
        if portable in portable_seen and portable_seen[portable][1] != exact_key:
            findings.append(finding("portable_name_collision", combination_index=index, first_index=portable_seen[portable][0]))
        else:
            portable_seen[portable] = (index, exact_key)
        if (not name or len(name) > 255 or name in (".", "..") or name[-1:] in (".", " ") or re.search(r'[<>:"/\\|?*\x00-\x1f\x7f]', name) or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", name)):
            findings.append(finding("unsafe_artifact_name", combination_index=index))
    return report(findings, combinations=size, generated=len(names), names=names)

def configure(parser):
    parser.add_argument("input", help="local artifact matrix contract JSON")
if __name__ == "__main__":
    sys.exit(run(configure, lambda args: audit(load_json(args.input))))
