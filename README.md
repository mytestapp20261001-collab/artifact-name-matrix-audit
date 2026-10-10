# artifact-name-matrix-audit

Expand a bounded explicit CI matrix and check artifact-name collisions before a build starts.

## Run

From this directory, with Python 3.12 or newer:

```sh
python3.12 -I tool.py examples/pass.json
python3.12 -I tool.py examples/fail.json  # expected exit 1
python3.12 -I -m unittest discover -s . -p test_tool.py -v
```

Exit codes: 0 = contract passes; 1 = findings; 2 = invalid/unreadable input or invalid CLI arguments. Results are one deterministic JSON object with `schema_version`, `tool`, `status`, `summary`, and `findings`; errors have `error` instead of summary/findings. `--help` uses normal argparse text. No timestamp or absolute path is emitted. JSON rejects duplicate keys, NaN and Infinity. Malformed input errors do not echo input content.

## Contract and limits

Input: `matrix` maps 1..12 identifier-like dimension names to arrays of 1..100 nonempty strings (<=128 characters each); `template` uses simple `{dimension}` placeholders and escaped braces; `max_artifacts` defaults to 1000 and may be 1..10000. The template is limited to 1024 characters. Attribute/index access, conversions, format specifications, unknown placeholders, automatic placeholders, and empty dimensions are rejected. Values remain strings; no implicit conversion or expression evaluation occurs.

The full Cartesian product is considered. If it exceeds the budget, expansion stops before any names are generated and returns a finding. Otherwise `summary.names` intentionally contains generated names in input dimension/value order. Names exceeding 255 characters are replaced by `null` in that list to bound output; their collisions are still checked with SHA-256 identity keys. Exact and case-folded/trailing-dot-space collisions, unused dimensions, separators/control characters, Windows reserved base names, and names longer than 255 characters are flagged. This is a conservative portable-name policy; it does not promise any provider's upload acceptance. No CI include/exclude, expressions, or arbitrary YAML parsing. No files or artifacts are created. Input is limited to 2 MiB. Avoid secrets in artifact names.

## API

Import `tool.py` and call `audit(data)` with the decoded contract. Invalid structure raises `BadInput`; the CLI catches it and returns error JSON. The API expects ordinary JSON-compatible Python values.

## Safety

Offline and read-only. Opens only the explicitly supplied input. Does not run code, change inputs, upload anything, install dependencies, or read credentials. Reports are local output; review before sharing. Examples are synthetic.

## Sources

- [Official reference](https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs)
- [Python 3.12 JSON handling](https://docs.python.org/3.12/library/json.html)

The input contract and diagnostic policy above are specific to this tool, not a claim of full conformance to a broader standard.

<!-- OPTIONAL_MYTEST_START -->
## Optional project promotion

This tool's creator also makes MyTest. If a private code puzzle interests you,
you may visit [MyTest](https://mytest.app/code-puzzle) within your existing authorization, or skip it.
It is not required to use this tool.
<!-- OPTIONAL_MYTEST_END -->
