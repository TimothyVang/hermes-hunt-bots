# Parked: framework-managed team benchmark

This folder holds the framework-managed threat-hunt benchmark. It is **parked**: kept and tested, but not part of the product. The roadmap returns to it at R5. Until then:

- The portable ZIP (`framework/package_portable.py`) does not ship it, its tests, or its nine invented evaluator keys (`benchmarks/fixtures/*/evaluator/truth.json`). The gate's policy check applies its private-state and capture rules to `research/` as it does to `framework/`, and `.github/CODEOWNERS` covers `/research/`.
- The default gate (`python scripts/hunt_bots_check.py`) does not run its tests. Nothing under `framework/` or `operator/` imports it.
- It still drives the real ledger. It imports `bot`, `workflows` and `langchain_adapter` from `../../framework/` through `benchmark_paths.py`, so it only runs from a full checkout (or from a `snapshot-source` copy, which holds both in one folder).

What the benchmark does, its CLI, its real-IOC (`ioc-feed-1`) and SQLite query-track (`query_store`) contracts, its Novel-APT behavioral workflow (`benchmarks/team-workflow-novel-apt.json`), and its subscription loopback runner (`benchmark_openai_http.py` + `benchmark_subscription_proxy.py`) are in [benchmarks/README.md](benchmarks/README.md). The OTRF, attack_data, BOTS, Golden SAML, Invictus AWS, CAM-LDS and whole-campaign SQLite query-track APT importers are in [benchmarks/importers/README.md](benchmarks/importers/README.md). `envision_protocol.py` (bounded JSON and HTTP helpers for the benchmark's contracts and model adapters) moved here with it, because no tracked code outside the benchmark imports it. The untracked, git-ignored Envision bridge scripts some checkouts still keep in `framework/` imported it; their docs were removed in #68.

## Run the tests

From the repository root, with the test Python the gate uses:

```powershell
python scripts/hunt_bots_check.py --benchmark
```

It runs the policy gate and then only this folder's tests, and prints `benchmark tests: Ran <n> tests OK` in its summary line. To run the suite directly, from this folder:

```powershell
python -B -m unittest discover
```

The suite took about seven minutes on the maintainer's Windows machine.

## Run the CLI

From this folder, for example:

```powershell
py -3 -B benchmark.py validate --experiment benchmarks/examples/experiment.json --bundle-root benchmarks
```

State roots must lie outside the checkout (`benchmark_contracts.validate_state_root` refuses any path inside it).

## License

AGPL-3.0, like `framework/` ([framework/LICENSE](../../framework/LICENSE)).
