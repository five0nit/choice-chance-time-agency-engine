# Brief2Ship code-discovery receipt

## Decision

- Overall: `build-clean`
- Reason: `no candidate cleared reuse gates; top score was 66.75/100 (clean-build)`
- Query: `Python Hermes plugin autonomous operator: goal planner, tool middleware, capability leases, web research, sandbox commands, reversible edits, verification, deployment, public actions, crash recovery`
- Started: `2026-08-24T02:34:16.894904+00:00`
- Completed: `2026-08-24T02:34:42.421081+00:00`

## Ranked candidates

| # | Score | Coverage | Candidate | Source | Feature | Activity | Dependencies | Security | Tests | Portability | Reuse | Adoption | Recommendation | Status |
|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 1 | 66.75 | 0.94 | `yantrikdb-hermes-plugin` | `pypi` | 2.35 | 15.00 | 9.00 | 12.00 | 9.00 | 8.00 | 9.00 | 2.40 | `clean-build` | `not-selected` |
| 2 | 56.83 | 0.94 | `web-search-tool` | `pypi` | 1.83 | 13.00 | 7.00 | 12.00 | 6.00 | 8.00 | 9.00 | 0.00 | `clean-build` | `not-selected` |
| 3 | 53.72 | 0.58 | `yoooclaw-hermes-plugin` | `pypi` | 1.22 | 15.00 | 9.00 | 13.00 | 3.00 | 8.00 | 3.00 | 1.50 | `clean-build` | `not-selected` |
| 4 | 52.37 | 0.64 | `wiki_tool_python` | `pypi` | 0.87 | 11.00 | 9.00 | 13.00 | 3.00 | 8.00 | 6.00 | 1.50 | `clean-build` | `not-selected` |
| 5 | 52.37 | 0.57 | `xberg-hermes-plugin` | `pypi` | 0.87 | 15.00 | 10.00 | 9.00 | 3.00 | 8.00 | 5.00 | 1.50 | `reject` | `blocked` |
| 6 | 46.72 | 0.64 | `web-tool-mcp-server` | `pypi` | 1.22 | 5.00 | 9.00 | 13.00 | 3.00 | 8.00 | 6.00 | 1.50 | `clean-build` | `not-selected` |
| 7 | 44.50 | 0.64 | `hermes-plugin-python` | `pypi` | 2.00 | 2.00 | 9.00 | 13.00 | 3.00 | 8.00 | 6.00 | 1.50 | `clean-build` | `not-selected` |
| 8 | 39.72 | 0.57 | `yaoys-python-tool` | `pypi` | 1.22 | 2.00 | 10.00 | 9.00 | 3.00 | 8.00 | 5.00 | 1.50 | `clean-build` | `blocked` |

## Candidate evidence

### 1. `yantrikdb-hermes-plugin`

- URL: `https://pypi.org/project/yantrikdb-hermes-plugin/`
- Repository: `https://github.com/yantrikos/yantrikdb-hermes-plugin`
- Version: `0.18.3`
- Canonical identity: `pypi:yantrikdb-hermes-plugin@0.18.3`
- License: `MIT`
- Activity: `2026-08-19T21:39:27Z`
- Dependencies: `2`
- Vulnerabilities: `none observed`
- Recommendation: `clean-build`
- Recommendation status: `not-selected`
- Hard blockers: `none`
- Required checks: `authorized sandbox test pass unavailable`
- Inspection: `inspected`
- Clone: `/tmp/brief2ship-preflight-cct-autonomous-8QDCol/worktrees/yantrikdb-hermes-plugin-99e268eabd95`
- Commit: `d9f646e487e5276fe5720b6e2f92c789e9cc1cda`
- Manifests: `pyproject.toml`
- Test files: `125`
- CI files: `2`

Score evidence:

- `feature_match`: `name token coverage=0.09; description token coverage=0.09; topic token coverage=0.13; exact phrase bonus=0; evidence coverage=1.00`
- `maintenance_activity`: `last activity 4 days ago; evidence coverage=1.00`
- `dependency_weight`: `declared dependencies=2; evidence coverage=1.00`
- `security_posture`: `OSV findings=0; permissive license=MIT; security policy absent; evidence coverage=1.00`
- `test_quality`: `test files/signals present; CI workflow present; test command detected; evidence coverage=1.00`
- `portability`: `cross-platform status not disproven; neutral baseline; portable ecosystem=Python; evidence coverage=0.40`
- `reuse_readiness`: `repository link present; description present; license declared; documentation present; package/build manifest present; bounded source footprint; evidence coverage=1.00`
- `adoption_health`: `strongest adoption signal=82; evidence coverage=1.00`

### 2. `web-search-tool`

- URL: `https://pypi.org/project/web-search-tool/`
- Repository: `https://github.com/vladistan/web-search-tool`
- Version: `0.1.2`
- Canonical identity: `pypi:web-search-tool@0.1.2`
- License: `MIT`
- Activity: `2026-07-07T12:37:15Z`
- Dependencies: `11`
- Vulnerabilities: `none observed`
- Recommendation: `clean-build`
- Recommendation status: `not-selected`
- Hard blockers: `none`
- Required checks: `authorized sandbox test pass unavailable`
- Inspection: `inspected`
- Clone: `/tmp/brief2ship-preflight-cct-autonomous-8QDCol/worktrees/web-search-tool-fac41d358cd7`
- Commit: `2ef9e9dd025ae302f12b08b5edc87ca2f62d908b`
- Manifests: `pyproject.toml`
- Test files: `33`
- CI files: `0`

Score evidence:

- `feature_match`: `name token coverage=0.09; description token coverage=0.04; topic token coverage=0.09; exact phrase bonus=0; evidence coverage=1.00`
- `maintenance_activity`: `last activity 47 days ago; evidence coverage=1.00`
- `dependency_weight`: `declared dependencies=11; evidence coverage=1.00`
- `security_posture`: `OSV findings=0; permissive license=MIT; security policy absent; evidence coverage=1.00`
- `test_quality`: `test files/signals present; test command detected; evidence coverage=1.00`
- `portability`: `cross-platform status not disproven; neutral baseline; portable ecosystem=Python; evidence coverage=0.40`
- `reuse_readiness`: `repository link present; description present; license declared; documentation present; package/build manifest present; bounded source footprint; evidence coverage=1.00`
- `adoption_health`: `strongest adoption signal=0; evidence coverage=1.00`

### 3. `yoooclaw-hermes-plugin`

- URL: `https://pypi.org/project/yoooclaw-hermes-plugin/`
- Repository: `unknown`
- Version: `0.8.1`
- Canonical identity: `pypi:yoooclaw-hermes-plugin@0.8.1`
- License: `MIT`
- Activity: `2026-08-21T08:09:17.180960Z`
- Dependencies: `2`
- Vulnerabilities: `none observed`
- Recommendation: `clean-build`
- Recommendation status: `not-selected`
- Hard blockers: `none`
- Required checks: `static repository inspection not completed; authorized sandbox test pass unavailable`
- Inspection: `blocked`
- Clone: `not cloned`
- Commit: `unknown`
- Manifests: `none`
- Test files: `0`
- CI files: `0`

Score evidence:

- `feature_match`: `name token coverage=0.09; description token coverage=0.04; topic token coverage=0.00; exact phrase bonus=0; evidence coverage=0.65`
- `maintenance_activity`: `last activity 2 days ago; evidence coverage=1.00`
- `dependency_weight`: `declared dependencies=2; evidence coverage=1.00`
- `security_posture`: `OSV findings=0; permissive license=MIT; security policy unknown; evidence coverage=0.85`
- `test_quality`: `test evidence unknown; partial neutral score; evidence coverage=0.00`
- `portability`: `cross-platform status not disproven; neutral baseline; portable ecosystem=Python; evidence coverage=0.40`
- `reuse_readiness`: `repository link missing; description present; license declared; evidence coverage=0.00`
- `adoption_health`: `adoption data unknown; partial neutral score; evidence coverage=0.00`

### 4. `wiki_tool_python`

- URL: `https://pypi.org/project/wiki_tool_python/`
- Repository: `https://github.com/ArtUshak/wiki_tool_python`
- Version: `0.3.2`
- Canonical identity: `pypi:wiki_tool_python@0.3.2`
- License: `MIT`
- Activity: `2026-05-23T11:40:51.844101Z`
- Dependencies: `3`
- Vulnerabilities: `none observed`
- Recommendation: `clean-build`
- Recommendation status: `not-selected`
- Hard blockers: `none`
- Required checks: `static repository inspection not completed; authorized sandbox test pass unavailable`

Score evidence:

- `feature_match`: `name token coverage=0.09; description token coverage=0.00; topic token coverage=0.00; exact phrase bonus=0; evidence coverage=0.65`
- `maintenance_activity`: `last activity 92 days ago; evidence coverage=1.00`
- `dependency_weight`: `declared dependencies=3; evidence coverage=1.00`
- `security_posture`: `OSV findings=0; permissive license=MIT; security policy unknown; evidence coverage=0.85`
- `test_quality`: `test evidence unknown; partial neutral score; evidence coverage=0.00`
- `portability`: `cross-platform status not disproven; neutral baseline; portable ecosystem=Python; evidence coverage=0.40`
- `reuse_readiness`: `repository link present; description present; license declared; registry reuse signals=2; evidence coverage=0.60`
- `adoption_health`: `adoption data unknown; partial neutral score; evidence coverage=0.00`

### 5. `xberg-hermes-plugin`

- URL: `https://pypi.org/project/xberg-hermes-plugin/`
- Repository: `https://github.com/xberg-io/xberg`
- Version: `1.0.14`
- Canonical identity: `pypi:xberg-hermes-plugin@1.0.14`
- License: `unknown`
- Activity: `2026-08-05T06:35:08.474045Z`
- Dependencies: `0`
- Vulnerabilities: `none observed`
- Recommendation: `reject`
- Recommendation status: `blocked`
- Hard blockers: `license missing or ambiguous`
- Required checks: `static repository inspection not completed; authorized sandbox test pass unavailable`

Score evidence:

- `feature_match`: `name token coverage=0.09; description token coverage=0.00; topic token coverage=0.00; exact phrase bonus=0; evidence coverage=0.65`
- `maintenance_activity`: `last activity 18 days ago; evidence coverage=1.00`
- `dependency_weight`: `declared dependencies=0; evidence coverage=1.00`
- `security_posture`: `OSV findings=0; license missing; security policy unknown; evidence coverage=0.60`
- `test_quality`: `test evidence unknown; partial neutral score; evidence coverage=0.00`
- `portability`: `cross-platform status not disproven; neutral baseline; portable ecosystem=Python; evidence coverage=0.40`
- `reuse_readiness`: `repository link present; description present; registry reuse signals=2; evidence coverage=0.30`
- `adoption_health`: `adoption data unknown; partial neutral score; evidence coverage=0.00`

### 6. `web-tool-mcp-server`

- URL: `https://pypi.org/project/web-tool-mcp-server/`
- Repository: `https://github.com/linview/sandbox_agent`
- Version: `0.0.2`
- Canonical identity: `pypi:web-tool-mcp-server@0.0.2`
- License: `MIT`
- Activity: `2025-08-19T07:53:09.118994Z`
- Dependencies: `4`
- Vulnerabilities: `none observed`
- Recommendation: `clean-build`
- Recommendation status: `not-selected`
- Hard blockers: `none`
- Required checks: `static repository inspection not completed; authorized sandbox test pass unavailable`

Score evidence:

- `feature_match`: `name token coverage=0.09; description token coverage=0.04; topic token coverage=0.00; exact phrase bonus=0; evidence coverage=0.65`
- `maintenance_activity`: `last activity 369 days ago; evidence coverage=1.00`
- `dependency_weight`: `declared dependencies=4; evidence coverage=1.00`
- `security_posture`: `OSV findings=0; permissive license=MIT; security policy unknown; evidence coverage=0.85`
- `test_quality`: `test evidence unknown; partial neutral score; evidence coverage=0.00`
- `portability`: `cross-platform status not disproven; neutral baseline; portable ecosystem=Python; evidence coverage=0.40`
- `reuse_readiness`: `repository link present; description present; license declared; registry reuse signals=2; evidence coverage=0.60`
- `adoption_health`: `adoption data unknown; partial neutral score; evidence coverage=0.00`

### 7. `hermes-plugin-python`

- URL: `https://pypi.org/project/hermes-plugin-python/`
- Repository: `https://github.com/hermes-hmc/hermes-plugin-python`
- Version: `0.2.0`
- Canonical identity: `pypi:hermes-plugin-python@0.2.0`
- License: `Apache-2.0`
- Activity: `2024-08-02T11:18:42.407517Z`
- Dependencies: `1`
- Vulnerabilities: `none observed`
- Recommendation: `clean-build`
- Recommendation status: `not-selected`
- Hard blockers: `none`
- Required checks: `static repository inspection not completed; authorized sandbox test pass unavailable`

Score evidence:

- `feature_match`: `name token coverage=0.13; description token coverage=0.09; topic token coverage=0.00; exact phrase bonus=0; evidence coverage=0.65`
- `maintenance_activity`: `last activity 751 days ago; evidence coverage=1.00`
- `dependency_weight`: `declared dependencies=1; evidence coverage=1.00`
- `security_posture`: `OSV findings=0; permissive license=Apache-2.0; security policy unknown; evidence coverage=0.85`
- `test_quality`: `test evidence unknown; partial neutral score; evidence coverage=0.00`
- `portability`: `cross-platform status not disproven; neutral baseline; portable ecosystem=Python; evidence coverage=0.40`
- `reuse_readiness`: `repository link present; description present; license declared; registry reuse signals=2; evidence coverage=0.60`
- `adoption_health`: `adoption data unknown; partial neutral score; evidence coverage=0.00`

### 8. `yaoys-python-tool`

- URL: `https://pypi.org/project/yaoys-python-tool/`
- Repository: `https://github.com/yaoysyao/PythonTools`
- Version: `0.0.54`
- Canonical identity: `pypi:yaoys-python-tool@0.0.54`
- License: `unknown`
- Activity: `2023-04-02T05:31:05.341600Z`
- Dependencies: `0`
- Vulnerabilities: `none observed`
- Recommendation: `clean-build`
- Recommendation status: `blocked`
- Hard blockers: `license missing or ambiguous`
- Required checks: `static repository inspection not completed; authorized sandbox test pass unavailable`

Score evidence:

- `feature_match`: `name token coverage=0.09; description token coverage=0.04; topic token coverage=0.00; exact phrase bonus=0; evidence coverage=0.65`
- `maintenance_activity`: `last activity 1239 days ago; evidence coverage=1.00`
- `dependency_weight`: `declared dependencies=0; evidence coverage=1.00`
- `security_posture`: `OSV findings=0; license missing; security policy unknown; evidence coverage=0.60`
- `test_quality`: `test evidence unknown; partial neutral score; evidence coverage=0.00`
- `portability`: `cross-platform status not disproven; neutral baseline; portable ecosystem=Python; evidence coverage=0.40`
- `reuse_readiness`: `repository link present; description present; registry reuse signals=2; evidence coverage=0.30`
- `adoption_health`: `adoption data unknown; partial neutral score; evidence coverage=0.00`

## Source receipts

- `github`: status=`ok`, returned=`0`, rate-limit-remaining=`9`
  - Warning: `unauthenticated GitHub rate limit is low; set GH_TOKEN or GITHUB_TOKEN`
- `pypi`: status=`ok`, returned=`8`, rate-limit-remaining=`None`

## Limitations

- `JavaScript client challenges are not bypassed; PyPI uses its official Simple index`
- `registry popularity is supporting evidence, not proof of implementation quality`
- `repository tests never execute unless both test_top and allow_untrusted_tests are set`
- `scores compare observed public metadata; missing evidence remains explicit`
