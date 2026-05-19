#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== Forbidden/demo markers =="
rg -n '\.unwrap\(|\.expect\(|panic!\(|todo!\(|unimplemented!\(' crates src tests xtask fuzz 2>/dev/null || true

echo
echo "== Overbroad security names =="
rg -n 'SecurityOrchestrator|SandboxManager|IsolationEngine|PolicyEngine|RuntimeController|Universal|Manager' crates src tests xtask docs README.md 2>/dev/null || true

echo
echo "== Raw string usage near authority concepts =="
rg -n 'String|Vec<String>|HashMap<String' crates/cocoon-core crates/cocoon-runtime crates/cocoon-policy 2>/dev/null || true

echo
echo "== String matching in permission/path/security logic =="
rg -n 'contains\(|starts_with\(|ends_with\(|split\(|replace\(' crates/cocoon-core crates/cocoon-bundle crates/cocoon-policy crates/cocoon-runtime 2>/dev/null || true

echo
echo "== Claims of sandbox/isolation/enforcement =="
rg -n 'sandbox|isolation|enforce|enforcement|secure|security boundary' crates docs README.md 2>/dev/null || true

echo
echo "== Redox cfg boundaries =="
rg -n 'target_os = "redox"|cfg\(redox|Command::new|spawn\(' crates/cocoon-runtime crates xtask 2>/dev/null || true

echo
echo "== Security invariant test keywords =="
rg -n 'absolute|parent|duplicate|missing|extra|hash|manifest|executable|entrypoint|traversal|permission expansion|scheme visibility|preopen|network default' crates tests xtask fuzz 2>/dev/null || true
