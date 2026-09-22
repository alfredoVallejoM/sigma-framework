#!/usr/bin/env bash
set -euo pipefail
umask 0022

repo=/home/alfred/Documentos/Proyectos/python/sigma/sigma-framework
workspace=/home/alfred/Documentos/Proyectos/python/sigma/sigma-framework-r15-local-data
python_bin=/home/alfred/miniforge3/bin/python
jq_bin=/usr/bin/jq
state="$workspace/r15-supervisor.state"
log="$workspace/r15-supervisor.log"

exec >> "$log" 2>&1
cd "$repo"

record() {
  printf '%s %s\n' "$(date --iso-8601=seconds)" "$*"
  printf '%s\n' "$*" > "$state"
}

trap 'record "supervisor-signal=TERM"; exit 143' TERM HUP
trap 'record "supervisor-signal=INT"; exit 130' INT
trap 'rc=$?; record "supervisor-exit=$rc"; exit "$rc"' EXIT

record "amendment-resume-start workers=4"
"$python_bin" -m scripts.run_r15_local run --workspace "$workspace" --campaign amendment --workers 4
current=$("$python_bin" -m scripts.r15_local_plan status --workspace "$workspace" | "$jq_bin" -r '.campaigns.amendment.complete_shards')
record "amendment=$current/384"
[[ "$current" == 384 ]]

record "amendment-audit-start"
"$python_bin" -m scripts.run_r15_local audit --workspace "$workspace" --campaign amendment
"$jq_bin" -e '.passed == true' "$workspace/datasets/amendment/amendment-summary.json"
record "amendment-audit-pass"

record "stat-start workers=1"
"$python_bin" -m scripts.run_r15_local run --workspace "$workspace" --campaign stat --workers 1
"$python_bin" -m scripts.run_r15_local audit --workspace "$workspace" --campaign stat
"$jq_bin" -e '.passed == true' "$workspace/datasets/stat/stat-summary.json"
record "stat-audit-pass"

record "engineering-start workers=4"
"$python_bin" -m scripts.run_r15_local run --workspace "$workspace" --campaign engineering --workers 4
"$python_bin" -m scripts.run_r15_local audit --workspace "$workspace" --campaign engineering
"$jq_bin" -e '.passed == true' "$workspace/datasets/engineering/engineering-summary.json"
record "engineering-audit-pass"

record "final-start"
"$python_bin" -m scripts.run_r15_local final --workspace "$workspace"
"$jq_bin" -e '.passed == true' "$workspace/datasets/final/r15-final-summary.json"
record "final-candidate-ready"
