#!/usr/bin/env bash
# Shared logging helpers for start_ai_tool_adk and start_ai_tool_adk_tunnel.
# Source this file after SCRIPT_DIR is set to the repository root:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   # shellcheck source=start_ai_tool_logging.sh
#   source "${SCRIPT_DIR}/start_ai_tool_logging.sh"

start_ai_tool_log_ts() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

start_ai_tool_logging_enabled() {
  [[ "${START_AI_TOOL_LOG_DISABLE:-0}" != "1" ]] && [[ "${START_AI_TOOL_LOG_DISABLE:-}" != "true" ]]
}

# Append a session header block to LOG_FILE (does not touch stdout).
# Usage: start_ai_tool_log_begin LOG_FILE SCRIPT_NAME [lines...]
start_ai_tool_log_begin() {
  local log_file="$1"
  local script_name="$2"
  shift 2
  mkdir -p "$(dirname "${log_file}")"
  {
    echo "==== $(start_ai_tool_log_ts) ${script_name} pid=$$ ===="
    local line
    for line in "$@"; do
      echo "${line}"
    done
    echo ""
  } >> "${log_file}"
}

# Tee stdout and stderr through LOG_FILE for the remainder of the shell (use before exec).
start_ai_tool_log_tee() {
  local log_file="$1"
  mkdir -p "$(dirname "${log_file}")"
  exec > >(tee -a "${log_file}") 2>&1
}
