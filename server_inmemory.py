import asyncio
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("GFiber-Net-InMemory-Server")

GNETCH_PATH = os.environ.get(
    "GNETCH_PATH", "/usr/local/google/home/mikezh/Coding/gfiber/bin/gnetch.sh"
)
CURRENT_DIR = os.getcwd()
LOG_DIR = os.environ.get("AUDIT_LOG_DIR", os.path.join(CURRENT_DIR, "audit_logs"))
SEMAPHORE_LIMIT = int(os.environ.get("AUDIT_SEMAPHORE_LIMIT", "30"))


@dataclass
class CommandResult:
    command: str
    stdout: str = ""
    stderr: str = ""
    filtered: str = ""
    exit_code: int | None = None
    duration_ms: int | None = None
    started_at: float | None = None
    completed_at: float | None = None
    facts: dict[str, Any] = field(default_factory=dict)
    components: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AuditRun:
    run_id: str
    created_at: float
    hosts: list[str]
    commands: list[str]
    state: str = "running"
    completed_at: float | None = None
    error: str | None = None
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    log_file: str | None = None
    results: dict[str, dict[str, CommandResult]] = field(default_factory=dict)


RUNS: dict[str, AuditRun] = {}


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def _ensure_log_dir() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)


def _parse_devices(devices: str) -> list[str]:
    candidate = os.path.join(CURRENT_DIR, devices)
    if os.path.exists(candidate):
        with open(candidate, "r") as f:
            raw_hosts = f.read().splitlines()
    else:
        raw_hosts = re.split(r"[,\s]+", devices.strip())

    hosts = [re.split(r"[:\s]", item)[0].strip() for item in raw_hosts if item.strip()]
    return sorted(set(hosts))


def _parse_commands(commands: str) -> list[str]:
    parsed = [item.strip() for item in re.split(r"[\n,]+", commands) if item.strip()]
    return parsed


def _filter_output(output: str) -> str:
    markers = ("RE-S", "SCB", "MPC", "FPC", "Chassis", "Model", "Junos:")
    lines = [line for line in output.splitlines() if any(marker in line for marker in markers)]
    return "\n".join(lines).strip()


def _extract_components(command: str, stdout: str, filtered: str) -> list[dict[str, Any]]:
    if "show chassis hardware" not in command.lower():
        return []

    components: list[dict[str, Any]] = []
    text = filtered or stdout

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        columns = [part.strip() for part in re.split(r"\s{2,}", stripped) if part.strip()]
        if not columns:
            continue

        component_type = ""
        slot = columns[0]
        part_number = ""
        serial_number = ""
        description = ""

        if stripped.startswith("Chassis"):
            component_type = "chassis"
            if len(columns) >= 3:
                serial_number = columns[-2]
                description = columns[-1]
            elif len(columns) == 2:
                description = columns[-1]
        elif stripped.startswith("Routing Engine"):
            component_type = "routing_engine"
            if len(columns) >= 4:
                part_number = columns[-3]
                serial_number = columns[-2]
                description = columns[-1]
        elif stripped.startswith("CB "):
            component_type = "control_board"
            if len(columns) >= 5:
                part_number = columns[-3]
                serial_number = columns[-2]
                description = columns[-1]
        elif stripped.startswith("FPC "):
            component_type = "line_card"
            if len(columns) >= 5:
                part_number = columns[-3]
                serial_number = columns[-2]
                description = columns[-1]

        if component_type and description:
            components.append(
                {
                    "component_type": component_type,
                    "slot": slot,
                    "part_number": part_number,
                    "serial_number": serial_number,
                    "description": description,
                }
            )

    return components


def _extract_facts(command: str, stdout: str, filtered: str) -> dict[str, Any]:
    cmd = command.lower()
    text = filtered or stdout
    facts: dict[str, Any] = {}

    if "show chassis hardware" in cmd:
        chassis_models = []
        routing_engines = []
        line_cards = []

        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("Chassis"):
                parts = stripped.split()
                if parts:
                    chassis_models.append(parts[-1])
            elif "Routing Engine" in stripped:
                parts = stripped.split()
                if parts:
                    routing_engines.append(parts[-1])
            elif stripped.startswith("FPC "):
                parts = stripped.split()
                if len(parts) >= 2:
                    line_cards.append(" ".join(parts[5:]) if len(parts) > 5 else stripped)

        if chassis_models:
            facts["chassis_models"] = sorted(set(chassis_models))
        if routing_engines:
            facts["routing_engines"] = sorted(set(routing_engines))
        if line_cards:
            facts["line_cards"] = sorted(set(line_cards))

    if "show version" in cmd:
        match = re.search(r"Junos:\s+([^\s]+)", stdout)
        if match:
            facts["junos_version"] = match.group(1)

    return facts


def _run_to_dict(run: AuditRun) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "state": run.state,
        "created_at": run.created_at,
        "completed_at": run.completed_at,
        "error": run.error,
        "hosts": run.hosts,
        "commands": run.commands,
        "total_tasks": run.total_tasks,
        "completed_tasks": run.completed_tasks,
        "failed_tasks": run.failed_tasks,
        "log_file": run.log_file,
    }


def _command_result_to_dict(result: CommandResult) -> dict[str, Any]:
    return {
        "command": result.command,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "filtered": result.filtered,
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "facts": result.facts,
        "components": result.components,
    }


def _full_run_to_dict(run: AuditRun) -> dict[str, Any]:
    results = {
        hostname: {
            command: _command_result_to_dict(result)
            for command, result in sorted(per_host.items())
        }
        for hostname, per_host in sorted(run.results.items())
    }
    return {
        **_run_to_dict(run),
        "summary": _build_summary(run),
        "results": results,
    }


def _persist_run_snapshot(run: AuditRun) -> None:
    _ensure_log_dir()
    if not run.log_file:
        run.log_file = os.path.join(LOG_DIR, f"audit_run_{run.run_id}.json")

    with open(run.log_file, "w") as f:
        json.dump(_full_run_to_dict(run), f, indent=2, sort_keys=True)


def _load_run_log(run_id: str) -> dict[str, Any] | None:
    log_file = os.path.join(LOG_DIR, f"audit_run_{run_id}.json")
    if not os.path.exists(log_file):
        return None
    with open(log_file, "r") as f:
        return json.load(f)


def _get_run_data(run_id: str) -> dict[str, Any] | None:
    run = RUNS.get(run_id)
    if run:
        return _full_run_to_dict(run)
    return _load_run_log(run_id)


def _match_text(value: str, query: str, match_mode: str) -> bool:
    if match_mode == "exact":
        return value == query
    if match_mode == "prefix":
        return value.startswith(query)
    if match_mode == "contains":
        return query in value
    raise ValueError(f"Unsupported match_mode: {match_mode}")


def _iter_components(
    run_data: dict[str, Any], component_type: str = "", command: str = ""
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for hostname, per_host in run_data.get("results", {}).items():
        for command_name, result in per_host.items():
            if command and command_name != command:
                continue
            for component in result.get("components", []):
                if component_type and component.get("component_type") != component_type:
                    continue
                items.append(
                    {
                        "hostname": hostname,
                        "command": command_name,
                        **component,
                    }
                )
    return items


async def _run_single_command(
    hostname: str, command: str, semaphore: asyncio.Semaphore
) -> tuple[str, str, CommandResult]:
    result = CommandResult(command=command, started_at=time.time())

    async with semaphore:
        start = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                GNETCH_PATH,
                command,
                hostname,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            result.stdout = stdout.decode(errors="replace").strip()
            result.stderr = stderr.decode(errors="replace").strip()
            result.filtered = _filter_output(result.stdout)
            result.exit_code = proc.returncode
            result.duration_ms = int((time.time() - start) * 1000)
            result.completed_at = time.time()
            result.facts = _extract_facts(command, result.stdout, result.filtered)
            result.components = _extract_components(command, result.stdout, result.filtered)
        except Exception as exc:
            result.stderr = str(exc)
            result.exit_code = -1
            result.duration_ms = int((time.time() - start) * 1000)
            result.completed_at = time.time()

    return hostname, command, result


def _build_summary(run: AuditRun) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "run_id": run.run_id,
        "state": run.state,
        "hosts_total": len(run.hosts),
        "commands_total": len(run.commands),
        "tasks_total": run.total_tasks,
        "tasks_completed": run.completed_tasks,
        "tasks_failed": run.failed_tasks,
        "success_hosts": [],
        "failed_hosts": [],
        "command_failures": [],
        "facts": {
            "chassis_models": {},
            "routing_engines": {},
            "junos_versions": {},
            "line_cards": {},
        },
    }

    failed_hosts = set()
    success_hosts = set()

    for hostname, per_host in run.results.items():
        host_failed = False
        host_succeeded = False
        for command, result in per_host.items():
            if result.exit_code == 0:
                host_succeeded = True
            else:
                host_failed = True
                summary["command_failures"].append(
                    {
                        "hostname": hostname,
                        "command": command,
                        "exit_code": result.exit_code,
                        "stderr": result.stderr[:500],
                    }
                )

            for model in result.facts.get("chassis_models", []):
                summary["facts"]["chassis_models"].setdefault(model, []).append(hostname)
            for re_model in result.facts.get("routing_engines", []):
                summary["facts"]["routing_engines"].setdefault(re_model, []).append(hostname)
            junos_version = result.facts.get("junos_version")
            if junos_version:
                summary["facts"]["junos_versions"].setdefault(junos_version, []).append(hostname)
            for card in result.facts.get("line_cards", []):
                summary["facts"]["line_cards"].setdefault(card, []).append(hostname)

        if host_succeeded:
            success_hosts.add(hostname)
        if host_failed:
            failed_hosts.add(hostname)

    summary["success_hosts"] = sorted(success_hosts)
    summary["failed_hosts"] = sorted(failed_hosts)

    for category in summary["facts"].values():
        for key, hosts in list(category.items()):
            category[key] = sorted(set(hosts))

    return summary


async def _execute_run(run_id: str) -> None:
    run = RUNS[run_id]
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)

    try:
        if not os.path.exists(GNETCH_PATH):
            raise FileNotFoundError(f"Script not found at {GNETCH_PATH}")

        tasks = [
            asyncio.create_task(_run_single_command(host, command, semaphore))
            for host in run.hosts
            for command in run.commands
        ]

        for task in asyncio.as_completed(tasks):
            hostname, command, result = await task
            run.results.setdefault(hostname, {})[command] = result
            run.completed_tasks += 1
            if result.exit_code != 0:
                run.failed_tasks += 1
            _persist_run_snapshot(run)

        run.state = "completed"
        run.completed_at = time.time()
        _persist_run_snapshot(run)
    except Exception as exc:
        run.state = "failed"
        run.error = str(exc)
        run.completed_at = time.time()
        _persist_run_snapshot(run)


@mcp.tool()
async def start_audit_run(devices: str, commands: str) -> str:
    """
    Start a server-side audit run.
    - devices: a filename in the current directory or a comma/space-separated host list
    - commands: a comma-separated or newline-separated command list
    """
    hosts = _parse_devices(devices)
    parsed_commands = _parse_commands(commands)

    if not hosts:
        return _json({"error": "No hosts were provided."})
    if not parsed_commands:
        return _json({"error": "No commands were provided."})

    run_id = uuid.uuid4().hex[:12]
    run = AuditRun(
        run_id=run_id,
        created_at=time.time(),
        hosts=hosts,
        commands=parsed_commands,
        total_tasks=len(hosts) * len(parsed_commands),
        log_file=os.path.join(LOG_DIR, f"audit_run_{run_id}.json"),
    )
    RUNS[run_id] = run
    _persist_run_snapshot(run)

    asyncio.create_task(_execute_run(run_id))
    return _json(_run_to_dict(run))


@mcp.tool()
def list_audit_runs() -> str:
    """List all audit runs stored in server memory."""
    runs = [_run_to_dict(run) for run in sorted(RUNS.values(), key=lambda item: item.created_at, reverse=True)]
    return _json({"runs": runs})


@mcp.tool()
def get_audit_run_status(run_id: str) -> str:
    """Return status metadata for a run."""
    run = RUNS.get(run_id)
    if not run:
        return _json({"error": f"Unknown run_id: {run_id}"})
    return _json(_run_to_dict(run))


@mcp.tool()
def get_audit_run_summary(run_id: str) -> str:
    """Return a compact summary for a run."""
    run = RUNS.get(run_id)
    if not run:
        return _json({"error": f"Unknown run_id: {run_id}"})
    return _json(_build_summary(run))


@mcp.tool()
def get_audit_run_log_path(run_id: str) -> str:
    """Return the log file path for a run."""
    run = RUNS.get(run_id)
    if run:
        return _json({"run_id": run_id, "log_file": run.log_file})

    logged = _load_run_log(run_id)
    if logged:
        return _json({"run_id": run_id, "log_file": logged.get("log_file")})

    return _json({"error": f"Unknown run_id: {run_id}"})


@mcp.tool()
def get_audit_host_details(run_id: str, hostname: str, include_raw: bool = False) -> str:
    """Return all command results for a single host."""
    run = RUNS.get(run_id)
    if not run:
        return _json({"error": f"Unknown run_id: {run_id}"})

    host_results = run.results.get(hostname)
    if not host_results:
        return _json({"error": f"No results for host: {hostname}"})

    payload = {"run_id": run_id, "hostname": hostname, "commands": {}}
    for command, result in host_results.items():
        payload["commands"][command] = {
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "stderr": result.stderr,
            "facts": result.facts,
            "output": result.stdout if include_raw else (result.filtered or result.stdout),
        }
    return _json(payload)


@mcp.tool()
def get_audit_command_details(
    run_id: str, hostname: str, command: str, include_raw: bool = False
) -> str:
    """Return a single host/command result."""
    run = RUNS.get(run_id)
    if not run:
        return _json({"error": f"Unknown run_id: {run_id}"})

    host_results = run.results.get(hostname, {})
    result = host_results.get(command)
    if not result:
        return _json({"error": f"No result for host={hostname} command={command}"})

    payload = {
        "run_id": run_id,
        "hostname": hostname,
        "command": command,
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "stderr": result.stderr,
        "facts": result.facts,
        "output": result.stdout if include_raw else (result.filtered or result.stdout),
    }
    return _json(payload)


@mcp.tool()
def search_audit_results(run_id: str, pattern: str, command: str = "") -> str:
    """Search result text across the run and return matching host/command pairs."""
    run = RUNS.get(run_id)
    if not run:
        return _json({"error": f"Unknown run_id: {run_id}"})

    needle = pattern.lower()
    matches = []
    for hostname, per_host in run.results.items():
        for cmd, result in per_host.items():
            if command and cmd != command:
                continue
            haystack = "\n".join([result.filtered, result.stdout, result.stderr]).lower()
            if needle in haystack:
                matches.append(
                    {
                        "hostname": hostname,
                        "command": cmd,
                        "exit_code": result.exit_code,
                        "facts": result.facts,
                    }
                )

    return _json({"run_id": run_id, "pattern": pattern, "matches": matches})


@mcp.tool()
def count_components(
    run_id: str,
    name: str,
    component_type: str = "",
    match_mode: str = "exact",
    command: str = "",
) -> str:
    """
    Count components by name.
    match_mode must be one of: exact, prefix, contains
    component_type examples: control_board, routing_engine, line_card, chassis
    """
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})

    try:
        components = [
            item
            for item in _iter_components(run_data, component_type=component_type, command=command)
            if _match_text(item["description"], name, match_mode)
        ]
    except ValueError as exc:
        return _json({"error": str(exc)})

    per_host: dict[str, int] = {}
    for item in components:
        per_host[item["hostname"]] = per_host.get(item["hostname"], 0) + 1

    return _json(
        {
            "run_id": run_id,
            "name": name,
            "match_mode": match_mode,
            "component_type": component_type,
            "command": command,
            "total_count": len(components),
            "host_count": len(per_host),
            "per_host": dict(sorted(per_host.items())),
        }
    )


@mcp.tool()
def list_components(
    run_id: str,
    name: str = "",
    component_type: str = "",
    match_mode: str = "exact",
    command: str = "",
) -> str:
    """
    List structured components.
    If name is provided, it is matched using match_mode.
    """
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})

    try:
        components = _iter_components(run_data, component_type=component_type, command=command)
        if name:
            components = [
                item for item in components if _match_text(item["description"], name, match_mode)
            ]
    except ValueError as exc:
        return _json({"error": str(exc)})

    return _json(
        {
            "run_id": run_id,
            "name": name,
            "match_mode": match_mode,
            "component_type": component_type,
            "command": command,
            "components": components,
        }
    )


@mcp.tool()
def list_audit_log_runs() -> str:
    """List persisted audit run logs from disk."""
    _ensure_log_dir()
    runs = []
    for name in sorted(os.listdir(LOG_DIR), reverse=True):
        if not name.startswith("audit_run_") or not name.endswith(".json"):
            continue
        path = os.path.join(LOG_DIR, name)
        try:
            with open(path, "r") as f:
                data = json.load(f)
            runs.append(
                {
                    "run_id": data.get("run_id"),
                    "state": data.get("state"),
                    "created_at": data.get("created_at"),
                    "completed_at": data.get("completed_at"),
                    "hosts": data.get("hosts", []),
                    "commands": data.get("commands", []),
                    "log_file": path,
                }
            )
        except Exception as exc:
            runs.append({"log_file": path, "error": str(exc)})
    return _json({"runs": runs})


@mcp.tool()
def get_audit_log_summary(run_id: str) -> str:
    """Return the persisted summary for a prior run."""
    data = _load_run_log(run_id)
    if not data:
        return _json({"error": f"Unknown run_id: {run_id}"})
    return _json(data.get("summary", {}))


@mcp.tool()
def get_audit_log_host_details(run_id: str, hostname: str, include_raw: bool = False) -> str:
    """Return host details from a persisted log."""
    data = _load_run_log(run_id)
    if not data:
        return _json({"error": f"Unknown run_id: {run_id}"})

    host_results = data.get("results", {}).get(hostname)
    if not host_results:
        return _json({"error": f"No results for host: {hostname}"})

    payload = {"run_id": run_id, "hostname": hostname, "commands": {}}
    for command, result in sorted(host_results.items()):
        payload["commands"][command] = {
            "exit_code": result.get("exit_code"),
            "duration_ms": result.get("duration_ms"),
            "stderr": result.get("stderr", ""),
            "facts": result.get("facts", {}),
            "output": result.get("stdout", "") if include_raw else (result.get("filtered") or result.get("stdout", "")),
        }
    return _json(payload)


if __name__ == "__main__":
    mcp.run()
