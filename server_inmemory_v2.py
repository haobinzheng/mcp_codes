import asyncio
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("GFiber-Net-InMemory-Server-v2")

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


def _parse_ping_stats(output: str) -> dict[str, Any]:
    transmitted = None
    received = None
    packet_loss = None
    latencies_ms: list[float] = []
    average_latency_ms = None

    packet_match = re.search(
        r"(\d+)\s+packets transmitted,\s+(\d+)(?:\s+packets?)?\s+received.*?(\d+(?:\.\d+)?)%\s+packet loss",
        output,
        flags=re.IGNORECASE,
    )
    if packet_match:
        transmitted = int(packet_match.group(1))
        received = int(packet_match.group(2))
        packet_loss = float(packet_match.group(3))

    for match in re.finditer(r"time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms", output, flags=re.IGNORECASE):
        latencies_ms.append(float(match.group(1)))

    rtt_match = re.search(
        r"(?:round-trip|rtt).*?=\s*([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)(?:/([0-9]+(?:\.[0-9]+)?))?\s*ms",
        output,
        flags=re.IGNORECASE,
    )
    if rtt_match:
        average_latency_ms = float(rtt_match.group(2))
    elif latencies_ms:
        average_latency_ms = round(sum(latencies_ms) / len(latencies_ms), 3)

    return {
        "packets_transmitted": transmitted,
        "packets_received": received,
        "packet_loss_percent": packet_loss,
        "latencies_ms": latencies_ms,
        "average_latency_ms": average_latency_ms,
    }


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
    structured_data_available = bool(result.facts or result.components)
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
        "structured_data_available": structured_data_available,
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


def _parse_host_filter(hosts: str) -> set[str]:
    if not hosts.strip():
        return set()
    return {item.strip() for item in re.split(r"[,\s]+", hosts) if item.strip()}


def _iter_results(
    run_data: dict[str, Any], command: str = "", hosts: set[str] | None = None
) -> list[tuple[str, str, dict[str, Any]]]:
    items: list[tuple[str, str, dict[str, Any]]] = []
    for hostname, per_host in sorted(run_data.get("results", {}).items()):
        if hosts and hostname not in hosts:
            continue
        for command_name, result in sorted(per_host.items()):
            if command and command_name != command:
                continue
            items.append((hostname, command_name, result))
    return items


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


def _list_run_commands(run_data: dict[str, Any]) -> list[str]:
    commands = set()
    for _, per_host in run_data.get("results", {}).items():
        commands.update(per_host.keys())
    if commands:
        return sorted(commands)
    return sorted(run_data.get("commands", []))


def _normalize_question_terms(question: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9][a-z0-9._/-]*", question.lower())
    stop_words = {
        "a",
        "an",
        "and",
        "are",
        "audit",
        "based",
        "be",
        "by",
        "command",
        "count",
        "device",
        "devices",
        "does",
        "each",
        "for",
        "from",
        "how",
        "i",
        "if",
        "in",
        "is",
        "it",
        "me",
        "of",
        "on",
        "or",
        "out",
        "print",
        "show",
        "tell",
        "that",
        "the",
        "these",
        "this",
        "to",
        "total",
        "use",
        "using",
        "what",
        "which",
        "with",
    }
    return [token for token in tokens if token not in stop_words and len(token) > 1]


def _score_raw_result(hostname: str, command_name: str, result: dict[str, Any], question: str) -> int:
    score = 0
    lowered_question = question.lower()
    lowered_command = command_name.lower()
    lowered_host = hostname.lower()
    haystack = "\n".join(
        [
            result.get("filtered", ""),
            result.get("stdout", ""),
            result.get("stderr", ""),
        ]
    ).lower()

    if lowered_command and lowered_command in lowered_question:
        score += 10
    if lowered_host and lowered_host in lowered_question:
        score += 8

    for term in _normalize_question_terms(question):
        hits = haystack.count(term)
        if hits:
            score += min(hits, 5)
        if term in lowered_command:
            score += 3
        if term in lowered_host:
            score += 2

    if result.get("exit_code") not in (None, 0):
        score += 1

    return score


def _excerpt_text(text: str, question: str, max_chars: int) -> str:
    text = text.strip()
    if len(text) <= max_chars:
        return text

    terms = _normalize_question_terms(question)
    lines = text.splitlines()
    for index, line in enumerate(lines):
        lowered_line = line.lower()
        if any(term in lowered_line for term in terms):
            start = max(0, index - 3)
            end = min(len(lines), index + 4)
            excerpt = "\n".join(lines[start:end]).strip()
            if len(excerpt) <= max_chars:
                return excerpt
            return excerpt[: max_chars - 15].rstrip() + "\n...[truncated]"

    return text[: max_chars - 15].rstrip() + "\n...[truncated]"


def _build_best_context_for_result(
    hostname: str,
    command_name: str,
    result: dict[str, Any],
    include_raw_when_structured: bool,
) -> dict[str, Any]:
    structured_data_available = bool(result.get("structured_data_available"))
    if structured_data_available:
        payload = {
            "mode": "structured",
            "hostname": hostname,
            "command": command_name,
            "structured_data_available": True,
            "facts": result.get("facts", {}),
            "components": result.get("components", []),
            "stderr": result.get("stderr", ""),
            "exit_code": result.get("exit_code"),
        }
        if include_raw_when_structured:
            payload["raw_output"] = result.get("stdout", "")
        return payload

    return {
        "mode": "raw",
        "hostname": hostname,
        "command": command_name,
        "structured_data_available": False,
        "raw_output": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
        "exit_code": result.get("exit_code"),
    }


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
async def ping_from_device(
    source_hostname: str,
    target_hostname: str,
    count: int = 4,
    timeout_sec: int = 2,
) -> str:
    """
    Execute ping from one device to another via gnetch and return raw output plus parsed latency stats.
    - source_hostname: device where the ping command should run
    - target_hostname: destination to ping from the source device
    - count: number of echo requests to send
    - timeout_sec: per-packet timeout in seconds
    """
    safe_count = max(1, min(count, 20))
    safe_timeout = max(1, min(timeout_sec, 10))
    command = f"ping {target_hostname}"

    start = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            GNETCH_PATH,
            command,
            source_hostname,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        raw_output = stdout.decode(errors="replace").strip()
        stderr_text = stderr.decode(errors="replace").strip()
        stats = _parse_ping_stats(raw_output)
        return _json(
            {
                "source_hostname": source_hostname,
                "target_hostname": target_hostname,
                "count": safe_count,
                "timeout_sec": safe_timeout,
                "exit_code": proc.returncode,
                "duration_ms": int((time.time() - start) * 1000),
                "raw_output": raw_output,
                "stderr": stderr_text,
                **stats,
            }
        )
    except Exception as exc:
        return _json(
            {
                "source_hostname": source_hostname,
                "target_hostname": target_hostname,
                "count": safe_count,
                "timeout_sec": safe_timeout,
                "exit_code": -1,
                "duration_ms": int((time.time() - start) * 1000),
                "raw_output": "",
                "stderr": str(exc),
                "packets_transmitted": None,
                "packets_received": None,
                "packet_loss_percent": None,
                "latencies_ms": [],
                "average_latency_ms": None,
            }
        )


@mcp.tool()
async def ping_device(hostname: str, count: int = 4, timeout_sec: int = 2) -> str:
    """
    Compatibility wrapper for older prompt/tool behavior.
    This tool now requires the user to specify a source device explicitly.
    """
    return _json(
        {
            "error": (
                "A ping source device is required. Use ping_from_device with both source_hostname and "
                "target_hostname. Do not assume ping runs from the local server."
            ),
            "hostname": hostname,
            "count": max(1, min(count, 20)),
            "timeout_sec": max(1, min(timeout_sec, 10)),
        }
    )


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
def get_analysis_context(
    run_id: str,
    hostname: str = "",
    command: str = "",
    include_raw_when_structured: bool = False,
) -> str:
    """
    Return the best available analysis context.
    - If structured data exists for the matching result set, return structured context.
    - Otherwise return raw command output.
    """
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})

    results = run_data.get("results", {})
    items = []
    for host_name, per_host in results.items():
        if hostname and host_name != hostname:
            continue
        for command_name, result in per_host.items():
            if command and command_name != command:
                continue
            items.append(
                _build_best_context_for_result(
                    host_name,
                    command_name,
                    result,
                    include_raw_when_structured,
                )
            )

    if not items:
        return _json(
            {
                "error": "No matching analysis context found.",
                "run_id": run_id,
                "hostname": hostname,
                "command": command,
            }
        )

    return _json(
        {
            "run_id": run_id,
            "hostname": hostname,
            "command": command,
            "items": items,
        }
    )


@mcp.tool()
def list_run_commands(run_id: str) -> str:
    """List the commands captured for a run."""
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})
    return _json({"run_id": run_id, "commands": _list_run_commands(run_data)})


@mcp.tool()
def get_raw_command_outputs(
    run_id: str,
    command: str,
    hosts: str = "",
    max_chars_per_output: int = 4_000_000,
    max_results: int = 20,
) -> str:
    """Return raw outputs for a command across matching hosts."""
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})

    host_filter = _parse_host_filter(hosts)
    items = []
    truncated = False
    for hostname, command_name, result in _iter_results(run_data, command=command, hosts=host_filter):
        raw_output = (result.get("stdout") or "").strip()
        if len(items) >= max_results:
            truncated = True
            break
        excerpt = raw_output[:max_chars_per_output]
        if len(raw_output) > max_chars_per_output:
            excerpt = excerpt.rstrip() + "\n...[truncated]"
            truncated = True
        items.append(
            {
                "hostname": hostname,
                "command": command_name,
                "exit_code": result.get("exit_code"),
                "stderr": result.get("stderr", ""),
                "raw_output": excerpt,
                "raw_output_complete": len(raw_output) <= max_chars_per_output,
            }
        )

    if not items:
        return _json(
            {
                "error": "No matching raw command outputs found.",
                "run_id": run_id,
                "command": command,
                "hosts": sorted(host_filter),
            }
        )

    return _json(
        {
            "run_id": run_id,
            "command": command,
            "hosts": sorted(host_filter),
            "max_chars_per_output": max_chars_per_output,
            "max_results": max_results,
            "truncated": truncated,
            "items": items,
        }
    )


@mcp.tool()
def search_raw_command_outputs(
    run_id: str,
    command: str,
    query: str,
    hosts: str = "",
    max_matches: int = 20,
    excerpt_chars: int = 1200,
) -> str:
    """Search raw outputs for a command and return matching excerpts."""
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})

    host_filter = _parse_host_filter(hosts)
    terms = _normalize_question_terms(query)
    if not terms:
        terms = [query.lower()]

    matches = []
    truncated = False
    for hostname, command_name, result in _iter_results(run_data, command=command, hosts=host_filter):
        raw_output = result.get("stdout", "")
        lowered = raw_output.lower()
        if not any(term in lowered for term in terms):
            continue
        if len(matches) >= max_matches:
            truncated = True
            break
        matches.append(
            {
                "hostname": hostname,
                "command": command_name,
                "exit_code": result.get("exit_code"),
                "stderr": result.get("stderr", ""),
                "excerpt": _excerpt_text(raw_output, query, excerpt_chars),
            }
        )

    return _json(
        {
            "run_id": run_id,
            "command": command,
            "query": query,
            "hosts": sorted(host_filter),
            "max_matches": max_matches,
            "truncated": truncated,
            "matches": matches,
        }
    )


@mcp.tool()
def get_raw_analysis_context(
    run_id: str,
    question: str,
    command: str = "",
    hosts: str = "",
    max_hosts: int = 8,
    max_chars_per_host: int = 2500,
) -> str:
    """
    Return the most relevant raw evidence for a question.
    This is intended for commands without structured parsers.
    """
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})

    host_filter = _parse_host_filter(hosts)
    commands = _list_run_commands(run_data)
    chosen_command = command
    if not chosen_command:
        if len(commands) == 1:
            chosen_command = commands[0]
        else:
            lowered_question = question.lower()
            for command_name in commands:
                if command_name.lower() in lowered_question:
                    chosen_command = command_name
                    break

    candidates = []
    for hostname, command_name, result in _iter_results(run_data, command=chosen_command, hosts=host_filter):
        if result.get("structured_data_available"):
            continue
        score = _score_raw_result(hostname, command_name, result, question)
        candidates.append((score, hostname, command_name, result))

    if not candidates and chosen_command:
        for hostname, command_name, result in _iter_results(run_data, command=chosen_command, hosts=host_filter):
            score = _score_raw_result(hostname, command_name, result, question)
            candidates.append((score, hostname, command_name, result))

    if not candidates:
        return _json(
            {
                "error": "No raw analysis context found.",
                "run_id": run_id,
                "question": question,
                "command": chosen_command,
                "available_commands": commands,
            }
        )

    candidates.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    selected = candidates[:max_hosts]
    items = []
    truncated = len(candidates) > max_hosts
    for score, hostname, command_name, result in selected:
        raw_output = result.get("stdout", "")
        excerpt = _excerpt_text(raw_output, question, max_chars_per_host)
        if len(raw_output) > len(excerpt):
            truncated = True
        items.append(
            {
                "hostname": hostname,
                "command": command_name,
                "score": score,
                "exit_code": result.get("exit_code"),
                "stderr": result.get("stderr", ""),
                "raw_excerpt": excerpt,
            }
        )

    return _json(
        {
            "run_id": run_id,
            "question": question,
            "command": chosen_command,
            "available_commands": commands,
            "hosts": sorted(host_filter),
            "max_hosts": max_hosts,
            "max_chars_per_host": max_chars_per_host,
            "truncated": truncated,
            "items": items,
        }
    )


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
def summarize_components(run_id: str, command: str = "") -> str:
    """Summarize all structured components by type and exact description."""
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})

    summary: dict[str, dict[str, int]] = {}
    for item in _iter_components(run_data, command=command):
        component_type = item["component_type"]
        description = item["description"]
        summary.setdefault(component_type, {})
        summary[component_type][description] = summary[component_type].get(description, 0) + 1

    return _json(
        {
            "run_id": run_id,
            "command": command,
            "summary": {
                component_type: dict(sorted(descriptions.items()))
                for component_type, descriptions in sorted(summary.items())
            },
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
