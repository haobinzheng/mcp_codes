import asyncio
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
import importlib.util

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("GFiber-Net-InMemory-Server-v2")

GNETCH_PATH = os.environ.get(
    "GNETCH_PATH", "/usr/local/google/home/mikezh/Coding/gfiber/bin/gnetch.sh"
)
CURRENT_DIR = os.getcwd()
LOG_DIR = os.environ.get("AUDIT_LOG_DIR", os.path.join(CURRENT_DIR, "audit_logs"))
SEMAPHORE_LIMIT = int(os.environ.get("AUDIT_SEMAPHORE_LIMIT", "30"))
BNG_BASE_DIR = os.path.join(CURRENT_DIR, "bng")
BNG_ORIGINAL_DIR = os.path.join(BNG_BASE_DIR, "configurations", "original")
BNG_FLAT_DIR = os.path.join(BNG_BASE_DIR, "configurations", "flat")
SROS_ROOTIFIER_PATH = os.path.join(BNG_BASE_DIR, "tools", "sros_rootifier.py")
FLAT_SROS_PATH = os.path.join(BNG_BASE_DIR, "tools", "flat_sros.py")

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
_RANCID_DEFAULT_SAMPLE_HOSTS = (
    "cr01.atl103",
    "dr01.cbf101",
    "mgt01.atl103",
    "sag01.cbf101",
    "mar01.atl103",
    "pr01.atl101",
    "agg01.atl103",
    "rr01.slc101",
    "fw-vip.cbf101",
    "fw01.cbf101",
    "msr01.den103",
    "mpr01.mci103",
    "sar01.bna103",
    "ssw02.atl103",
    "sag91.atl151",
    "sag81.atl151",
    "cr02.mci102",
    "dr02.slc101",
    "mgt02.aus121",
    "sag92.lax103",
    "mar02.hsv107",
    "pr02.ord101",
    "agg02.bna103",
    "rr01.cbf101",
    "mgt01.cbf101",
    "cr01.aus122",
    "dr01.atl103",
    "mgt03.sat103",
    "sag01.atl103",
    "fw-vip.slc103",
    "dr02.rdu103",
)
_RANCID_NON_HOST_BASENAMES_LOWER = frozenset(
    {
        "router.db",
        "cvs",
        "cvswrappers",
        ".gitignore",
        "readme",
        "changelog",
        "makefile",
    }
)


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


def _ensure_bng_dirs() -> None:
    os.makedirs(BNG_ORIGINAL_DIR, exist_ok=True)
    os.makedirs(BNG_FLAT_DIR, exist_ok=True)


def _load_flat_sros_module():
    spec = importlib.util.spec_from_file_location("flat_sros_tool", FLAT_SROS_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load flat_sros module from {FLAT_SROS_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def _filter_output(output: str, command: str = "") -> str:
    """Keep hardware-relevant lines; PTX/JNP10K output uses PSM/SIB/FTC/etc., not only MX-style markers."""
    cmd = command.lower()
    if "show chassis hardware" in cmd:
        markers = (
            "Chassis",
            "Model",
            "Junos:",
            "RE-S",
            "SCB",
            "MPC",
            "FPC",
            "Routing Engine",
            "CB ",
            "PSM",
            "PDM",
            "SIB",
            "FTC",
            "Fan Tray",
            "Midplane",
            "FPM ",
            "MEZZ",
            "PIC ",
            "Xcvr",
        )
    else:
        markers = ("RE-S", "SCB", "MPC", "FPC", "Chassis", "Model", "Junos:")
    lines = [line for line in output.splitlines() if any(marker in line for marker in markers)]
    return "\n".join(lines).strip()


def _hw_table_tail(columns: list[str]) -> tuple[str, str, str]:
    """Part number, serial, description from a typical ``show chassis hardware`` row."""
    if len(columns) >= 5:
        return columns[-3], columns[-2], columns[-1]
    if len(columns) == 4:
        return "", columns[-2], columns[-1]
    if len(columns) >= 2:
        return "", "", columns[-1]
    return "", "", ""


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
                part_number, serial_number, description = _hw_table_tail(columns)
        elif stripped.startswith("CB "):
            component_type = "control_board"
            if len(columns) >= 5:
                part_number = columns[-3]
                serial_number = columns[-2]
                description = columns[-1]
            elif len(columns) >= 4:
                part_number, serial_number, description = _hw_table_tail(columns)
        elif stripped.startswith("FPC "):
            component_type = "line_card"
            if len(columns) >= 5:
                part_number = columns[-3]
                serial_number = columns[-2]
                description = columns[-1]
            elif len(columns) >= 4:
                part_number, serial_number, description = _hw_table_tail(columns)
        elif re.match(r"^PSM\s+\d+", stripped):
            component_type = "power_supply"
            if len(columns) >= 4:
                part_number, serial_number, description = _hw_table_tail(columns)
        elif re.match(r"^SIB\s+\d+", stripped):
            component_type = "fabric"
            if len(columns) >= 4:
                part_number, serial_number, description = _hw_table_tail(columns)
        elif re.match(r"^FTC\s+\d+", stripped):
            component_type = "fan_controller"
            if len(columns) >= 4:
                part_number, serial_number, description = _hw_table_tail(columns)
        elif re.match(r"^Fan Tray\s+\d+", stripped):
            component_type = "fan_tray"
            if len(columns) >= 4:
                part_number, serial_number, description = _hw_table_tail(columns)
        elif stripped.startswith("Midplane"):
            component_type = "midplane"
            if len(columns) >= 4:
                part_number, serial_number, description = _hw_table_tail(columns)
        elif re.match(r"^FPM\s+\d+", stripped) or stripped.startswith("FPM "):
            component_type = "front_panel"
            if len(columns) >= 4:
                part_number, serial_number, description = _hw_table_tail(columns)
        elif re.match(r"^MEZZ\s+\d+", stripped):
            component_type = "mezzanine"
            if len(columns) >= 4:
                part_number, serial_number, description = _hw_table_tail(columns)

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
        fabric_modules: list[str] = []
        power_modules: list[str] = []

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
            elif re.match(r"^SIB\s+\d+", stripped):
                cols = [p.strip() for p in re.split(r"\s{2,}", stripped) if p.strip()]
                if cols:
                    fabric_modules.append(cols[-1])
            elif re.match(r"^PSM\s+\d+", stripped):
                cols = [p.strip() for p in re.split(r"\s{2,}", stripped) if p.strip()]
                if cols:
                    power_modules.append(cols[-1])

        if chassis_models:
            facts["chassis_models"] = sorted(set(chassis_models))
        if routing_engines:
            facts["routing_engines"] = sorted(set(routing_engines))
        if line_cards:
            facts["line_cards"] = sorted(set(line_cards))
        if fabric_modules:
            facts["fabric_modules"] = sorted(set(fabric_modules))
        if power_modules:
            facts["power_modules"] = sorted(set(power_modules))

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


def _parse_rancid_folders_file() -> dict[str, str]:
    """Parse repo rancid_folders mapping: flexible ``key: path`` lines."""
    path = os.environ.get("RANCID_FOLDERS_FILE", os.path.join(_REPO_ROOT, "rancid_folders"))
    mapping: dict[str, str] = {}
    if not os.path.isfile(path):
        return mapping
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key and value:
                mapping[key] = value
    return mapping


def _rancid_allowed_depot_realpaths(mapping: dict[str, str]) -> set[str]:
    roots: set[str] = set()
    for configured in mapping.values():
        try:
            roots.add(os.path.realpath(configured))
        except OSError:
            continue
    return roots


def _rancid_resolve_family_key(mapping: dict[str, str], device_family: str) -> str | None:
    if not device_family.strip():
        return None
    raw = device_family.strip()
    if raw in mapping:
        return raw
    lowered = raw.lower()
    for key in mapping:
        if key.lower() == lowered:
            return key
    return None


def _rancid_hostname_from_entry(name: str) -> str:
    base = os.path.basename(name.strip())
    if base.endswith(",v"):
        base = base[:-2]
    return base


def _rancid_stem_from_hostname(hostname: str) -> str:
    host = hostname.strip()
    if not host:
        return ""
    dot = host.find(".")
    if dot == -1:
        return host
    return host[:dot]


def _rancid_function_code_from_hostname(hostname: str) -> str:
    """Short function-style code from hostname (stem letters/hyphens before trailing digits).

    Used only to *discover* category labels present in inventory (e.g. ``dr``, ``cr``, ``mar``).
    Does not attach human descriptions (core router, etc.); those stay in ops/docs.
    """
    stem = _rancid_stem_from_hostname(hostname)
    if not stem:
        return "unknown"
    match = re.match(r"^([A-Za-z][A-Za-z-]*?)(\d+)$", stem)
    if match:
        return match.group(1).lower()
    return stem.lower()


def _rancid_is_probable_host_file(filename: str) -> bool:
    base = os.path.basename(filename)
    if not base or base.startswith("."):
        return False
    lower = base.lower()
    if lower in _RANCID_NON_HOST_BASENAMES_LOWER:
        return False
    if lower.endswith((".md", ".html", ".pdf")):
        return False
    if os.path.isdir(filename):
        return False
    return True


def _rancid_list_depot_hostnames(depot_dir: str) -> list[str]:
    names: list[str] = []
    try:
        for entry in sorted(os.listdir(depot_dir)):
            path = os.path.join(depot_dir, entry)
            if not _rancid_is_probable_host_file(path):
                continue
            if not os.path.isfile(path):
                continue
            names.append(_rancid_hostname_from_entry(entry))
    except OSError:
        return []
    return sorted(set(names))


def _rancid_read_sample_hostnames(sample_path: str) -> list[str]:
    if not os.path.isfile(sample_path):
        return []
    hosts: list[str] = []
    try:
        with open(sample_path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                item = line.strip()
                if item and not item.startswith("#"):
                    hosts.append(item)
    except OSError:
        return []
    return sorted(set(hosts))


def _rancid_ensure_sample_file(canonical_family: str) -> None:
    """If ``rancid_samples/<family>/`` exists but ``ls_output_sample.txt`` is missing, seed ~30 lines."""
    samples_dir = os.path.join(_REPO_ROOT, "rancid_samples", canonical_family)
    sample_path = os.path.join(samples_dir, "ls_output_sample.txt")
    if os.path.isfile(sample_path) or not os.path.isdir(samples_dir):
        return
    try:
        os.makedirs(samples_dir, exist_ok=True)
    except OSError:
        return
    lines = "\n".join(_RANCID_DEFAULT_SAMPLE_HOSTS) + "\n"
    try:
        with open(sample_path, "w", encoding="utf-8") as handle:
            handle.write(lines)
    except OSError:
        return


def _rancid_sample_paths_secure(canonical_family: str) -> tuple[str, str] | None:
    """Return (samples_dir_real, sample_file_real) if paths stay under repo rancid_samples."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", canonical_family):
        return None
    samples_dir = os.path.join(_REPO_ROOT, "rancid_samples", canonical_family)
    sample_path = os.path.join(samples_dir, "ls_output_sample.txt")
    try:
        dir_real = os.path.realpath(samples_dir)
        file_real = os.path.realpath(sample_path)
        root_real = os.path.realpath(os.path.join(_REPO_ROOT, "rancid_samples"))
    except OSError:
        return None
    prefix = root_real.rstrip(os.sep) + os.sep
    if not (dir_real == root_real or dir_real.startswith(prefix)):
        return None
    if not file_real.startswith(dir_real.rstrip(os.sep) + os.sep):
        return None
    return dir_real, file_real


def _rancid_gather_hostnames(
    mapping: dict[str, str],
    canonical_family: str,
    depot_path: str,
    *,
    allow_sample_fallback: bool = True,
) -> tuple[list[str], str, str]:
    """Return (hostnames, inventory_path_used, source).

    ``source`` is ``depot`` (live ``os.listdir``), ``sample`` (repo sample file), ``none`` (no data),
    or ``depot_unavailable`` when the depot cannot be read and sample fallback is disabled.
    """
    allowed = _rancid_allowed_depot_realpaths(mapping)
    try:
        depot_real = os.path.realpath(depot_path)
    except OSError:
        depot_real = ""
    if depot_real and os.path.isdir(depot_path) and depot_real in allowed:
        return _rancid_list_depot_hostnames(depot_path), depot_path, "depot"

    if not allow_sample_fallback:
        return [], depot_path, "depot_unavailable"

    _rancid_ensure_sample_file(canonical_family)
    secured = _rancid_sample_paths_secure(canonical_family)
    if not secured:
        return [], "", "none"
    _dir_real, sample_file = secured
    hosts = _rancid_read_sample_hostnames(sample_file)
    return hosts, sample_file, "sample"


def _rancid_filter_hostnames_grep(hostnames: list[str], needle: str) -> list[str]:
    """Keep hostnames whose line matches ``ls | grep needle`` (substring, case-insensitive)."""
    n = needle.strip().lower()
    if not n:
        return list(hostnames)
    return sorted(h for h in hostnames if n in h.lower())


def _rancid_summarize_function_categories(
    hostnames: list[str], *, max_samples_per_category: int
) -> dict[str, Any]:
    buckets: dict[str, list[str]] = {}
    for h in hostnames:
        code = _rancid_function_code_from_hostname(h)
        buckets.setdefault(code, []).append(h)
    for key in buckets:
        buckets[key] = sorted(buckets[key])
    categories = sorted(buckets.keys())
    cap = max(0, int(max_samples_per_category))
    samples = {c: buckets[c][:cap] if cap else [] for c in categories}
    counts = {c: len(buckets[c]) for c in categories}
    truncated_flags = {
        c: (cap > 0 and len(buckets[c]) > cap) for c in categories
    }
    return {
        "function_categories": categories,
        "function_category_counts": counts,
        "sample_hostnames_per_category": samples,
        "sample_hostnames_truncated": truncated_flags,
        "max_samples_per_category": cap,
        "category_derivation": "stem before first dot; letters/hyphens before trailing digits on stem (e.g. dr01 -> dr)",
        "note": (
            "function_category_counts are full totals per category. "
            "sample_hostnames_per_category lists at most max_samples_per_category hosts each; "
            "see sample_hostnames_truncated when the sample list is shorter than the count."
        ),
    }


def _rancid_depot_access_details(mapping: dict[str, str], depot_path: str) -> dict[str, Any]:
    """Return whether a configured Rancid depot root is usable, with stable ``reason`` codes for clients."""
    result: dict[str, Any] = {"ok": False, "configured_depot_path": depot_path}
    path = (depot_path or "").strip()
    if not path:
        result["reason"] = "empty_path"
        result["hint"] = "The juniper entry in rancid_folders must be a non-empty directory path."
        return result

    allowed = _rancid_allowed_depot_realpaths(mapping)
    try:
        depot_real = os.path.realpath(path)
    except OSError as exc:
        result["reason"] = "realpath_failed"
        result["os_error"] = str(exc)
        result["hint"] = "Could not resolve the configured path (parent permissions or I/O)."
        return result

    result["depot_realpath"] = depot_real
    if depot_real not in allowed:
        result["reason"] = "not_in_allowlist"
        result["hint"] = (
            "After realpath(), this directory is not one of the roots declared in rancid_folders; "
            "check for typos or unexpected symlinks."
        )
        return result

    if not os.path.lexists(path):
        result["reason"] = "path_missing"
        result["hint"] = (
            "The path is absent on the host running the MCP server (default rancid_folders often "
            "targets an internal checkout). This is not an LLM permission issue: point "
            "RANCID_FOLDERS_FILE at a local mapping file whose juniper: line references a directory "
            "that exists here, or run the client on a host that mounts the real Rancid tree."
        )
        return result

    if not os.path.isdir(path):
        result["reason"] = "not_a_directory"
        result["hint"] = "Expected a directory of per-host Rancid files, not a single file."
        return result

    try:
        os.listdir(path)
    except PermissionError as exc:
        result["reason"] = "permission_denied"
        result["os_error"] = str(exc)
        result["hint"] = (
            "The OS denied listing this directory; fix filesystem permissions or run as a user "
            "with read and execute on the depot directory."
        )
        return result
    except OSError as exc:
        result["reason"] = "listdir_failed"
        result["os_error"] = str(exc)
        result["hint"] = "Could not list directory contents; see os_error."
        return result

    result["ok"] = True
    return result


def _rancid_depot_accessible(mapping: dict[str, str], depot_path: str) -> bool:
    return bool(_rancid_depot_access_details(mapping, depot_path).get("ok"))


def _parse_junos_model_and_release_from_config(text: str) -> dict[str, Any]:
    """Best-effort parse of Junos ``show version`` / ``show version detail`` style lines in Rancid text."""
    model: str | None = None
    junos: str | None = None
    for pattern in (
        r"(?im)^\s*#?\s*Model:\s*(.+?)\s*$",
        r"(?im)^\s*model\s*:\s*(.+?)\s*$",
    ):
        m = re.search(pattern, text)
        if m:
            model = m.group(1).strip()
            break
    for pattern in (
        r"(?im)^\s*Junos:\s*(.+?)\s*$",
        r"(?im)^\s*JUNOS\s+Software\s+Release\s+\[([^\]]+)\]",
        r"(?i)JUNOS\s+Base\s+OS\s+Software\s+\[([^\]]+)\]",
    ):
        m = re.search(pattern, text)
        if m:
            junos = m.group(1).strip()
            break
    return {"model": model, "junos": junos}


def _rancid_read_file_for_model_scan(path: str, max_bytes: int) -> tuple[str, bool, str | None]:
    """Return (text, truncated, error)."""
    cap = max(4096, min(int(max_bytes), 64_000_000))
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return "", False, str(exc)
    truncated = size > cap
    try:
        with open(path, "rb") as handle:
            blob = handle.read(cap)
    except OSError as exc:
        return "", False, str(exc)
    try:
        text = blob.decode("utf-8", errors="replace")
    except Exception as exc:
        return "", truncated, str(exc)
    return text, truncated, None


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
    run_data: dict[str, Any],
    component_type: str = "",
    command: str = "",
    hosts: set[str] | None = None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for hostname, per_host in run_data.get("results", {}).items():
        if hosts and hostname not in hosts:
            continue
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
            result.filtered = _filter_output(result.stdout, command=command)
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
            "fabric_modules": {},
            "power_modules": {},
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
            for mod in result.facts.get("fabric_modules", []):
                summary["facts"]["fabric_modules"].setdefault(mod, []).append(hostname)
            for mod in result.facts.get("power_modules", []):
                summary["facts"]["power_modules"].setdefault(mod, []).append(hostname)

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


async def _start_audit_run_async(
    hosts: list[str],
    parsed_commands: list[str],
    *,
    audit_profile: str | None = None,
) -> str:
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
    payload: dict[str, Any] = dict(_run_to_dict(run))
    if audit_profile:
        payload["audit_profile"] = audit_profile
    return _json(payload)


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

    return await _start_audit_run_async(hosts, parsed_commands)


@mcp.tool()
async def start_ptx_chassis_hardware_audit(devices: str) -> str:
    """
    Start a **PTX / JNP10K-class** chassis hardware audit: runs ``show chassis hardware`` on each host
    via gnetch. Uses PTX-aware output filtering (PSM, SIB, FTC, Fan Tray, …) and structured parsing for
    fabric, power, line cards, and routing engines—same follow-up tools as ``start_audit_run``
    (``get_audit_run_status``, ``get_audit_run_summary``, ``summarize_components``, ``count_components``, …).
    - devices: filename in the current working directory or comma/space-separated hostnames (same as ``start_audit_run``).
    """
    hosts = _parse_devices(devices)
    if not hosts:
        return _json({"error": "No hosts were provided."})
    return await _start_audit_run_async(
        hosts,
        ["show chassis hardware"],
        audit_profile="ptx_chassis_hardware",
    )


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
async def collect_bng_configuration(hostname: str) -> str:
    """
    Collect BNG configuration using 'admin display-config' through gnetch,
    save the original config under bng/configurations/original,
    and rootify it into bng/configurations/flat.
    """
    _ensure_bng_dirs()
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    safe_hostname = hostname.strip().lower()
    original_path = os.path.join(BNG_ORIGINAL_DIR, f"{safe_hostname}_{timestamp}.cfg")
    flat_path = os.path.join(BNG_FLAT_DIR, f"{safe_hostname}_{timestamp}_flat.cfg")

    start = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            GNETCH_PATH,
            "admin display-config",
            safe_hostname,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        raw_output = stdout.decode(errors="replace")
        stderr_text = stderr.decode(errors="replace").strip()

        if proc.returncode != 0:
            return _json(
                {
                    "hostname": safe_hostname,
                    "command": "admin display-config",
                    "exit_code": proc.returncode,
                    "stderr": stderr_text,
                    "duration_ms": int((time.time() - start) * 1000),
                    "error": "Configuration collection failed.",
                }
            )

        with open(original_path, "w") as f:
            f.write(raw_output)

        rootifier = await asyncio.create_subprocess_exec(
            "python3",
            SROS_ROOTIFIER_PATH,
            original_path,
            BNG_FLAT_DIR,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        root_stdout, root_stderr = await rootifier.communicate()
        root_stdout_text = root_stdout.decode(errors="replace").strip()
        root_stderr_text = root_stderr.decode(errors="replace").strip()

        return _json(
            {
                "hostname": safe_hostname,
                "command": "admin display-config",
                "exit_code": proc.returncode,
                "duration_ms": int((time.time() - start) * 1000),
                "original_path": original_path,
                "flat_path": flat_path,
                "rootifier_exit_code": rootifier.returncode,
                "rootifier_stdout": root_stdout_text,
                "rootifier_stderr": root_stderr_text,
                "bytes_collected": len(raw_output),
                "lines_collected": len(raw_output.splitlines()),
                "stderr": stderr_text,
            }
        )
    except Exception as exc:
        return _json(
            {
                "hostname": safe_hostname,
                "command": "admin display-config",
                "exit_code": -1,
                "duration_ms": int((time.time() - start) * 1000),
                "original_path": original_path,
                "flat_path": flat_path,
                "rootifier_exit_code": None,
                "rootifier_stdout": "",
                "rootifier_stderr": "",
                "bytes_collected": 0,
                "lines_collected": 0,
                "stderr": str(exc),
                "error": "Configuration collection failed with an exception.",
            }
        )


@mcp.tool()
def flatten_sros_config(raw_text: str, hierarchy: str = "") -> str:
    """
    Convert hierarchical SR OS configuration into flat format.
    - raw_text: pasted SR OS config block, optionally including [gl:/configure ...] and CLI prompt lines
    - hierarchy: optional current location such as /configure service; if omitted, the tool will try to
      extract it from raw_text
    """
    try:
        module = _load_flat_sros_module()
        resolved_hierarchy = hierarchy.strip() or module.extract_hierarchy_from_text(raw_text)
        if not resolved_hierarchy:
            return _json(
                {
                    "error": (
                        "No SR OS hierarchy was found. Include a [gl:/configure ...] line in the pasted text "
                        "or provide hierarchy explicitly, for example /configure service."
                    ),
                    "flat_lines": [],
                    "hierarchy": "",
                }
            )

        flat_lines = module.flatten_sros_config(resolved_hierarchy, raw_text)
        return _json(
            {
                "hierarchy": resolved_hierarchy,
                "flat_lines": flat_lines,
                "flat_text": "\n".join(flat_lines),
                "line_count": len(flat_lines),
            }
        )
    except Exception as exc:
        return _json(
            {
                "error": str(exc),
                "flat_lines": [],
                "hierarchy": hierarchy.strip(),
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
    hosts: str = "",
) -> str:
    """
    Count components by name.
    match_mode must be one of: exact, prefix, contains
    component_type examples: chassis, routing_engine, control_board, line_card, power_supply,
    fabric, fan_controller, fan_tray, midplane, front_panel, mezzanine
    """
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})
    host_filter = _parse_host_filter(hosts)

    try:
        components = [
            item
            for item in _iter_components(
                run_data,
                component_type=component_type,
                command=command,
                hosts=host_filter,
            )
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
            "hosts": sorted(host_filter),
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
    hosts: str = "",
) -> str:
    """
    List structured components.
    If name is provided, it is matched using match_mode.
    """
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})
    host_filter = _parse_host_filter(hosts)

    try:
        components = _iter_components(
            run_data,
            component_type=component_type,
            command=command,
            hosts=host_filter,
        )
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
            "hosts": sorted(host_filter),
            "components": components,
        }
    )


@mcp.tool()
def summarize_components(run_id: str, command: str = "", hosts: str = "") -> str:
    """Summarize all structured components by type and exact description."""
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})
    host_filter = _parse_host_filter(hosts)

    summary: dict[str, dict[str, int]] = {}
    for item in _iter_components(run_data, command=command, hosts=host_filter):
        component_type = item["component_type"]
        description = item["description"]
        summary.setdefault(component_type, {})
        summary[component_type][description] = summary[component_type].get(description, 0) + 1

    return _json(
        {
            "run_id": run_id,
            "command": command,
            "hosts": sorted(host_filter),
            "summary": {
                component_type: dict(sorted(descriptions.items()))
                for component_type, descriptions in sorted(summary.items())
            },
        }
    )


@mcp.tool()
def get_host_component_summary(run_id: str, hosts: str = "", command: str = "") -> str:
    """Return structured component summaries grouped by host."""
    run_data = _get_run_data(run_id)
    if not run_data:
        return _json({"error": f"Unknown run_id: {run_id}"})

    host_filter = _parse_host_filter(hosts)
    per_host: dict[str, dict[str, dict[str, int]]] = {}
    for item in _iter_components(run_data, command=command, hosts=host_filter):
        hostname = item["hostname"]
        component_type = item["component_type"]
        description = item["description"]
        per_host.setdefault(hostname, {})
        per_host[hostname].setdefault(component_type, {})
        per_host[hostname][component_type][description] = (
            per_host[hostname][component_type].get(description, 0) + 1
        )

    return _json(
        {
            "run_id": run_id,
            "command": command,
            "hosts": sorted(host_filter) if host_filter else sorted(per_host.keys()),
            "per_host": {
                hostname: {
                    component_type: dict(sorted(descriptions.items()))
                    for component_type, descriptions in sorted(component_map.items())
                }
                for hostname, component_map in sorted(per_host.items())
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


@mcp.tool()
def list_rancid_device_families() -> str:
    """
    List Rancid **device family** keys from the repo ``rancid_folders`` file (e.g. juniper, cisco, bng).

    Use when the user asks how many / which device families exist for Rancid inventories, before
    calling ``list_rancid_devices`` with a specific ``device_family``.
    """
    mapping = _parse_rancid_folders_file()
    if not mapping:
        return _json(
            {
                "error": "No rancid_folders mapping loaded",
                "hint": os.environ.get(
                    "RANCID_FOLDERS_FILE", os.path.join(_REPO_ROOT, "rancid_folders")
                ),
            }
        )
    families = sorted(mapping.keys())
    return _json(
        {
            "families": families,
            "family_count": len(families),
            "paths_by_family": dict(sorted(mapping.items())),
        }
    )


@mcp.tool()
def list_rancid_devices(
    device_family: str = "juniper",
    list_function_categories: bool = False,
    hostname_prefix: str = "",
    max_devices: int = 20000,
    max_samples_per_category: int = 5,
) -> str:
    """
    Rancid device inventory (paths from repo ``rancid_folders``).

    **Two modes** (do not combine with ``hostname_prefix`` when listing categories—prefix is ignored then):

    1. ``list_function_categories=True`` — **live only**: ``os.listdir`` on the depot directory (same
       idea as ``ls``). Categories and counts are derived from those filenames. If the depot path is
       missing or unreadable, returns an error—**no** ``rancid_samples`` fallback.

    2. ``list_function_categories=False`` — return device names from depot when available; if the
       live depot path is missing locally, may fall back to ``rancid_samples/<family>/ls_output_sample.txt``.
       Check the JSON ``source`` field: ``depot`` means live ``os.listdir``; ``sample`` means the repo sample list only.
       Optional ``hostname_prefix`` filters like ``ls | grep <prefix>`` (substring, case-insensitive).
    """
    mapping = _parse_rancid_folders_file()
    if not mapping:
        return _json(
            {
                "error": "No rancid_folders mapping loaded",
                "hint": f"Expected file at {os.environ.get('RANCID_FOLDERS_FILE', os.path.join(_REPO_ROOT, 'rancid_folders'))}",
            }
        )

    canonical = _rancid_resolve_family_key(mapping, device_family)
    if not canonical:
        return _json(
            {
                "error": f"Unknown device_family: {device_family!r}",
                "known_families": sorted(mapping.keys()),
            }
        )

    depot_path = mapping[canonical]
    allow_sample = not list_function_categories
    hostnames, inventory_path, source = _rancid_gather_hostnames(
        mapping, canonical, depot_path, allow_sample_fallback=allow_sample
    )
    if source == "depot_unavailable":
        return _json(
            {
                "error": "Live Rancid directory not available; category listing requires a readable depot path.",
                "device_family": canonical,
                "configured_depot_path": depot_path,
                "hint": "Run the MCP server where rancid_folders paths exist (real-time os.listdir). Sample files are not used for list_function_categories.",
            }
        )
    if source == "none":
        return _json(
            {
                "error": "No depot directory and no sample listing available",
                "device_family": canonical,
                "configured_depot_path": depot_path,
                "sample_hint": os.path.join(_REPO_ROOT, "rancid_samples", canonical, "ls_output_sample.txt"),
            }
        )

    base: dict[str, Any] = {
        "device_family": canonical,
        "inventory_path": inventory_path,
        "source": source,
        "configured_depot_path": depot_path,
        "total_devices": len(hostnames),
    }

    if list_function_categories:
        summary = _rancid_summarize_function_categories(
            hostnames, max_samples_per_category=max_samples_per_category
        )
        base["mode"] = "function_categories"
        base["listing"] = "live_depot_os_listdir"
        base.update(summary)
        if hostname_prefix.strip():
            base["hostname_prefix_ignored"] = hostname_prefix.strip()
        return _json(base)

    total_before = len(hostnames)
    filtered = _rancid_filter_hostnames_grep(hostnames, hostname_prefix)
    cap = max(1, min(int(max_devices), 500_000))
    truncated = len(filtered) > cap
    devices = filtered[:cap]

    payload: dict[str, Any] = {
        **base,
        "mode": "devices",
        "hostname_prefix": hostname_prefix.strip(),
        "filter": "substring case-insensitive on device name (ls | grep style)" if hostname_prefix.strip() else "none",
        "total_devices_before_filter": total_before,
        "total_devices": len(filtered),
        "devices": devices,
    }
    if truncated:
        payload["truncated"] = True
        payload["max_devices"] = cap
        payload["note"] = f"Returned first {cap} names after filter; increase max_devices if needed."
    return _json(payload)


@mcp.tool()
def list_rancid_juniper_platform_models(
    hostname_prefix: str = "",
    model_substring: str = "",
    max_files: int = 5000,
    max_read_bytes_per_file: int = 0,
) -> str:
    """
    For **Juniper** Rancid configs: read each host file under the live ``juniper`` depot path and
    extract platform **model** and **Junos/OS release** from ``show version`` / ``show version detail``
    style lines (e.g. ``# Model: ex4200-48t``, ``Junos: 22.2R3-S1.9``).

    Answers questions like **all CR devices' OS version** from Rancid: set ``hostname_prefix="cr"``
    (substring match on hostnames such as ``cr01....``); each row's ``junos`` field is the parsed OS
    release from saved config text—**not** a live ``start_audit_run`` (use audits when the user needs
    fresh CLI output).

    For **all MX960 (or EX4200-48t, etc.) OS versions** from Rancid, set ``model_substring`` to a
    substring of the parsed ``Model:`` line (case-insensitive), e.g. ``mx960`` or ``ex4200-48t``;
    only hosts whose model contains that text are returned. Hostname and model filters combine with AND.

    ``max_files`` is the maximum number of **files opened** (read budget) per call, scanning the
    sorted depot list until the budget is exhausted—raise it if matches may lie beyond the first chunk.

    Requires a readable **depot** directory from ``rancid_folders`` (no sample-file fallback).
    On failure, JSON includes ``depot_access_reason`` (e.g. ``path_missing``, ``permission_denied``).

    - ``hostname_prefix``: optional ``ls | grep`` style filter on the hostname/filename before scanning.
    - ``model_substring``: optional case-insensitive substring match on the parsed **model** field.
    - ``max_files``: max host **files to open** per call (default 5000, hard cap 50000).
    - ``max_read_bytes_per_file``: per-file read cap (default from env ``RANCID_MODEL_SCAN_MAX_BYTES`` or 8 MiB).
    """
    mapping = _parse_rancid_folders_file()
    if not mapping:
        return _json(
            {
                "error": "No rancid_folders mapping loaded",
                "hint": os.environ.get(
                    "RANCID_FOLDERS_FILE", os.path.join(_REPO_ROOT, "rancid_folders")
                ),
            }
        )
    canonical = _rancid_resolve_family_key(mapping, "juniper")
    if not canonical:
        return _json({"error": "juniper family missing from rancid_folders", "known_families": sorted(mapping.keys())})

    depot_path = mapping[canonical]
    # Same live-depot rule as list_rancid_devices, but **never** sample fallback: hostname-only
    # listing can return ``source: "sample"`` when the configured path is absent, which is easy
    # to mistake for a working depot—this tool must open per-host files under the real directory.
    probe_source = _rancid_gather_hostnames(
        mapping, canonical, depot_path, allow_sample_fallback=False
    )[2]
    if probe_source != "depot":
        access = _rancid_depot_access_details(mapping, depot_path)
        err: dict[str, Any] = {
            "error": "Live Juniper Rancid depot is not reachable for a platform scan (per-host file reads).",
            "depot_access_reason": access.get("reason", "unknown"),
            "hostname_list_probe_source": probe_source,
            "configured_depot_path": depot_path,
            "hint": access.get("hint", ""),
            "note": (
                "If ``list_rancid_devices`` showed CR routers but this tool fails, check that JSON's "
                "``source`` field: ``sample`` means ``rancid_samples/`` only, not your live Rancid tree."
            ),
        }
        for key in ("depot_realpath", "os_error"):
            if key in access:
                err[key] = access[key]
        return _json(err)

    host_file_pairs: list[tuple[str, str]] = []
    try:
        for entry in sorted(os.listdir(depot_path)):
            path = os.path.join(depot_path, entry)
            if not _rancid_is_probable_host_file(path) or not os.path.isfile(path):
                continue
            host_file_pairs.append((_rancid_hostname_from_entry(entry), path))
    except OSError as exc:
        return _json({"error": f"Cannot list juniper depot: {exc}", "configured_depot_path": depot_path})

    needle = hostname_prefix.strip().lower()
    if needle:
        host_file_pairs = [(h, p) for h, p in host_file_pairs if needle in h.lower()]

    total_depot_candidates = len(host_file_pairs)
    cap_reads = max(1, min(int(max_files), 50_000))
    model_needle = model_substring.strip().lower()

    default_bytes = int(os.environ.get("RANCID_MODEL_SCAN_MAX_BYTES", str(8 * 1024 * 1024)))
    per_cap = int(max_read_bytes_per_file) if int(max_read_bytes_per_file) > 0 else default_bytes

    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    model_histogram: dict[str, int] = {}
    files_opened = 0
    stopped_early = False

    for hostname, filepath in sorted(host_file_pairs, key=lambda item: item[0]):
        if files_opened >= cap_reads:
            stopped_early = total_depot_candidates > files_opened
            break
        files_opened += 1
        text, truncated, err = _rancid_read_file_for_model_scan(filepath, per_cap)
        if err:
            errors.append({"hostname": hostname, "error": err})
            rows.append(
                {
                    "hostname": hostname,
                    "model": None,
                    "junos": None,
                    "file_read_truncated": False,
                    "parse_note": f"read_error: {err}",
                }
            )
            continue
        parsed = _parse_junos_model_and_release_from_config(text)
        model = parsed["model"]
        junos = parsed["junos"]
        note_parts: list[str] = []
        if truncated:
            note_parts.append(f"read_truncated_after_{per_cap}_bytes")
        if not model and not junos:
            note_parts.append("no_model_or_junos_line_found")
        if model_needle:
            if not model or model_needle not in model.lower():
                continue
        rows.append(
            {
                "hostname": hostname,
                "model": model,
                "junos": junos,
                "file_read_truncated": truncated,
                "parse_note": "; ".join(note_parts) if note_parts else "",
            }
        )
        if model:
            mk = model.strip()
            model_histogram[mk] = model_histogram.get(mk, 0) + 1

    unique_models = sorted(model_histogram.keys(), key=lambda k: (-model_histogram[k], k.lower()))
    payload: dict[str, Any] = {
        "device_family": "juniper",
        "hostname_inventory_source": "depot",
        "inventory_path": depot_path,
        "configured_depot_path": depot_path,
        "hostname_prefix": hostname_prefix.strip(),
        "model_substring": model_substring.strip(),
        "max_reads_budget": cap_reads,
        "files_opened": files_opened,
        "depot_host_candidates_after_hostname_filter": total_depot_candidates,
        "stopped_early_after_read_budget": stopped_early,
        "max_read_bytes_per_file": per_cap,
        "matching_host_count": len(rows),
        "platforms": rows,
        "unique_model_histogram": {m: model_histogram[m] for m in unique_models},
        "read_errors": errors,
        "note": (
            "Field ``junos`` on each row is the OS/Junos release parsed from Rancid file contents "
            "(show-version style lines), not a live device poll."
        ),
    }
    if stopped_early:
        payload["budget_note"] = (
            "Read budget exhausted before every depot file was opened; raise max_files to search further."
        )
    return _json(payload)


def _core_capacity_extract_metro(device_name: str) -> str:
    match = re.search(r"\.(\D{3})\d*", device_name)
    return match.group(1) if match else "unknown"


def _core_capacity_get_pacific_timestamp() -> str:
    try:
        from datetime import datetime
        from zoneinfo import ZoneInfo
        utc_now = datetime.now(tz=ZoneInfo("UTC"))
        pacific_time = utc_now.astimezone(ZoneInfo("America/Los_Angeles"))
        return pacific_time.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        import time
        return time.strftime("%Y-%m-%d %H:%M:%S")


def _core_capacity_parse_isis_adj(output: list[str]) -> list[dict[str, Any]]:
    adjacency_list = []
    if not output:
        return []
    start_idx = 1 if any(h in output[0] for h in ("Interface", "System", "State")) else 0
    for line in output[start_idx:]:
        line_str = line.strip()
        if not line_str or "Warning: License key missing" in line_str:
            continue
        fields = line_str.split()
        if len(fields) < 5:
            continue
        adjacency_list.append({
            "Interface": fields[0],
            "System": fields[1],
            "L": fields[2],
            "State": fields[3],
            "Hold (secs)": fields[4],
        })
    return adjacency_list


def _core_capacity_save_high_interfaces(audit_result: dict[str, Any], json_file_path: str) -> dict[str, Any]:
    high_utilization_data = {}
    if os.path.exists(json_file_path):
        with open(json_file_path, "r") as json_file:
            try:
                high_utilization_data = json.load(json_file)
            except Exception:
                pass

    high_devices_existed = False
    for device, interfaces in audit_result.items():
        metro = _core_capacity_extract_metro(device)
        device_data = high_utilization_data.get(metro, {}).get(device, {})
        for key, details in interfaces.items():
            if key in ["role", "year"]:
                continue
            interface = key
            input_bps = round(details.get("input_bps", 0))
            input_percent = round(details.get("input_bps_percent", 0))
            output_bps = round(details.get("output_bps", 0))
            output_percent = round(details.get("output_bps_percent", 0))
            neighbor = details.get("neighbor", "Unknown")
            speed = details.get("speed", "Unknown")
            timestamp = _core_capacity_get_pacific_timestamp()

            if input_percent > 50 or output_percent > 50:
                high_devices_existed = True
                if interface not in device_data:
                    device_data[interface] = []
                device_data[interface].append({
                    "neighbor": neighbor,
                    "input_util": input_bps,
                    "input_percent": input_percent,
                    "output_util": output_bps,
                    "output_percent": output_percent,
                    "speed": speed,
                    "timestamp": timestamp
                })
        if device_data:
            high_utilization_data.setdefault(metro, {})[device] = device_data

    if high_utilization_data and high_devices_existed:
        try:
            with open(json_file_path, "w") as json_file:
                json.dump(high_utilization_data, json_file, indent=4)
        except Exception:
            pass
    return high_utilization_data


@mcp.tool()
async def audit_core_capacity(devices: str) -> str:
    """
    Audit core network capacity of GFiber/Juniper devices.
    Runs network commands to collect ISIS adjacencies and interface utilization data for core/backbone links,
    identifying interfaces with high utilization (>50%).

    This tool can audit a single device or a list of devices.
    - devices: a filename containing device hostnames, or a comma/space-separated list of hostnames.
    """
    hosts = _parse_devices(devices)
    if not hosts:
        return _json({"error": "No devices specified or found."})

    # Try to import dynamic device attributes from setup_db
    device_info_cache = {}
    try:
        import sys
        gfiber_path = "/usr/local/google/home/mikezh/Coding/gfiber"
        if gfiber_path not in sys.path:
            sys.path.append(gfiber_path)
        from utils_gfiber import setup_db
        setup = setup_db("rancid_juniper_core.yaml")
        if setup and hasattr(setup, "setupdb") and hasattr(setup.setupdb, "Device_list"):
            for dev in setup.setupdb.Device_list:
                device_info_cache[dev.hostname.strip().lower()] = {
                    "role": getattr(dev, "role", "metro"),
                    "year": getattr(dev, "year", 2024),
                }
    except Exception:
        pass

    def get_device_meta(hostname: str) -> dict[str, Any]:
        h = hostname.strip().lower()
        if h in device_info_cache:
            return device_info_cache[h]
        role = "metro"
        if h.startswith("cr") or "core" in h:
            role = "backbone"
        return {"role": role, "year": 2024}

    # Create log folder matching setupdb behavior
    log_folder = os.path.join(CURRENT_DIR, "audit_logs_core")
    os.makedirs(log_folder, exist_ok=True)

    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)

    async def process_device(hostname: str) -> tuple[str, dict[str, Any]]:
        meta = get_device_meta(hostname)
        role = meta["role"]
        year = meta["year"]

        local_device_site = hostname.split(".")[1] if "." in hostname else hostname
        matched = re.search(r"([a-zA-Z]+)[0-9]+", local_device_site)
        local_site = matched.group(1).strip() if matched else "Unknown"

        bundle_dict = {
            "role": role,
            "year": year
        }
        device_log_file = os.path.join(log_folder, f"{hostname}.log")

        try:
            # Write initial log entry
            with open(device_log_file, 'a') as log_file:
                log_file.write(f"Processing device: {hostname}\n")

            async with semaphore:
                # Fetch 'show version'
                proc = await asyncio.create_subprocess_exec(
                    GNETCH_PATH, "show version", hostname,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                version_result = stdout.decode(errors="replace").strip().splitlines()

                with open(device_log_file, 'a') as log_file:
                    log_file.write("\n--- show version ---\n")
                    log_file.write("\n".join(version_result) + "\n")

                # Fetch 'show isis adjacency'
                proc = await asyncio.create_subprocess_exec(
                    GNETCH_PATH, "show isis adjacency", hostname,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                adj_result = stdout.decode(errors="replace").strip().splitlines()

                with open(device_log_file, 'a') as log_file:
                    log_file.write("\n--- show isis adjacency ---\n")
                    log_file.write("\n".join(adj_result) + "\n")

            adj_list = _core_capacity_parse_isis_adj(adj_result)

            for adj in adj_list:
                sys_name = adj.get("System", "")
                state = adj.get("State", "")
                if ("dr" in sys_name or "cr" in sys_name or "pr" in sys_name) and state == "Up":
                    intf = adj.get("Interface", "").split(".")[0]
                    if not intf:
                        continue
                    bundle_dict.setdefault(intf, {"neighbor": sys_name})

                    remote_device_site = sys_name.split(".")[1] if "." in sys_name else sys_name
                    matched = re.search(r"([a-zA-Z]+)[0-9]+", remote_device_site)
                    remote_site = matched.group(1).strip() if matched else "Unknown"

                    bundle_dict[intf]["Circuit"] = "SR" if local_site.upper() == remote_site.upper() else "LR"

                    # Fetch 'show interfaces extensive'
                    async with semaphore:
                        proc = await asyncio.create_subprocess_exec(
                            GNETCH_PATH, f"show interfaces {intf} extensive", hostname,
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                        )
                        stdout, _ = await proc.communicate()
                        intf_result = stdout.decode(errors="replace").strip().splitlines()

                    with open(device_log_file, 'a') as log_file:
                        log_file.write(f"\n--- show interfaces {intf} extensive ---\n")
                        log_file.write("\n".join(intf_result) + "\n")

                    # Parse interface details
                    speed_in_bps = 100_000_000_000
                    speed_str = "100Gbps"
                    description = ""
                    input_bps = 0
                    input_bps_percent = 0.0
                    output_bps = 0
                    output_bps_percent = 0.0
                    input_pps = 0
                    output_pps = 0
                    agg_member_links = 0
                    agg_members = []

                    for line in intf_result:
                        line_str = line.strip()
                        if "Description: " in line_str:
                            description = line_str
                        elif "Link-level type: Ethernet, MTU" in line_str or "Speed:" in line_str:
                            regex_speed = r"Speed: ([0-9]+Gbps)"
                            matched = re.search(regex_speed, line_str)
                            if matched:
                                speed_str = matched.group(1)
                                try:
                                    speed_in_bps = int(speed_str.replace("Gbps", "")) * 1_000_000_000
                                except ValueError:
                                    pass
                        elif "Traffic statistics:" in line_str:
                            try:
                                idx = intf_result.index(line)
                                if idx + 1 < len(intf_result):
                                    parts = intf_result[idx + 1].split(":")
                                    if len(parts) > 1:
                                        subparts = parts[1].split()
                                        if len(subparts) > 1:
                                            input_bps = int(subparts[1].strip())
                                if idx + 2 < len(intf_result):
                                    parts = intf_result[idx + 2].split(":")
                                    if len(parts) > 1:
                                        subparts = parts[1].split()
                                        if len(subparts) > 1:
                                            output_bps = int(subparts[1].strip())
                                if idx + 3 < len(intf_result):
                                    parts = intf_result[idx + 3].split(":")
                                    if len(parts) > 1:
                                        subparts = parts[1].split()
                                        if len(subparts) > 1:
                                            input_pps = int(subparts[1].strip())
                                if idx + 4 < len(intf_result):
                                    parts = intf_result[idx + 4].split(":")
                                    if len(parts) > 1:
                                        subparts = parts[1].split()
                                        if len(subparts) > 1:
                                            output_pps = int(subparts[1].strip())

                                if speed_in_bps > 0:
                                    input_bps_percent = (input_bps / speed_in_bps) * 100
                                    output_bps_percent = (output_bps / speed_in_bps) * 100
                            except Exception:
                                pass
                        elif "Aggregate member links:" in line_str:
                            try:
                                agg_member_links = int(line_str.split(":")[1].strip())
                            except Exception:
                                pass

                    agg_link_found = False
                    for i in range(len(intf_result)):
                        if "Link:" in intf_result[i] or "Members:" in intf_result[i]:
                            num = 0
                            agg_link_found = True
                            continue
                        if agg_link_found and intf_result[i].strip().startswith(("et-", "xe-", "ge-")):
                            agg_members.append(intf_result[i].strip().split()[0])
                            num += 1
                            if agg_member_links > 0 and num == agg_member_links:
                                break

                    member_speeds = {}
                    for member in agg_members:
                        async with semaphore:
                            proc = await asyncio.create_subprocess_exec(
                                GNETCH_PATH, f"show interfaces {member}", hostname,
                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                            )
                            stdout, _ = await proc.communicate()
                            member_result = stdout.decode(errors="replace").strip().splitlines()

                        with open(device_log_file, 'a') as log_file:
                            log_file.write(f"\n--- show interfaces {member} ---\n")
                            log_file.write("\n".join(member_result) + "\n")

                        member_speed = "Unknown"
                        for m_line in member_result:
                            if "Speed:" in m_line or "Link-level type: Ethernet, MTU" in m_line:
                                matched = re.search(r"Speed: ([0-9]+Gbps)", m_line)
                                if matched:
                                    member_speed = matched.group(1)
                                    break
                        member_speeds[member] = member_speed

                    bundle_dict[intf]["description"] = description
                    bundle_dict[intf]["speed"] = speed_str
                    bundle_dict[intf]["speed_human"] = speed_in_bps
                    bundle_dict[intf]["input_bps"] = input_bps
                    bundle_dict[intf]["input_bps_percent"] = input_bps_percent
                    bundle_dict[intf]["output_bps"] = output_bps
                    bundle_dict[intf]["output_bps_percent"] = output_bps_percent
                    bundle_dict[intf]["input_pps"] = input_pps
                    bundle_dict[intf]["output_pps"] = output_pps
                    bundle_dict[intf]["ae_list"] = agg_members
                    bundle_dict[intf]["member_speeds"] = member_speeds
                    is_400g = any("400g" in sp.lower() for sp in member_speeds.values())
                    bundle_dict[intf]["is_400g_upgraded"] = is_400g
                    bundle_dict[intf]["upgrade_status"] = "400G upgraded" if is_400g else "Not upgraded"

            with open(device_log_file, 'a') as log_file:
                log_file.write("\n--- Processed Data ---\n")
                log_file.write(json.dumps(bundle_dict, indent=4) + "\n")

        except Exception as exc:
            with open(device_log_file, 'a') as log_file:
                log_file.write(f"\nError processing device {hostname}: {exc}\n")

        return hostname, bundle_dict

    # Execute concurrent processing
    tasks = [process_device(h) for h in hosts]
    results = await asyncio.gather(*tasks)
    audit_result = {h: d for h, d in results}

    # Save high utilization interfaces history
    json_file_path = os.path.join(CURRENT_DIR, "high_utilization_history.json")
    high_util_data = _core_capacity_save_high_interfaces(audit_result, json_file_path)

    # Dump snapshot json file matching main() date format
    from datetime import datetime
    now_str = datetime.now().strftime("%Y_%m_%d_%H_%M")
    json_folder = os.path.join(CURRENT_DIR, "Json_core_folder")
    os.makedirs(json_folder, exist_ok=True)
    
    snapshot_filename = f"core_high_{now_str}.json"
    with open(os.path.join(json_folder, snapshot_filename), "w") as f:
        json.dump(audit_result, f, indent=4)

    # Format high utilization report lists for return
    high_util_list = []
    for metro, metro_devices in high_util_data.items():
        for dev_name, dev_intfs in metro_devices.items():
            if dev_name in audit_result:
                for intf_name, history in dev_intfs.items():
                    if history:
                        latest = history[-1]
                        high_util_list.append({
                            "device": dev_name,
                            "interface": intf_name,
                            "metro": metro,
                            "speed": latest.get("speed", "Unknown"),
                            "neighbor": latest.get("neighbor", "Unknown"),
                            "input_percent": latest.get("input_percent", 0),
                            "output_percent": latest.get("output_percent", 0),
                            "timestamp": latest.get("timestamp", "")
                        })

    return _json({
        "status": "completed",
        "total_devices": len(hosts),
        "devices": audit_result,
        "high_utilization_interfaces": high_util_list,
        "snapshot_file": os.path.join(json_folder, snapshot_filename),
        "history_file": json_file_path
    })


@mcp.tool()
def scan_high_utilization_interfaces(
    threshold_percent: float = 50.0,
    date_filter: str = "",
    router_filter: str = ""
) -> str:
    """
    Scan all historical interface audit logs inside `Audit_interfaces_data` to identify
    interfaces exceeding a certain utilization threshold.
    - threshold_percent: float/int, only return interfaces where input or output utilization exceeds this (default is 50.0).
    - date_filter: optional string (e.g., '2026-05-14') to check a specific date.
    - router_filter: optional string (e.g., 'cr01' or 'iad101') to check a specific router name or prefix.
    """
    import glob
    root_dir = os.path.abspath(os.path.join(CURRENT_DIR, "Audit_interfaces_data"))
    if not os.path.exists(root_dir):
        return _json({"error": f"Directory {root_dir} does not exist."})

    # Path validation to prevent directory traversal
    def is_safe_subpath(target_path: str) -> bool:
        canonical_root = os.path.realpath(root_dir)
        canonical_target = os.path.realpath(target_path)
        return canonical_target == canonical_root or canonical_target.startswith(canonical_root + os.sep)

    matches = []
    
    # Scan date directories
    for date_folder in os.listdir(root_dir):
        date_path = os.path.join(root_dir, date_folder)
        if not os.path.isdir(date_path):
            continue
        if not is_safe_subpath(date_path):
            continue
        if date_filter and date_filter not in date_folder:
            continue
            
        # Scan router directories
        for router_folder in os.listdir(date_path):
            router_path = os.path.join(date_path, router_folder)
            if not os.path.isdir(router_path):
                continue
            if not is_safe_subpath(router_path):
                continue
            if router_filter and router_filter not in router_folder:
                continue
                
            # Scan JSON files
            json_files = glob.glob(os.path.join(router_path, f"{router_folder}_*.json"))
            for f in json_files:
                if not is_safe_subpath(f):
                    continue
                
                # Extract timestamp from filename (e.g. router_2026_05_14_21_10.json)
                basename = os.path.basename(f)
                match_ts = re.search(r"_(\d{4}_\d{2}_\d{2}_\d{2}_\d{2})\.json$", basename)
                ts_label = "Unknown"
                if match_ts:
                    parts = match_ts.group(1).split("_")
                    if len(parts) >= 5:
                        ts_label = f"{parts[3]}:{parts[4]}"
                
                try:
                    with open(f, "r") as fh:
                        data = json.load(fh)
                except Exception:
                    continue
                    
                for k, v in data.items():
                    if k in ["role", "year", "audit_timestamp"] or not isinstance(v, dict):
                        continue
                        
                    in_pct = round(v.get("input_bps_percent", 0), 1)
                    out_pct = round(v.get("output_bps_percent", 0), 1)
                    
                    if in_pct > threshold_percent or out_pct > threshold_percent:
                        matches.append({
                            "date": date_folder,
                            "router": router_folder,
                            "interface": k,
                            "neighbor": v.get("neighbor", "Unknown"),
                            "circuit": v.get("Circuit", "Unknown"),
                            "speed": v.get("speed", "Unknown"),
                            "input_percent": in_pct,
                            "output_percent": out_pct,
                            "timestamp": ts_label
                        })
                        
    # Sort matches by date, then router, then timestamp, then interface
    matches.sort(key=lambda x: (x["date"], x["router"], x["timestamp"], x["interface"]), reverse=True)
    
    return _json({
        "total_matches": len(matches),
        "threshold_percent": threshold_percent,
        "high_utilization_interfaces": matches
    })


if __name__ == "__main__":
    mcp.run()
