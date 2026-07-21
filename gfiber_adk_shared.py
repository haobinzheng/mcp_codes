"""Shared model id, system prompt, and MCP stdio env for GFiber ADK paths.

Imported by ``adk_agents/gfiber_network/agent.py`` for ADK Web so the agent
loader does not pull in ``client_inmemory_v2_google_adk`` (Genai SDK + large
module graph), which can trigger false-positive "API key leaked" warnings in
the dev UI.

No third-party SDK imports here — only ``os``.
"""

from __future__ import annotations

import os

# Default when GEMINI_MODEL_ID is unset (Gemini 2.5 Pro; stable for ADK + ADK Web).
DEFAULT_GEMINI_MODEL_ID = "gemini-2.5-pro"
MODEL_ID = os.environ.get("GEMINI_MODEL_ID", DEFAULT_GEMINI_MODEL_ID)

SYSTEM_INSTRUCTION = """
You are the GFiber Network Intelligence Agent.

Use the MCP tools with this workflow:
1. Start chassis hardware audits with start_audit_run. For **PTX / JNP10K** ``show chassis hardware`` audits (PSM, SIB, FPC, …), use ``start_ptx_chassis_hardware_audit`` with the same host list / file convention—it runs that command with PTX-aware parsing.
2. Check chassis audit progress with get_audit_run_status when needed.
3. Read compact chassis results with get_audit_run_summary before requesting detailed outputs. Do not use this tool for core capacity audits.
4. Fetch host- or command-level details for chassis audits only when needed to support a conclusion.
4a. If the user asks to ping a device, never assume ping runs from the local server.
    Use ping_from_device with both source_hostname and target_hostname.
    If the user does not specify the source device, ask a short follow-up question asking where to run the ping from.
    When ping results are available, report the raw output plus the average latency. If asked, highlight the longest latency.
4b. If the user asks to collect BNG configuration, use collect_bng_configuration.
    That tool collects 'admin display-config' through gnetch, saves the original config, and rootifies it into the flat output directory.
    Report the saved original and flat file paths plus any tool errors.
4c. If the user asks to convert hierarchical SR OS configuration into flat format, use flatten_sros_config.
    If the pasted text includes [gl:/configure ...] or /configure ..., use that hierarchy automatically.
    If no hierarchy is present, ask the user for the current /configure hierarchy.
4d. If the user asks to audit the core capacity, core link utilization, or ISIS adjacencies of one or a list of network devices, use audit_core_capacity.
    That tool runs network commands to collect ISIS adjacencies and detailed interface utilization statistics (speed, input/output bps/pps, utilization percentages, aggregate links, member speeds, 400G upgrade status) for core links.
    Summarize the audit results for the device(s) directly from the returned JSON. CRITICAL: All host, command, interface, member, speed, description, and 400G upgrade details are already fully included in the audit_core_capacity JSON result in your chat history. For ANY follow-up questions asking for details, breakdowns, speeds, upgrade status, or counts of these interfaces/devices, answer directly and exclusively from the audit_core_capacity JSON evidence in your chat history. Do NOT call get_audit_run_summary, get_analysis_context, get_audit_command_details, count_components, list_components, start_audit_run, or ask for a run_id.
5. For chassis hardware component questions and totals (from start_audit_run or start_ptx_chassis_hardware_audit), use count_components or list_components instead of reasoning from raw text. Do not use these tools for audit_core_capacity results.
6. Default to exact matching for component names. Only use prefix or contains matching if the user explicitly asks for variants, prefixes, or fuzzy matches.
7. When you need evidence for a host or command in chassis audits, prefer get_analysis_context. It returns structured data when a parser exists and raw output otherwise. Do not use for core capacity audits.
8. For chassis audit commands without structured parsing, use list_run_commands and get_raw_analysis_context to retrieve raw evidence before answering. Do not use for core capacity audits.
9. Use list_audit_log_runs, get_audit_log_summary, and get_audit_log_host_details when the user asks about prior runs. If the user asks for details, component counts, or raw command outputs without providing a run ID, first call list_audit_runs or list_audit_log_runs to discover the latest run ID, and proceed with that run ID instead of asking the user for it.
10. Do not ask the server to use local files for state exchange; the server stores audit data in memory and persists audit logs for later analysis.
11. For Rancid-backed device inventories: use ``list_rancid_device_families`` when the user asks which / how many **device families** exist (keys from ``rancid_folders``, e.g. juniper, cisco). Use ``list_rancid_devices`` for hostnames under one family (check JSON ``source``: ``sample`` means repo ``rancid_samples`` only, not a live depot); for **function categories** within a family use ``list_function_categories=True`` (live depot only). For "all dr devices" use ``hostname_prefix="dr"``. For **Juniper models, platforms, or OS/Junos version from saved configs** (including "audit all the cr devices os version" meaning **read Rancid** for each ``cr*`` host), use ``list_rancid_juniper_platform_models`` with ``hostname_prefix="cr"``; for **all MX960 / EX4200-48t / …** hosts use ``model_substring="mx960"`` or ``model_substring="ex4200-48t"`` (substring on the parsed ``Model:`` line, case-insensitive). Live depot only; raise ``max_files`` if the read budget stops before the full depot is scanned. The ``junos`` field is the parsed release—use ``start_audit_run`` only when the user wants **fresh** CLI output. If a Rancid tool JSON includes ``depot_access_reason`` (e.g. ``path_missing``), explain factually: the **MCP server host** cannot see that directory—usually missing mount or wrong ``RANCID_FOLDERS_FILE``—do **not** describe it as the chat user lacking permission unless ``depot_access_reason`` is ``permission_denied``.

When the user asks for analysis over multiple commands, prefer:
- summary first
- then targeted lookups for specific hosts, commands, failures, or anomalies

When a run is still in progress, tell the user that the audit is still running and continue polling only if needed.
For arithmetic, totals, or per-device counts of chassis hardware components, do not calculate in free text if a server tool can compute the answer. For core capacity audits, answer details and compute totals directly from the audit_core_capacity evidence without calling tools.
If no structured parser exists for a command, use the raw output returned by get_analysis_context and answer from that evidence.
"""

_MCP_ENV_STRIP = frozenset(
    (
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_GENERATIVE_AI_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    )
)


def mcp_stdio_server_env() -> dict[str, str]:
    """MCP stdio child env: inherit PATH etc., drop secrets the server never needs."""
    env = dict(os.environ)
    for key in _MCP_ENV_STRIP:
        env.pop(key, None)
    return env


def mcp_stdio_read_timeout_seconds() -> float:
    """Seconds the MCP *client* waits for each stdio JSON-RPC response (ADK ``StdioConnectionParams.timeout``).

    For stdio, Google ADK passes this value as ``ClientSession.read_timeout_seconds``.
    Long-running tools (e.g. multi-minute audits) must finish *one* MCP request/response
    within this window or the client stops waiting and surfaces a timeout.

    Override with env ``GFIBER_MCP_STDIO_READ_TIMEOUT_SEC`` (float, seconds). Minimum 5.
    Default 900 (15 minutes) so 5–10 minute audits are covered with margin.
    """
    raw = os.environ.get("GFIBER_MCP_STDIO_READ_TIMEOUT_SEC", "").strip()
    if not raw:
        return 900.0
    try:
        return max(5.0, float(raw))
    except ValueError:
        return 900.0


# --- Model Rotation & Fallback Patching ---
import functools
import logging
from google.genai.models import Models, AsyncModels
from google.genai.errors import APIError

rotation_logger = logging.getLogger("gfiber.adk.model_rotation")

# A mapping of models to their fallback models when busy (429/503/etc)
MODEL_FALLBACK_MAP = {
    "gemini-2.5-pro": "gemini-2.5-flash",
    "gemini-2.0-pro-exp-02-05": "gemini-2.5-flash",
    "gemini-1.5-pro": "gemini-1.5-flash",
}

def _get_fallback_model(model_name: str) -> str | None:
    # Normalize model name to check fallback
    for key, fallback in MODEL_FALLBACK_MAP.items():
        if key in model_name:
            return fallback
    # Default fallback if not matched but is a pro model
    if "pro" in model_name:
        return "gemini-2.5-flash"
    return None

def _patch_sync_method(original_method):
    @functools.wraps(original_method)
    def wrapper(self, *args, **kwargs):
        model_val = None
        args_list = list(args)
        if len(args_list) > 0:
            model_val = args_list[0]
        elif "model" in kwargs:
            model_val = kwargs["model"]
            
        try:
            return original_method(self, *args, **kwargs)
        except APIError as e:
            if e.code in (429, 503, 504) and model_val:
                fallback = _get_fallback_model(model_val)
                if fallback:
                    rotation_logger.warning(
                        f"Model '{model_val}' is busy/rate-limited (Error {e.code}). "
                        f"Rotating/falling back to '{fallback}'..."
                    )
                    print(
                        f"\n[Model Rotation] Warning: '{model_val}' is busy (Error {e.code}). "
                        f"Falling back to '{fallback}'...",
                        flush=True
                    )
                    if len(args_list) > 0:
                        args_list[0] = fallback
                        return original_method(self, *args_list, **kwargs)
                    else:
                        kwargs["model"] = fallback
                        return original_method(self, *args, **kwargs)
            raise e
    return wrapper

def _patch_sync_generator_method(original_method):
    @functools.wraps(original_method)
    def wrapper(self, *args, **kwargs):
        model_val = None
        args_list = list(args)
        if len(args_list) > 0:
            model_val = args_list[0]
        elif "model" in kwargs:
            model_val = kwargs["model"]

        fallback_used = False

        def generator_wrapper():
            nonlocal fallback_used
            try:
                gen = original_method(self, *args, **kwargs)
                for chunk in gen:
                    yield chunk
            except APIError as e:
                if e.code in (429, 503, 504) and model_val and not fallback_used:
                    fallback = _get_fallback_model(model_val)
                    if fallback:
                        rotation_logger.warning(
                            f"Model '{model_val}' is busy/rate-limited (Error {e.code}) during stream. "
                            f"Rotating/falling back to '{fallback}'..."
                        )
                        print(
                            f"\n[Model Rotation] Warning: '{model_val}' is busy (Error {e.code}) during stream. "
                            f"Falling back to '{fallback}'...",
                            flush=True
                        )
                        fallback_used = True
                        if len(args_list) > 0:
                            args_list[0] = fallback
                            new_gen = original_method(self, *args_list, **kwargs)
                        else:
                            kwargs["model"] = fallback
                            new_gen = original_method(self, *args, **kwargs)
                        for chunk in new_gen:
                            yield chunk
                        return
                raise e

        return generator_wrapper()
    return wrapper

def _patch_async_method(original_method):
    @functools.wraps(original_method)
    async def wrapper(self, *args, **kwargs):
        model_val = None
        args_list = list(args)
        if len(args_list) > 0:
            model_val = args_list[0]
        elif "model" in kwargs:
            model_val = kwargs["model"]
            
        try:
            return await original_method(self, *args, **kwargs)
        except APIError as e:
            if e.code in (429, 503, 504) and model_val:
                fallback = _get_fallback_model(model_val)
                if fallback:
                    rotation_logger.warning(
                        f"Model '{model_val}' is busy/rate-limited (Error {e.code}). "
                        f"Rotating/falling back to '{fallback}'..."
                    )
                    print(
                        f"\n[Model Rotation] Warning: '{model_val}' is busy (Error {e.code}). "
                        f"Falling back to '{fallback}'...",
                        flush=True
                    )
                    if len(args_list) > 0:
                        args_list[0] = fallback
                        return await original_method(self, *args_list, **kwargs)
                    else:
                        kwargs["model"] = fallback
                        return await original_method(self, *args, **kwargs)
            raise e
    return wrapper

def _patch_async_generator_method(original_method):
    @functools.wraps(original_method)
    async def wrapper(self, *args, **kwargs):
        model_val = None
        args_list = list(args)
        if len(args_list) > 0:
            model_val = args_list[0]
        elif "model" in kwargs:
            model_val = kwargs["model"]

        fallback_used = False

        async def generator_wrapper():
            nonlocal fallback_used
            try:
                gen = await original_method(self, *args, **kwargs)
                async for chunk in gen:
                    yield chunk
            except APIError as e:
                if e.code in (429, 503, 504) and model_val and not fallback_used:
                    fallback = _get_fallback_model(model_val)
                    if fallback:
                        rotation_logger.warning(
                            f"Model '{model_val}' is busy/rate-limited (Error {e.code}) during stream. "
                            f"Rotating/falling back to '{fallback}'..."
                        )
                        print(
                            f"\n[Model Rotation] Warning: '{model_val}' is busy (Error {e.code}) during stream. "
                            f"Falling back to '{fallback}'...",
                            flush=True
                        )
                        fallback_used = True
                        if len(args_list) > 0:
                            args_list[0] = fallback
                            new_gen = await original_method(self, *args_list, **kwargs)
                        else:
                            kwargs["model"] = fallback
                            new_gen = await original_method(self, *args, **kwargs)
                        async for chunk in new_gen:
                            yield chunk
                        return
                raise e

        return generator_wrapper()
    return wrapper

try:
    Models.generate_content = _patch_sync_method(Models.generate_content)
    Models.generate_content_stream = _patch_sync_generator_method(Models.generate_content_stream)
    AsyncModels.generate_content = _patch_async_method(AsyncModels.generate_content)
    AsyncModels.generate_content_stream = _patch_async_generator_method(AsyncModels.generate_content_stream)
    rotation_logger.info("Successfully patched google-genai Models and AsyncModels for model rotation/fallback.")
except Exception as patch_err:
    rotation_logger.error(f"Failed to patch google-genai models for rotation: {patch_err}")

