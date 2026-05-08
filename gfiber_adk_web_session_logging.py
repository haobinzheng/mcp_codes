"""Session logging for ADK Web (``google.adk.cli web``) using an ``App``-level plugin.

Writes append-only JSONL (and a human-readable ``.log``) under ``session_logs/``,
similar to ``client_inmemory_v2_google_adk.py``, but keyed by ADK session id:

  ``session_logs/adk_web_session_<session_id>.jsonl``

Disable with ``GFIBER_ADK_WEB_SESSION_LOG_DISABLE=1``.
Override directory with ``SESSION_LOG_DIR`` (same as the stdio client).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import traceback
from typing import Any

from google.adk.plugins.base_plugin import BasePlugin
from google.genai import types

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_LOG_DIR = os.path.join(_REPO_ROOT, "session_logs")

_TOOL_RESULT_MAX_CHARS = int(os.environ.get("GFIBER_ADK_WEB_TOOL_LOG_MAX_CHARS", "120000"))
_MODEL_TEXT_MAX_CHARS = int(os.environ.get("GFIBER_ADK_WEB_MODEL_LOG_MAX_CHARS", "200000"))


def _truncate(s: str, max_len: int) -> str:
    s = s.replace("\r\n", "\n")
    if len(s) <= max_len:
        return s
    return s[:max_len] + f"... ({len(s)} chars total)"


def _content_text(content: types.Content | None) -> str:
    if not content or not content.parts:
        return ""
    chunks: list[str] = []
    for part in content.parts:
        t = getattr(part, "text", None) or ""
        if t:
            chunks.append(t)
    return "\n".join(chunks).strip()


class AdkWebSessionRecorder:
    """Append-only JSONL plus plain-text log for one ADK browser session."""

    def __init__(self, *, session_id: str, app_name: str, jsonl_path: str) -> None:
        self.session_id = session_id
        self.app_name = app_name
        self.jsonl_path = jsonl_path
        self.text_log_path = (
            jsonl_path[:-6] + ".log" if jsonl_path.endswith(".jsonl") else jsonl_path + ".log"
        )
        level_name = os.environ.get("GFIBER_SESSION_LOG_LEVEL", "INFO").upper()
        level = getattr(logging, level_name, logging.INFO)
        self._logger = logging.getLogger(f"gfiber.adk_web.session.{session_id}")
        self._logger.handlers.clear()
        self._logger.setLevel(level)
        self._logger.propagate = False
        fmt = logging.Formatter(
            fmt="%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        fh = logging.FileHandler(self.text_log_path, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(fmt)
        self._logger.addHandler(fh)
        if os.environ.get("GFIBER_LOG_CONSOLE", "").lower() in ("1", "true", "yes"):
            ch = logging.StreamHandler()
            ch.setLevel(level)
            ch.setFormatter(fmt)
            self._logger.addHandler(ch)
        self._write_lock = threading.Lock()

    def _format_text_row(self, row: dict[str, Any]) -> str:
        ev = row.get("event", "?")
        bits: list[str] = [str(ev), f"source=adk_web"]
        for key in (
            "turn_id",
            "invocation_id",
            "tool_name",
            "error",
            "exc_type",
            "partial",
            "turn_complete",
            "error_code",
            "mcp_is_error",
            "app_name",
        ):
            if key in row and row[key] is not None:
                bits.append(f"{key}={row[key]}")
        if "prompt" in row:
            p = str(row["prompt"])
            bits.append(f"prompt_len={len(p)}")
            bits.append(f"prompt_preview={_truncate(p, 240)!r}")
        if "response" in row:
            r = str(row["response"])
            bits.append(f"response_len={len(r)}")
            bits.append(f"response_preview={_truncate(r, 500)!r}")
        if "args" in row and row["args"] is not None:
            bits.append(f"args={_truncate(json.dumps(row['args'], default=str), 800)}")
        if "result" in row and row["result"] is not None:
            r = str(row["result"])
            bits.append(f"result_len={len(r)}")
            bits.append(f"result_preview={_truncate(r, 600)!r}")
        if "traceback" in row and row["traceback"]:
            bits.append(f"traceback={_truncate(str(row['traceback']), 800)!r}")
        return " | ".join(bits)

    def record(self, **fields: Any) -> None:
        if "event" not in fields:
            raise ValueError("AdkWebSessionRecorder.record() requires event=...")
        row: dict[str, Any] = {
            "session_id": self.session_id,
            "app_name": self.app_name,
            "source": "adk_web",
            "timestamp": time.time(),
            **fields,
        }
        line = json.dumps(row, sort_keys=True, default=str) + "\n"
        with self._write_lock:
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(line)
        self._logger.info(self._format_text_row(row))


class GfiberAdkWebSessionLogPlugin(BasePlugin):
    """Logs user prompts, tool I/O, model steps, and errors for ADK Web."""

    def __init__(self) -> None:
        super().__init__(name="gfiber_adk_web_session_log")
        log_root = os.environ.get("SESSION_LOG_DIR", _DEFAULT_LOG_DIR)
        os.makedirs(log_root, exist_ok=True)
        self._log_root = log_root
        self._recorders: dict[str, AdkWebSessionRecorder] = {}
        self._rec_lock = threading.Lock()

    def _disabled(self) -> bool:
        return os.environ.get("GFIBER_ADK_WEB_SESSION_LOG_DISABLE", "").lower() in (
            "1",
            "true",
            "yes",
            "on",
        )

    def _get_recorder(self, *, session_id: str, app_name: str) -> AdkWebSessionRecorder | None:
        if self._disabled():
            return None
        with self._rec_lock:
            existing = self._recorders.get(session_id)
            if existing:
                return existing
            jsonl_path = os.path.join(self._log_root, f"adk_web_session_{session_id}.jsonl")
            rec = AdkWebSessionRecorder(session_id=session_id, app_name=app_name, jsonl_path=jsonl_path)
            self._recorders[session_id] = rec
            rec.record(
                event="session_started",
                framework="google-adk-web",
                jsonl_path=rec.jsonl_path,
                text_log_path=rec.text_log_path,
            )
            return rec

    async def before_run_callback(self, *, invocation_context) -> Any:
        """Ensure a recorder exists; log per-invocation boundary."""
        if self._disabled():
            return None
        sess = invocation_context.session
        rec = self._get_recorder(session_id=sess.id, app_name=sess.app_name)
        if rec:
            rec.record(
                event="invocation_start",
                invocation_id=invocation_context.invocation_id,
                user_id=getattr(sess, "user_id", None),
            )
        return None

    async def on_user_message_callback(self, *, invocation_context, user_message) -> Any:
        rec = self._get_recorder(
            session_id=invocation_context.session.id,
            app_name=invocation_context.session.app_name,
        )
        if not rec:
            return None
        text = _content_text(user_message)
        rec.record(
            event="user_prompt",
            turn_id=invocation_context.invocation_id,
            invocation_id=invocation_context.invocation_id,
            prompt=text,
        )
        return None

    async def before_tool_callback(self, *, tool, tool_args, tool_context) -> Any:
        rec = self._get_recorder(
            session_id=tool_context.invocation_context.session.id,
            app_name=tool_context.invocation_context.session.app_name,
        )
        if not rec:
            return None
        name = getattr(tool, "name", "") or ""
        rec.record(
            event="tool_call",
            turn_id=tool_context.invocation_id,
            invocation_id=tool_context.invocation_id,
            tool_name=name,
            args=dict(tool_args) if isinstance(tool_args, dict) else {"_raw": str(tool_args)},
        )
        return None

    async def after_tool_callback(self, *, tool, tool_args, tool_context, result) -> Any:
        rec = self._get_recorder(
            session_id=tool_context.invocation_context.session.id,
            app_name=tool_context.invocation_context.session.app_name,
        )
        if not rec:
            return None
        name = getattr(tool, "name", "") or ""
        try:
            payload = json.dumps(result, default=str)
        except TypeError:
            payload = str(result)
        row: dict[str, Any] = {
            "event": "tool_result",
            "turn_id": tool_context.invocation_id,
            "invocation_id": tool_context.invocation_id,
            "tool_name": name,
            "result": _truncate(payload, _TOOL_RESULT_MAX_CHARS),
        }
        if isinstance(result, dict) and "isError" in result:
            row["mcp_is_error"] = result.get("isError")
        rec.record(**row)
        return None

    async def on_tool_error_callback(self, *, tool, tool_args, tool_context, error) -> Any:
        rec = self._get_recorder(
            session_id=tool_context.invocation_context.session.id,
            app_name=tool_context.invocation_context.session.app_name,
        )
        if not rec:
            return None
        name = getattr(tool, "name", "") or ""
        rec.record(
            event="tool_error",
            turn_id=tool_context.invocation_id,
            invocation_id=tool_context.invocation_id,
            tool_name=name,
            error=str(error),
            exc_type=type(error).__name__,
            traceback=traceback.format_exc(),
        )
        return None

    async def after_model_callback(self, *, callback_context, llm_response) -> Any:
        rec = self._get_recorder(
            session_id=callback_context.session.id,
            app_name=callback_context.session.app_name,
        )
        if not rec:
            return None
        text = _content_text(llm_response.content)
        err_code = getattr(llm_response, "error_code", None)
        err_msg = getattr(llm_response, "error_message", None)
        rec.record(
            event="model_response",
            turn_id=callback_context.invocation_id,
            invocation_id=callback_context.invocation_id,
            response=_truncate(text, _MODEL_TEXT_MAX_CHARS),
            partial=getattr(llm_response, "partial", None),
            turn_complete=getattr(llm_response, "turn_complete", None),
            error_code=err_code,
            error_message=err_msg,
        )
        return None

    async def on_model_error_callback(self, *, callback_context, llm_request, error) -> Any:
        rec = self._get_recorder(
            session_id=callback_context.session.id,
            app_name=callback_context.session.app_name,
        )
        if not rec:
            return None
        rec.record(
            event="turn_error",
            turn_id=callback_context.invocation_id,
            invocation_id=callback_context.invocation_id,
            error=str(error),
            exc_type=type(error).__name__,
            traceback=traceback.format_exc(),
        )
        return None

    async def after_run_callback(self, *, invocation_context) -> None:
        if self._disabled():
            return
        rec = self._recorders.get(invocation_context.session.id)
        if not rec:
            return
        rec.record(
            event="invocation_complete",
            invocation_id=invocation_context.invocation_id,
        )
