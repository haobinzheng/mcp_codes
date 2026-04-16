import asyncio
import os
import queue
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

from flask import Flask, jsonify, render_template_string, request

import client_inmemory_v2 as cli


WEB_HOST = os.environ.get("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))
SESSION_IDLE_TTL_SECONDS = int(os.environ.get("WEB_SESSION_TTL_SECONDS", "7200"))

app = Flask(__name__)


HTML_PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GFiber In-Memory Agent v2</title>
  <style>
    :root {
      --bg: #f4f1e8;
      --panel: #fffdf8;
      --ink: #16213a;
      --muted: #68758c;
      --accent: #0f6b5b;
      --accent-2: #d97b2d;
      --border: #d6d0c2;
    }
    body {
      margin: 0;
      font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(217,123,45,0.16), transparent 28%),
        linear-gradient(135deg, #f1ece1 0%, var(--bg) 50%, #efe7d7 100%);
      min-height: 100vh;
    }
    .shell {
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px 20px 32px;
    }
    .hero {
      display: grid;
      grid-template-columns: 1.4fr 1fr;
      gap: 18px;
      margin-bottom: 18px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: 0 18px 40px rgba(21, 32, 58, 0.08);
    }
    .hero-main {
      padding: 22px 24px;
    }
    .hero-main h1 {
      margin: 0 0 8px;
      font-size: 30px;
      line-height: 1.1;
      letter-spacing: -0.02em;
    }
    .hero-main p {
      margin: 0;
      color: var(--muted);
      line-height: 1.5;
    }
    .hero-side {
      padding: 20px 22px;
      display: grid;
      gap: 10px;
    }
    .meta {
      font-size: 13px;
      color: var(--muted);
      word-break: break-all;
    }
    .layout {
      display: grid;
      grid-template-columns: 1.2fr 0.95fr;
      gap: 18px;
    }
    .conversation {
      min-height: 640px;
      display: flex;
      flex-direction: column;
    }
    .conversation-header, .composer-header {
      padding: 16px 18px 10px;
      border-bottom: 1px solid rgba(214,208,194,0.7);
      font-weight: 600;
    }
    #messages {
      padding: 16px 18px 18px;
      overflow-y: auto;
      flex: 1;
      min-height: 520px;
      max-height: 74vh;
    }
    .message {
      margin-bottom: 14px;
      padding: 12px 14px;
      border-radius: 14px;
      white-space: pre-wrap;
      line-height: 1.45;
    }
    .user {
      background: rgba(15, 107, 91, 0.08);
      border: 1px solid rgba(15, 107, 91, 0.16);
    }
    .assistant {
      background: rgba(22, 33, 58, 0.05);
      border: 1px solid rgba(22, 33, 58, 0.08);
    }
    .system {
      background: rgba(217, 123, 45, 0.08);
      border: 1px solid rgba(217, 123, 45, 0.16);
    }
    .composer {
      display: flex;
      flex-direction: column;
      min-height: 640px;
    }
    .composer-body {
      padding: 16px 18px 18px;
      display: grid;
      gap: 12px;
    }
    textarea {
      width: 100%;
      min-height: 440px;
      resize: vertical;
      font: 14px/1.45 Menlo, Consolas, monospace;
      padding: 14px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: #fffefa;
      box-sizing: border-box;
    }
    .button-row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }
    button {
      appearance: none;
      border: none;
      border-radius: 999px;
      padding: 12px 18px;
      font-weight: 600;
      cursor: pointer;
    }
    .primary {
      background: var(--accent);
      color: white;
    }
    .secondary {
      background: #ebe6d8;
      color: var(--ink);
    }
    .warning {
      background: var(--accent-2);
      color: white;
    }
    #status {
      font-size: 13px;
      color: var(--muted);
      min-height: 18px;
    }
    @media (max-width: 980px) {
      .hero, .layout {
        grid-template-columns: 1fr;
      }
      textarea {
        min-height: 320px;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="hero">
      <section class="card hero-main">
        <h1>GFiber In-Memory Agent v2</h1>
        <p>
          This browser client runs on the remote VM, keeps the v2 CLI logic unchanged,
          and gives you a large prompt editor for big command outputs and SR OS configuration blocks.
        </p>
      </section>
      <aside class="card hero-side">
        <div class="meta"><strong>Session</strong><br><span id="session-id">Starting...</span></div>
        <div class="meta"><strong>Model</strong><br><span id="model-id">{{ model_id }}</span></div>
        <div class="meta"><strong>Server</strong><br><span id="server-path">{{ server_path }}</span></div>
        <div class="meta"><strong>Session Log</strong><br><span id="session-log">Pending...</span></div>
      </aside>
    </div>

    <div class="layout">
      <section class="card conversation">
        <div class="conversation-header">Conversation</div>
        <div id="messages"></div>
      </section>

      <section class="card composer">
        <div class="composer-header">Prompt Editor</div>
        <div class="composer-body">
          <div id="status">Creating browser session...</div>
          <textarea id="prompt" spellcheck="false" placeholder="Paste a normal prompt, raw command output, or SR OS config here."></textarea>
          <div class="button-row">
            <button class="primary" id="send-btn">Send</button>
            <button class="warning" id="flat-btn">Send As Flat SR OS</button>
            <button class="secondary" id="clear-btn">Clear</button>
            <button class="secondary" id="copy-log-btn">Copy Log Path</button>
          </div>
        </div>
      </section>
    </div>
  </div>

  <script>
    let sessionId = "";
    let sessionLog = "";
    const promptEl = document.getElementById("prompt");
    const messagesEl = document.getElementById("messages");
    const statusEl = document.getElementById("status");

    function setStatus(text) {
      statusEl.textContent = text;
    }

    function addMessage(kind, text) {
      const node = document.createElement("div");
      node.className = `message ${kind}`;
      node.textContent = text;
      messagesEl.appendChild(node);
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    async function createSession() {
      const response = await fetch("/api/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
      });
      const data = await response.json();
      sessionId = data.session_id;
      sessionLog = data.session_log_file;
      document.getElementById("session-id").textContent = sessionId;
      document.getElementById("session-log").textContent = sessionLog;
      addMessage("system", "Browser session ready. Use the large editor on the right for normal prompts or pasted config blocks.");
      setStatus("Ready.");
    }

    async function sendPrompt(mode) {
      const prompt = promptEl.value.trim();
      if (!prompt) {
        return;
      }
      addMessage("user", prompt);
      setStatus("Working...");
      promptEl.value = "";
      const response = await fetch("/api/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: sessionId,
          prompt,
          mode
        })
      });
      const data = await response.json();
      if (!response.ok) {
        addMessage("system", data.error || "Request failed.");
        setStatus("Request failed.");
        return;
      }
      if (data.session_log_file) {
        sessionLog = data.session_log_file;
        document.getElementById("session-log").textContent = sessionLog;
      }
      addMessage("assistant", data.answer || "No response received.");
      setStatus("Ready.");
    }

    document.getElementById("send-btn").addEventListener("click", () => sendPrompt("normal"));
    document.getElementById("flat-btn").addEventListener("click", () => sendPrompt("flat-sros"));
    document.getElementById("clear-btn").addEventListener("click", () => {
      promptEl.value = "";
      setStatus("Editor cleared.");
    });
    document.getElementById("copy-log-btn").addEventListener("click", async () => {
      if (!sessionLog) return;
      await navigator.clipboard.writeText(sessionLog);
      setStatus("Log path copied to clipboard.");
    });

    createSession().catch((err) => {
      addMessage("system", `Startup failed: ${err}`);
      setStatus("Startup failed.");
    });
  </script>
</body>
</html>
"""


@dataclass
class SessionReply:
    answer: str
    session_id: str
    session_log_file: str
    turn_id: str


class WebAgentSession:
    def __init__(self) -> None:
        self.browser_session_id = uuid.uuid4().hex[:12]
        self._jobs: queue.Queue = queue.Queue()
        self._thread = threading.Thread(target=self._run_thread, daemon=True)
        self._stopped = threading.Event()
        self.last_used = time.time()
        self.session_log_file = ""
        self.model_id = cli.MODEL_ID
        self.server_path = cli.SERVER_PATH
        self._thread.start()

    def send_prompt(self, prompt: str, mode: str) -> SessionReply:
        self.last_used = time.time()
        reply_queue: queue.Queue = queue.Queue(maxsize=1)
        self._jobs.put({"type": "prompt", "prompt": prompt, "mode": mode, "reply_queue": reply_queue})
        result = reply_queue.get()
        if isinstance(result, Exception):
            raise result
        return result

    def close(self) -> None:
        if self._stopped.is_set():
            return
        self._stopped.set()
        self._jobs.put({"type": "quit"})

    def _run_thread(self) -> None:
        try:
            asyncio.run(self._run_async())
        except Exception as exc:
            while True:
                try:
                    job = self._jobs.get_nowait()
                except queue.Empty:
                    break
                reply_queue = job.get("reply_queue")
                if reply_queue is not None:
                    reply_queue.put(exc)

    async def _run_async(self) -> None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("Set GEMINI_API_KEY before starting the web client.")
        if not os.path.exists(cli.SERVER_PATH):
            raise RuntimeError(f"Server not found at {cli.SERVER_PATH}")

        client = cli.genai.Client(api_key=api_key)
        params = cli.StdioServerParameters(command="python3", args=[cli.SERVER_PATH], env=os.environ.copy())
        cli._ensure_session_log_dir()
        session_id = uuid.uuid4().hex[:12]
        self.session_log_file = os.path.join(cli.SESSION_LOG_DIR, f"session_{session_id}.jsonl")

        async with cli.stdio_client(params) as (read, write):
            async with cli.ClientSession(read, write) as session:
                await session.initialize()
                cli._write_session_log(
                    self.session_log_file,
                    {
                        "client_version": f"{cli.CLIENT_VERSION}-web",
                        "event": "session_started",
                        "model_id": cli.MODEL_ID,
                        "server_path": cli.SERVER_PATH,
                        "server_version": cli.SERVER_VERSION,
                        "session_id": session_id,
                        "timestamp": time.time(),
                    },
                )
                chat = client.aio.chats.create(
                    model=cli.MODEL_ID,
                    config=cli.types.GenerateContentConfig(
                        tools=[session],
                        system_instruction=cli.SYSTEM_INSTRUCTION,
                    ),
                )
                deterministic_state: dict[str, Any] = {}
                session_memory = cli._new_session_memory()

                while True:
                    job = await asyncio.to_thread(self._jobs.get)
                    if job.get("type") == "quit":
                        cli._write_session_log(
                            self.session_log_file,
                            {
                                "event": "session_ended",
                                "reason": "web_session_closed",
                                "session_id": session_id,
                                "timestamp": time.time(),
                            },
                        )
                        return

                    reply_queue = job["reply_queue"]
                    prompt = str(job.get("prompt", "")).strip()
                    mode = str(job.get("mode", "normal"))
                    turn_id = uuid.uuid4().hex[:12]
                    if mode == "flat-sros":
                        prompt = f"convert sros configuration into flat format\n{prompt}"

                    try:
                        reply = await self._process_prompt(
                            session=session,
                            chat=chat,
                            prompt=prompt,
                            session_id=session_id,
                            turn_id=turn_id,
                            deterministic_state=deterministic_state,
                            session_memory=session_memory,
                        )
                        reply_queue.put(
                            SessionReply(
                                answer=reply,
                                session_id=self.browser_session_id,
                                session_log_file=self.session_log_file,
                                turn_id=turn_id,
                            )
                        )
                    except Exception as exc:
                        cli._write_session_log(
                            self.session_log_file,
                            {
                                "error": str(exc),
                                "event": "turn_error",
                                "session_id": session_id,
                                "timestamp": time.time(),
                                "turn_id": turn_id,
                            },
                        )
                        reply_queue.put(exc)

    async def _process_prompt(
        self,
        *,
        session,
        chat,
        prompt: str,
        session_id: str,
        turn_id: str,
        deterministic_state: dict,
        session_memory: dict,
    ) -> str:
        cli._write_session_log(
            self.session_log_file,
            {
                "event": "user_prompt",
                "prompt": prompt,
                "session_id": session_id,
                "timestamp": time.time(),
                "turn_id": turn_id,
            },
        )
        cli._remember_user_prompt(session_memory, prompt)

        deterministic_response = await cli._handle_deterministic_audit_summary(
            session,
            chat,
            self.session_log_file,
            session_id,
            turn_id,
            prompt,
            deterministic_state,
            session_memory,
        )
        if deterministic_response is None:
            deterministic_response = await cli._handle_deterministic_bng_config_collection(
                session,
                self.session_log_file,
                session_id,
                turn_id,
                prompt,
                session_memory,
            )
        if deterministic_response is None:
            deterministic_response = await cli._handle_deterministic_flat_sros(
                session,
                self.session_log_file,
                session_id,
                turn_id,
                prompt,
                session_memory,
            )
        if deterministic_response is None:
            deterministic_response = await cli._handle_deterministic_ping(
                session,
                self.session_log_file,
                session_id,
                turn_id,
                prompt,
                session_memory,
            )
        if deterministic_response is None:
            deterministic_response = await cli._handle_deterministic_hardware_count(
                session,
                self.session_log_file,
                session_id,
                turn_id,
                prompt,
                deterministic_state,
                session_memory,
            )
        if deterministic_response is not None:
            cli._write_session_log(
                self.session_log_file,
                {
                    "event": "model_answer",
                    "response": deterministic_response,
                    "session_id": session_id,
                    "timestamp": time.time(),
                    "turn_id": turn_id,
                },
            )
            return deterministic_response

        enriched_prompt = (
            f"{cli._build_memory_context(session_memory)}\n\n"
            f"Current user request:\n{prompt}"
        )
        response = await chat.send_message(enriched_prompt)

        for _ in range(cli.MAX_TOOL_LOOPS):
            if not response.candidates or not response.candidates[0].content:
                break

            parts = response.candidates[0].content.parts
            if not parts:
                break

            tool_calls = [part.function_call for part in parts if part.function_call]
            if not tool_calls:
                break

            tool_responses = []
            for call in tool_calls:
                result = await cli._call_tool_logged(
                    session,
                    self.session_log_file,
                    session_id,
                    turn_id,
                    call.name,
                    dict(call.args),
                )
                result_text = cli._tool_result_text(result)
                try:
                    cli._remember_tool_data(session_memory, call.name, cli.json.loads(result_text))
                except Exception:
                    pass
                tool_responses.append(
                    cli.types.Part.from_function_response(
                        name=call.name,
                        response={"result": result_text},
                    )
                )
            response = await chat.send_message(tool_responses)
        else:
            cli._write_session_log(
                self.session_log_file,
                {
                    "event": "tool_loop_limit_reached",
                    "max_tool_loops": cli.MAX_TOOL_LOOPS,
                    "session_id": session_id,
                    "timestamp": time.time(),
                    "turn_id": turn_id,
                },
            )
            return "Stopped after too many consecutive tool loops."

        final_text = response.text or "No model text returned."
        cli._write_session_log(
            self.session_log_file,
            {
                "event": "model_answer",
                "response": final_text,
                "session_id": session_id,
                "timestamp": time.time(),
                "turn_id": turn_id,
            },
        )
        return final_text


SESSIONS: dict[str, WebAgentSession] = {}
SESSIONS_LOCK = threading.Lock()


def _create_session() -> WebAgentSession:
    session = WebAgentSession()
    with SESSIONS_LOCK:
        SESSIONS[session.browser_session_id] = session
    return session


def _get_session(browser_session_id: str) -> WebAgentSession | None:
    with SESSIONS_LOCK:
        session = SESSIONS.get(browser_session_id)
    if session is not None:
        session.last_used = time.time()
    return session


def _cleanup_idle_sessions() -> None:
    now = time.time()
    expired: list[WebAgentSession] = []
    with SESSIONS_LOCK:
        for session_id, session in list(SESSIONS.items()):
            if now - session.last_used > SESSION_IDLE_TTL_SECONDS:
                expired.append(session)
                del SESSIONS[session_id]
    for session in expired:
        session.close()


@app.get("/")
def index():
    return render_template_string(
        HTML_PAGE,
        model_id=cli.MODEL_ID,
        server_path=cli.SERVER_PATH,
    )


@app.post("/api/session")
def api_create_session():
    _cleanup_idle_sessions()
    session = _create_session()
    return jsonify(
        {
            "model_id": session.model_id,
            "server_path": session.server_path,
            "session_id": session.browser_session_id,
            "session_log_file": session.session_log_file or "pending",
        }
    )


@app.post("/api/send")
def api_send():
    payload = request.get_json(silent=True) or {}
    session_id = str(payload.get("session_id", "")).strip()
    prompt = str(payload.get("prompt", "")).strip()
    mode = str(payload.get("mode", "normal")).strip() or "normal"
    if not session_id:
        return jsonify({"error": "Missing session_id."}), 400
    if not prompt:
        return jsonify({"error": "Prompt is empty."}), 400
    if mode not in {"normal", "flat-sros"}:
        return jsonify({"error": "Unsupported mode."}), 400

    session = _get_session(session_id)
    if session is None:
        return jsonify({"error": "Session not found. Refresh the page to start a new session."}), 404

    try:
        reply = session.send_prompt(prompt, mode)
    except Exception as exc:
        return jsonify({"error": str(exc), "session_log_file": session.session_log_file}), 500

    return jsonify(
        {
            "answer": reply.answer,
            "session_id": reply.session_id,
            "session_log_file": reply.session_log_file,
            "turn_id": reply.turn_id,
        }
    )


def main() -> None:
    print(f"GFiber web client listening on http://{WEB_HOST}:{WEB_PORT}")
    print("Use SSH port forwarding from your Mac if the VM is remote.")
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False)


if __name__ == "__main__":
    main()
