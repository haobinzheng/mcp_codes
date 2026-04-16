import asyncio
import os
import queue
import threading
import time
import tkinter as tk
import uuid
from tkinter import messagebox, scrolledtext, ttk

import client_inmemory_v2 as cli


WINDOW_TITLE = "GFiber In-Memory Agent v2 GUI"


class AgentWorker:
    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue
        self.prompt_queue: queue.Queue = queue.Queue()
        self.thread = threading.Thread(target=self._run_thread, daemon=True)
        self._stopped = threading.Event()

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        if self._stopped.is_set():
            return
        self._stopped.set()
        self.prompt_queue.put({"type": "quit"})

    def submit_prompt(self, prompt: str, mode: str = "normal") -> None:
        self.prompt_queue.put({"type": "prompt", "prompt": prompt, "mode": mode})

    def _emit(self, event_type: str, **payload) -> None:
        payload["event"] = event_type
        self.event_queue.put(payload)

    def _run_thread(self) -> None:
        try:
            asyncio.run(self._run_async())
        except Exception as exc:
            self._emit("fatal_error", message=str(exc))

    async def _run_async(self) -> None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            self._emit("fatal_error", message="Set GEMINI_API_KEY before starting the GUI client.")
            return
        if not os.path.exists(cli.SERVER_PATH):
            self._emit("fatal_error", message=f"Server not found at {cli.SERVER_PATH}")
            return

        client = cli.genai.Client(api_key=api_key)
        params = cli.StdioServerParameters(
            command="python3",
            args=[cli.SERVER_PATH],
            env=os.environ.copy(),
        )
        cli._ensure_session_log_dir()
        session_id = uuid.uuid4().hex[:12]
        session_log_file = os.path.join(cli.SESSION_LOG_DIR, f"session_{session_id}.jsonl")

        async with cli.stdio_client(params) as (read, write):
            async with cli.ClientSession(read, write) as session:
                await session.initialize()
                cli._write_session_log(
                    session_log_file,
                    {
                        "client_version": f"{cli.CLIENT_VERSION}-gui",
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
                deterministic_state: dict = {}
                session_memory = cli._new_session_memory()
                self._emit(
                    "ready",
                    session_id=session_id,
                    session_log_file=session_log_file,
                    server_path=cli.SERVER_PATH,
                    model_id=cli.MODEL_ID,
                )

                while True:
                    job = await asyncio.to_thread(self.prompt_queue.get)
                    if job.get("type") == "quit":
                        cli._write_session_log(
                            session_log_file,
                            {
                                "event": "session_ended",
                                "reason": "gui_exit",
                                "session_id": session_id,
                                "timestamp": time.time(),
                            },
                        )
                        return
                    if job.get("type") != "prompt":
                        continue

                    prompt = str(job.get("prompt", "")).strip()
                    if not prompt:
                        continue
                    mode = job.get("mode", "normal")
                    if mode == "flat-sros":
                        prompt = f"convert sros configuration into flat format\n{prompt}"

                    turn_id = uuid.uuid4().hex[:12]
                    self._emit("user_prompt", prompt=prompt, turn_id=turn_id)
                    cli._write_session_log(
                        session_log_file,
                        {
                            "event": "user_prompt",
                            "prompt": prompt,
                            "session_id": session_id,
                            "timestamp": time.time(),
                            "turn_id": turn_id,
                        },
                    )
                    cli._remember_user_prompt(session_memory, prompt)

                    try:
                        deterministic_response = await cli._handle_deterministic_audit_summary(
                            session,
                            chat,
                            session_log_file,
                            session_id,
                            turn_id,
                            prompt,
                            deterministic_state,
                            session_memory,
                        )
                        if deterministic_response is None:
                            deterministic_response = await cli._handle_deterministic_bng_config_collection(
                                session,
                                session_log_file,
                                session_id,
                                turn_id,
                                prompt,
                                session_memory,
                            )
                        if deterministic_response is None:
                            deterministic_response = await cli._handle_deterministic_flat_sros(
                                session,
                                session_log_file,
                                session_id,
                                turn_id,
                                prompt,
                                session_memory,
                            )
                        if deterministic_response is None:
                            deterministic_response = await cli._handle_deterministic_ping(
                                session,
                                session_log_file,
                                session_id,
                                turn_id,
                                prompt,
                                session_memory,
                            )
                        if deterministic_response is None:
                            deterministic_response = await cli._handle_deterministic_hardware_count(
                                session,
                                session_log_file,
                                session_id,
                                turn_id,
                                prompt,
                                deterministic_state,
                                session_memory,
                            )
                        if deterministic_response is not None:
                            cli._write_session_log(
                                session_log_file,
                                {
                                    "event": "model_answer",
                                    "response": deterministic_response,
                                    "session_id": session_id,
                                    "timestamp": time.time(),
                                    "turn_id": turn_id,
                                },
                            )
                            self._emit("assistant_answer", response=deterministic_response, turn_id=turn_id)
                            continue

                        enriched_prompt = (
                            f"{cli._build_memory_context(session_memory)}\n\n"
                            f"Current user request:\n{prompt}"
                        )
                        self._emit("status", message="Sending request to model...")
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
                                self._emit("status", message=f"Server executing: {call.name}")
                                result = await cli._call_tool_logged(
                                    session,
                                    session_log_file,
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
                                session_log_file,
                                {
                                    "event": "tool_loop_limit_reached",
                                    "max_tool_loops": cli.MAX_TOOL_LOOPS,
                                    "session_id": session_id,
                                    "timestamp": time.time(),
                                    "turn_id": turn_id,
                                },
                            )
                            self._emit(
                                "assistant_answer",
                                response="Stopped after too many consecutive tool loops.",
                                turn_id=turn_id,
                            )
                            continue

                        if response.text:
                            cli._write_session_log(
                                session_log_file,
                                {
                                    "event": "model_answer",
                                    "response": response.text,
                                    "session_id": session_id,
                                    "timestamp": time.time(),
                                    "turn_id": turn_id,
                                },
                            )
                            self._emit("assistant_answer", response=response.text, turn_id=turn_id)
                        else:
                            self._emit("assistant_answer", response="No model text returned.", turn_id=turn_id)
                    except Exception as exc:
                        cli._write_session_log(
                            session_log_file,
                            {
                                "error": str(exc),
                                "event": "turn_error",
                                "session_id": session_id,
                                "timestamp": time.time(),
                                "turn_id": turn_id,
                            },
                        )
                        self._emit("turn_error", message=str(exc), turn_id=turn_id)


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(WINDOW_TITLE)
        self.root.geometry("1200x820")

        self.event_queue: queue.Queue = queue.Queue()
        self.worker = AgentWorker(self.event_queue)

        self.status_var = tk.StringVar(value="Starting GUI client...")
        self.session_var = tk.StringVar(value="Session: starting")
        self.log_var = tk.StringVar(value="Log: pending")

        self._build_ui()
        self.worker.start()
        self.root.after(150, self._drain_events)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        self.root.rowconfigure(1, weight=1)
        self.root.rowconfigure(2, weight=1)
        self.root.columnconfigure(0, weight=1)

        header = ttk.Frame(self.root, padding=10)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text="GFiber In-Memory Agent v2 GUI", font=("Helvetica", 16, "bold")).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(header, textvariable=self.session_var).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Label(header, textvariable=self.log_var).grid(row=2, column=0, sticky="w")
        ttk.Label(header, textvariable=self.status_var).grid(row=3, column=0, sticky="w", pady=(6, 0))

        conversation_frame = ttk.LabelFrame(self.root, text="Conversation", padding=8)
        conversation_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 8))
        conversation_frame.rowconfigure(0, weight=1)
        conversation_frame.columnconfigure(0, weight=1)

        self.conversation = scrolledtext.ScrolledText(conversation_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.conversation.grid(row=0, column=0, sticky="nsew")

        composer_frame = ttk.LabelFrame(self.root, text="Prompt Editor", padding=8)
        composer_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))
        composer_frame.rowconfigure(0, weight=1)
        composer_frame.columnconfigure(0, weight=1)

        self.input_text = scrolledtext.ScrolledText(composer_frame, wrap=tk.WORD, height=16)
        self.input_text.grid(row=0, column=0, columnspan=4, sticky="nsew")

        ttk.Button(composer_frame, text="Send", command=self._send_normal).grid(
            row=1, column=0, sticky="ew", pady=(8, 0), padx=(0, 6)
        )
        ttk.Button(composer_frame, text="Send As Flat SR OS", command=self._send_flat_sros).grid(
            row=1, column=1, sticky="ew", pady=(8, 0), padx=6
        )
        ttk.Button(composer_frame, text="Clear Input", command=self._clear_input).grid(
            row=1, column=2, sticky="ew", pady=(8, 0), padx=6
        )
        ttk.Button(composer_frame, text="Copy Log Path", command=self._copy_log_path).grid(
            row=1, column=3, sticky="ew", pady=(8, 0), padx=(6, 0)
        )

    def _append_conversation(self, speaker: str, text: str) -> None:
        self.conversation.configure(state=tk.NORMAL)
        self.conversation.insert(tk.END, f"{speaker}:\n{text}\n\n")
        self.conversation.see(tk.END)
        self.conversation.configure(state=tk.DISABLED)

    def _current_input(self) -> str:
        return self.input_text.get("1.0", tk.END).strip()

    def _clear_input(self) -> None:
        self.input_text.delete("1.0", tk.END)

    def _copy_log_path(self) -> None:
        log_text = self.log_var.get().replace("Log: ", "", 1).strip()
        if not log_text or log_text == "pending":
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(log_text)
        self.status_var.set("Log path copied to clipboard.")

    def _send_normal(self) -> None:
        prompt = self._current_input()
        if not prompt:
            return
        self.status_var.set("Queued prompt.")
        self.worker.submit_prompt(prompt, mode="normal")
        self._clear_input()

    def _send_flat_sros(self) -> None:
        prompt = self._current_input()
        if not prompt:
            return
        self.status_var.set("Queued SR OS flatten prompt.")
        self.worker.submit_prompt(prompt, mode="flat-sros")
        self._clear_input()

    def _drain_events(self) -> None:
        try:
            while True:
                event = self.event_queue.get_nowait()
                event_type = event.get("event")
                if event_type == "ready":
                    self.session_var.set(f'Session: {event.get("session_id", "")} | Model: {event.get("model_id", "")}')
                    self.log_var.set(f'Log: {event.get("session_log_file", "")}')
                    self.status_var.set("Ready.")
                    self._append_conversation(
                        "SYSTEM",
                        "GUI client ready.\n"
                        f'Session log: {event.get("session_log_file", "")}\n'
                        "Use the large editor below for long prompts or pasted configuration blocks.",
                    )
                elif event_type == "user_prompt":
                    self._append_conversation("USER", event.get("prompt", ""))
                    self.status_var.set("Prompt sent.")
                elif event_type == "assistant_answer":
                    self._append_conversation("AI", event.get("response", ""))
                    self.status_var.set("Response received.")
                elif event_type == "status":
                    self.status_var.set(event.get("message", "Working..."))
                elif event_type == "turn_error":
                    self._append_conversation("ERROR", event.get("message", "Unknown error"))
                    self.status_var.set("Request failed.")
                elif event_type == "fatal_error":
                    self.status_var.set("Startup failed.")
                    messagebox.showerror("GFiber GUI Client", event.get("message", "Unknown startup failure"))
                else:
                    self.status_var.set("Idle.")
        except queue.Empty:
            pass
        self.root.after(150, self._drain_events)

    def _on_close(self) -> None:
        self.worker.stop()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    style = ttk.Style()
    if "clam" in style.theme_names():
        style.theme_use("clam")
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
