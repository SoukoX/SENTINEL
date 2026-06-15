"""
SENTINEL — AI Intelligence Layer

LLMProvider with unified function calling across all 5 backends.
Supports Ollama, Groq, OpenRouter, and OpenCode Zen.
Features: rate limiting, token estimation, input truncation,
retry with exponential backoff.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Callable


# ─────────────────────────────────────────────
# DATA TYPES
# ─────────────────────────────────────────────

@dataclass
class LLMMessage:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    tool_calls: list[dict] | None = None
    tool_call_id: str | None = None
    name: str | None = None


@dataclass
class LLMResult:
    content: str
    tool_calls: list[dict] | None = None
    finish_reason: str = "stop"
    usage: dict | None = None
    backend: str = ""


@dataclass
class BackendConfig:
    name: str
    api_key: str | None = None
    model: str = ""
    base_url: str = ""
    rpm: int = 10
    supports_tools: bool = True
    fallback_models: list[str] | None = None


# ─────────────────────────────────────────────
# TOKEN ESTIMATOR
# ─────────────────────────────────────────────

# Cache for tiktoken if available
_tiktoken_enc = None

def _get_tokenizer():
    global _tiktoken_enc
    if _tiktoken_enc is not None:
        return _tiktoken_enc
    try:
        import tiktoken
        _tiktoken_enc = tiktoken.get_encoding("cl100k_base")
    except Exception:
        _tiktoken_enc = False
    return _tiktoken_enc


def estimate_tokens(text: str) -> int:
    """Estimate token count using tiktoken if available, fallback to ~4 chars/token."""
    enc = _get_tokenizer()
    if enc:
        try:
            return len(enc.encode(text))
        except Exception:
            pass
    return max(1, len(text) // 4)


def truncate_messages(messages: list, max_input_tokens: int = 64000) -> list:
    """
    Truncate message history to stay within token budget.
    Preserves system message and most recent messages, drops oldest.
    """
    total = 0
    # First pass: count tokens for each message
    counted = []
    for m in reversed(messages):
        content = m.content if hasattr(m, 'content') else (isinstance(m, dict) and m.get('content', '')) or str(m)
        tokens = estimate_tokens(content) + 10  # +10 for message overhead
        counted.append((m, tokens))

    # If within budget, return as-is
    if sum(t for _, t in counted) <= max_input_tokens:
        return messages

    # Always keep system message (first) and most recent messages
    # Find system message
    system_idx = None
    for i, m in enumerate(messages):
        role = m.role if hasattr(m, 'role') else (isinstance(m, dict) and m.get('role', ''))
        if role == 'system':
            system_idx = i
            break

    # Build truncated: system (if exists) + recent messages within budget
    result = []
    budget = max_input_tokens

    if system_idx is not None:
        sys_tokens = estimate_tokens(messages[system_idx].content) + 10
        result.append(messages[system_idx])
        budget -= sys_tokens

    # Add from newest to oldest (excluding system)
    for m in reversed(messages):
        if m is (system_idx is not None and messages[system_idx]):
            continue
        content = m.content if hasattr(m, 'content') else (isinstance(m, dict) and m.get('content', '')) or str(m)
        tokens = estimate_tokens(content) + 10
        if budget - tokens >= 0:
            result.append(m)
            budget -= tokens
        else:
            break

    # Restore chronological order
    if system_idx is not None:
        first = result[0]
        rest = list(reversed(result[1:]))
        return [first] + rest
    return list(reversed(result))


# ─────────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────────

class _SlidingWindowRateLimiter:
    def __init__(self, max_per_minute: int):
        self.max_per_minute = max_per_minute
        self._timestamps: list[float] = []

    def wait_if_needed(self) -> None:
        now = time.time()
        cutoff = now - 60
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self.max_per_minute:
            sleep_time = self._timestamps[0] - cutoff
            if sleep_time > 0:
                time.sleep(sleep_time)
        self._timestamps.append(time.time())


# ─────────────────────────────────────────────
# BACKEND CONFIGURATIONS
# ─────────────────────────────────────────────

BACKENDS: dict[str, BackendConfig] = {
    "ollama": BackendConfig(
        name="ollama",
        base_url=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
        model=os.environ.get("OLLAMA_MODEL", "mistral"),
        rpm=60,
    ),
    "openrouter": BackendConfig(
        name="openrouter",
        api_key=os.environ.get("OPENROUTER_API_KEY"),
        model="google/gemini-2.0-flash-001:free",
        base_url="https://openrouter.ai/api/v1",
        rpm=15,
        fallback_models=[
            "google/gemini-2.0-flash-exp:free",
            "deepseek/deepseek-chat-v3-0324:free",
            "qwen/qwen3-235b-a22b:free",
            "google/gemma-4-31b-it:free",
            "nvidia/nemotron-3-ultra-550b-a55b:free",
            "meta-llama/llama-3.3-70b-instruct:free",
            "mistralai/mistral-small-3.1-24b-instruct:free",
            "nvidia/nemotron-3-super-120b-a12b:free",
        ],
    ),
    "opencode": BackendConfig(
        name="opencode",
        api_key=os.environ.get("OPENCODE_API_KEY"),
        model="deepseek-v4-flash-free",
        base_url="https://opencode.ai/zen/v1",
        rpm=30,
    ),
    "cerebras": BackendConfig(
        name="cerebras",
        api_key=os.environ.get("CEREBRAS_API_KEY"),
        model="llama3.3-70b",
        base_url="https://api.cerebras.ai/v1",
        rpm=30,
        fallback_models=[
            "llama3.1-8b",
            "gpt-oss-120b",
        ],
    ),
}


# ─────────────────────────────────────────────
# BACKEND DETECTION
# ─────────────────────────────────────────────

def reconfigure_backend(name: str, api_key: str | None = None, url: str | None = None) -> bool:
    """Update a backend config in-place at runtime (no importlib.reload needed).
    Call after setting os.environ for the corresponding var, then detect_available_backends()
    will pick up the change because BACKENDS is mutated directly."""
    if name not in BACKENDS:
        return False
    cfg = BACKENDS[name]
    if name == "ollama":
        cfg.base_url = url or os.environ.get("OLLAMA_URL", "http://localhost:11434")
    elif api_key is not None:
        cfg.api_key = api_key
    return True


def detect_available_backends() -> list[BackendConfig]:
    available = []
    for name, cfg in BACKENDS.items():
        if name == "ollama":
            try:
                req = urllib.request.Request(f"{cfg.base_url}/api/tags")
                urllib.request.urlopen(req, timeout=3)
                available.append(cfg)
            except Exception:
                pass
        elif name == "opencode" and cfg.api_key:
            try:
                payload = json.dumps({
                    "model": cfg.model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                }).encode()
                headers = {
                    "Content-Type": "application/json",
                    "User-Agent": "SENTINEL/1.0",
                    "Authorization": f"Bearer {cfg.api_key}",
                }
                req = urllib.request.Request(
                    f"{cfg.base_url.rstrip('/')}/chat/completions",
                    data=payload, headers=headers, method="POST",
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    available.append(cfg)
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    continue
                available.append(cfg)
            except Exception:
                available.append(cfg)
        elif name == "openrouter" and cfg.api_key:
            try:
                req = urllib.request.Request(
                    "https://openrouter.ai/api/v1/auth/key",
                    headers={"Authorization": f"Bearer {cfg.api_key}"},
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    available.append(cfg)
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    continue
                available.append(cfg)
            except Exception:
                available.append(cfg)
        elif name == "cerebras" and cfg.api_key:
            try:
                payload = json.dumps({
                    "model": cfg.model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                }).encode()
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {cfg.api_key}",
                }
                req = urllib.request.Request(
                    f"{cfg.base_url}/chat/completions",
                    data=payload, headers=headers, method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    available.append(cfg)
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    continue
                available.append(cfg)
            except Exception:
                continue
        elif cfg.api_key:
            available.append(cfg)
    return available


# ─────────────────────────────────────────────
# LLM PROVIDER
# ─────────────────────────────────────────────

class LLMProvider:
    # Persistent set of model IDs that returned 404 — never try them again
    _model_404_cache: set[str] = set()
    _404_CACHE_FILE = Path.home() / ".sentinel" / "model_404_cache.json"
    # Persistent set of backend names that returned 429 quota exceeded
    _quota_exceeded_cache: set[str] = set()
    _QUOTA_CACHE_FILE = Path.home() / ".sentinel" / "quota_exceeded_cache.json"

    @classmethod
    def _load_cache(cls):
        for attr, fname in [("_model_404_cache", "_404_CACHE_FILE"),
                            ("_quota_exceeded_cache", "_QUOTA_CACHE_FILE")]:
            if getattr(cls, attr):
                continue
            path = getattr(cls, fname)
            try:
                if path.exists():
                    with open(path) as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            setattr(cls, attr, set(data))
            except Exception:
                pass

    @classmethod
    def _save_cache(cls, attr, fname_attr):
        path = getattr(cls, fname_attr)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as f:
                json.dump(sorted(getattr(cls, attr)), f)
        except Exception:
            pass

    @classmethod
    def _save_404_cache(cls):
        cls._save_cache("_model_404_cache", "_404_CACHE_FILE")

    @classmethod
    def _save_quota_cache(cls):
        cls._save_cache("_quota_exceeded_cache", "_QUOTA_CACHE_FILE")

    def __init__(self, backends: list[BackendConfig] | None = None):
        self.backends = backends or detect_available_backends()
        if not self.backends:
            self.backends = [BACKENDS["ollama"]]
        self._rate_limiters: dict[str, _SlidingWindowRateLimiter] = {}
        for b in self.backends:
            self._rate_limiters[b.name] = _SlidingWindowRateLimiter(b.rpm)
        self._primary = self.backends[0] if self.backends else None
        self._load_cache()
        # Filter out quota-exceeded backends
        self.backends = [b for b in self.backends if b.name not in self._quota_exceeded_cache]

    @property
    def primary(self) -> BackendConfig | None:
        return self._primary

    @property
    def name(self) -> str:
        return self._primary.name if self._primary else "none"

    def chat(self, messages: list[LLMMessage],
             tools: list[dict] | None = None,
             temperature: float = 0.1,
             max_tokens: int = 2000) -> LLMResult:
        if not self.backends:
            return LLMResult(content="No AI backends available", finish_reason="error")

        # Truncate messages to stay within token budget
        trimmed = truncate_messages(messages, max_input_tokens=64000)

        last_error = ""
        for i, backend in enumerate(self.backends):
            limiter = self._rate_limiters.get(backend.name)
            if limiter:
                limiter.wait_if_needed()

            try:
                if backend.name == "ollama":
                    return self._call_openai_compat(backend, trimmed, tools, temperature, max_tokens)
                else:
                    return self._call_openai_compat(backend, trimmed, tools, temperature, max_tokens)
            except Exception as e:
                last_error = str(e)
                if i < len(self.backends) - 1:
                    continue
                break

        return LLMResult(content=f"All backends failed: {last_error}", finish_reason="error")

    def chat_stream(self, messages: list[LLMMessage],
                    tools: list[dict] | None = None,
                    temperature: float = 0.1,
                    max_tokens: int = 2000,
                    on_chunk: Callable[[str], None] | None = None,
                    interrupt_check: Callable[[], bool] | None = None) -> LLMResult:
        if not self.backends:
            return LLMResult(content="No AI backends available", finish_reason="error")

        trimmed = truncate_messages(messages, max_input_tokens=64000)

        last_error = ""
        for i, backend in enumerate(self.backends):
            limiter = self._rate_limiters.get(backend.name)
            if limiter:
                limiter.wait_if_needed()
            try:
                return self._call_openai_compat_stream(
                    backend, trimmed, tools, temperature, max_tokens,
                    on_chunk, interrupt_check,
                )
            except Exception as e:
                last_error = str(e)
                if i < len(self.backends) - 1:
                    continue
                break

        return LLMResult(content=f"All backends failed: {last_error}", finish_reason="error")

    def _call_openai_compat_stream(self, backend: BackendConfig,
                                    messages: list[LLMMessage],
                                    tools: list[dict] | None = None,
                                    temperature: float = 0.1,
                                    max_tokens: int = 2000,
                                    on_chunk: Callable[[str], None] | None = None,
                                    interrupt_check: Callable[[], bool] | None = None) -> LLMResult:
        models_to_try = [backend.model]
        if backend.fallback_models:
            models_to_try.extend(backend.fallback_models)

        last_error = ""
        for model in models_to_try:
            if model in self._model_404_cache:
                continue

            body = {
                "model": model,
                "messages": [self._msg_to_dict(m) for m in messages],
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": True,
            }
            if tools:
                body["tools"] = tools
                body["tool_choice"] = "auto"

            url = f"{backend.base_url.rstrip('/')}/chat/completions"
            data = json.dumps(body).encode()
            headers = {
                "Content-Type": "application/json",
                "Connection": "keep-alive",
            }
            if backend.api_key:
                headers["Authorization"] = f"Bearer {backend.api_key}"

            max_retries = 2
            for attempt in range(max_retries):
                req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                try:
                    resp = urllib.request.urlopen(req, timeout=120)
                    break
                except urllib.error.HTTPError as e:
                    err_body = e.read().decode()
                    if (backend.name == "opencode" and e.code == 403
                            and "1010" in err_body and backend.api_key):
                        zen_url = "https://opencode.ai/zen/v1/chat/completions"
                        for zm in ["deepseek-v4-flash-free", "minimax-m3-free",
                                   "mimo-v2.5-free", "nemotron-3-ultra-free",
                                   "qwen3.6-plus-free", "north-mini-code-free",
                                   "llama-3.3-70b-instruct-free"]:
                            body["model"] = zm
                            data = json.dumps(body).encode()
                            for use_key in [True, False]:
                                h = {"Content-Type": "application/json", "User-Agent": "SENTINEL/1.0",
                                     "Connection": "keep-alive"}
                                if use_key and backend.api_key:
                                    h["Authorization"] = f"Bearer {backend.api_key}"
                                req = urllib.request.Request(zen_url, data=data, headers=h, method="POST")
                                try:
                                    resp = urllib.request.urlopen(req, timeout=120)
                                    break
                                except urllib.error.HTTPError:
                                    continue
                        else:
                            last_error = "opencode: all free models failed via Zen endpoint"
                            break
                    if e.code in (429, 502, 503) and attempt < max_retries - 1:
                        delay = float(e.headers.get("Retry-After", str(min(1.5**attempt, 8.0))))
                        time.sleep(delay)
                        continue
                    if e.code == 404:
                        self._model_404_cache.add(model)
                        self._save_404_cache()
                        break
                    last_error = f"{backend.name} HTTP {e.code}: {err_body[:300]}"
                    break
                except (urllib.error.URLError, TimeoutError) as e:
                    if attempt < max_retries - 1:
                        time.sleep(min(1.5**attempt, 8.0))
                        continue
                    last_error = f"{backend.name} connection failed: {e}"
                    break
            else:
                last_error = f"{backend.name} max retries exceeded"
                break

            if last_error:
                if models_to_try.index(model) < len(models_to_try) - 1:
                    continue
                break

            # ── Parse SSE stream ──
            full_content = ""
            tool_calls_acc: dict[int, dict] = {}
            finish_reason = "stop"
            # Set socket read timeout so readline() doesn't hang forever during interrupt
            try:
                sock = resp.fp.raw._sock if hasattr(resp.fp, 'raw') and hasattr(resp.fp.raw, '_sock') else None
            except Exception:
                sock = None
            orig_timeout = None
            if sock:
                try:
                    orig_timeout = sock.gettimeout()
                    sock.settimeout(5.0)
                except Exception:
                    sock = None
            try:
                while True:
                    if interrupt_check and interrupt_check():
                        resp.close()
                        break
                    try:
                        raw = resp.fp.readline()
                    except OSError:
                        break
                    if not raw:
                        break
                    line = raw.decode().strip()
                    if not line:
                        continue
                    if not line.startswith("data: "):
                        continue
                    payload = line[6:].strip()
                    if payload == "[DONE]":
                        break
                    try:
                        chunk = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    choices = chunk.get("choices", [])
                    if not choices:
                        continue
                    delta = choices[0].get("delta", {})
                    content_delta = delta.get("content")
                    if content_delta:
                        full_content += content_delta
                        if on_chunk:
                            on_chunk(content_delta)
                    tc_delta = delta.get("tool_calls")
                    if tc_delta:
                        for tc in tc_delta:
                            idx = tc.get("index", 0)
                            if idx not in tool_calls_acc:
                                tool_calls_acc[idx] = {
                                    "id": tc.get("id", ""),
                                    "type": "function",
                                    "function": {
                                        "name": tc.get("function", {}).get("name", ""),
                                        "arguments": tc.get("function", {}).get("arguments", ""),
                                    },
                                }
                            else:
                                acc = tool_calls_acc[idx]
                                if tc.get("id"):
                                    acc["id"] = tc["id"]
                                fn = tc.get("function", {})
                                if fn.get("name"):
                                    acc["function"]["name"] = fn["name"]
                                if fn.get("arguments"):
                                    acc["function"]["arguments"] += fn["arguments"]
                    fr = choices[0].get("finish_reason")
                    if fr:
                        finish_reason = fr
            finally:
                if sock and orig_timeout is not None:
                    try:
                        sock.settimeout(orig_timeout)
                    except Exception:
                        pass
                resp.close()

            tool_calls = list(tool_calls_acc.values()) if tool_calls_acc else None
            if tool_calls:
                for tc in tool_calls:
                    try:
                        parsed = json.loads(tc["function"]["arguments"])
                        tc["function"]["arguments"] = json.dumps(parsed)
                    except json.JSONDecodeError:
                        pass

            return LLMResult(
                content=full_content,
                tool_calls=tool_calls,
                finish_reason=finish_reason,
                usage=None,
                backend=backend.name,
            )

        raise RuntimeError(last_error or f"{backend.name} stream failed")

    # ── OpenAI-compatible (Ollama, Groq, OpenRouter, OpenCode) ──

    def _call_openai_compat(self, backend: BackendConfig,
                            messages: list[LLMMessage],
                            tools: list[dict] | None = None,
                            temperature: float = 0.1,
                            max_tokens: int = 2000) -> LLMResult:
        models_to_try = [backend.model]
        if backend.fallback_models:
            models_to_try.extend(backend.fallback_models)

        last_error = ""
        for model in models_to_try:
            # Skip models previously known to return 404
            if model in self._model_404_cache:
                continue

            body = {
                "model": model,
                "messages": [self._msg_to_dict(m) for m in messages],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if tools:
                body["tools"] = tools
                body["tool_choice"] = "auto"

            url = f"{backend.base_url.rstrip('/')}/chat/completions"
            data = json.dumps(body).encode()

            headers = {
                "Content-Type": "application/json",
                "Connection": "keep-alive",
            }
            if backend.api_key:
                headers["Authorization"] = f"Bearer {backend.api_key}"

            # Retry with exponential backoff for rate limits / server errors
            max_retries = 4
            for attempt in range(max_retries):
                req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                try:
                    resp = urllib.request.urlopen(req, timeout=120)
                    result = json.loads(resp.read().decode())
                    choice = result.get("choices", [{}])[0]
                    msg = choice.get("message", {})
                    content = msg.get("content") or ""
                    tool_calls_raw = msg.get("tool_calls")
                    tool_calls = None
                    if tool_calls_raw:
                        tool_calls = []
                        for tc in tool_calls_raw:
                            func = tc.get("function", {})
                            try:
                                parsed_args = json.loads(func.get("arguments", "{}"))
                            except json.JSONDecodeError:
                                parsed_args = {"raw": func.get("arguments", "")}
                            tool_calls.append({
                                "id": tc.get("id", ""),
                                "type": "function",
                                "function": {
                                    "name": func.get("name", ""),
                                    "arguments": json.dumps(parsed_args),
                                },
                            })
                    return LLMResult(
                        content=content,
                        tool_calls=tool_calls,
                        finish_reason=choice.get("finish_reason", "stop"),
                        usage=result.get("usage"),
                        backend=backend.name,
                    )
                except urllib.error.HTTPError as e:
                    err_body = e.read().decode()
                    # OpenCode 403/1010 (Cloudflare access denied) — try Zen endpoint
                    if (backend.name == "opencode" and e.code == 403
                            and "1010" in err_body and backend.api_key):
                        zen_url = "https://opencode.ai/zen/v1/chat/completions"
                        zen_models = ["deepseek-v4-flash-free", "minimax-m3-free", "mimo-v2.5-free",
                                      "nemotron-3-ultra-free", "qwen3.6-plus-free", "north-mini-code-free",
                                      "llama-3.3-70b-instruct-free"]
                        for zm in zen_models:
                            body["model"] = zm
                            data = json.dumps(body).encode()
                            for use_key in [True, False]:
                                h = {
                                    "Content-Type": "application/json",
                                    "User-Agent": "SENTINEL/1.0",
                                    "Connection": "keep-alive",
                                }
                                if use_key and backend.api_key:
                                    h["Authorization"] = f"Bearer {backend.api_key}"
                                req = urllib.request.Request(zen_url, data=data, headers=h, method="POST")
                                try:
                                    resp = urllib.request.urlopen(req, timeout=120)
                                    result = json.loads(resp.read().decode())
                                    choice = result.get("choices", [{}])[0]
                                    msg = choice.get("message", {})
                                    content = msg.get("content") or ""
                                    tool_calls_raw = msg.get("tool_calls")
                                    tool_calls = None
                                    if tool_calls_raw:
                                        tool_calls = []
                                        for tc in tool_calls_raw:
                                            func = tc.get("function", {})
                                            try:
                                                parsed_args = json.loads(func.get("arguments", "{}"))
                                            except json.JSONDecodeError:
                                                parsed_args = {"raw": func.get("arguments", "")}
                                            tool_calls.append({
                                                "id": tc.get("id", ""),
                                                "type": "function",
                                                "function": {
                                                    "name": func.get("name", ""),
                                                    "arguments": json.dumps(parsed_args),
                                                },
                                            })
                                    return LLMResult(
                                        content=content,
                                        tool_calls=tool_calls,
                                        finish_reason=choice.get("finish_reason", "stop"),
                                        usage=result.get("usage"),
                                        backend=backend.name,
                                    )
                                except urllib.error.HTTPError:
                                    continue
                        last_error = "opencode: all free models failed via Zen endpoint"
                        break
                    # Quota-exceeded 429 — skip this backend entirely
                    if e.code == 429 and ('quota' in err_body.lower() or 'exceeded' in err_body.lower()):
                        last_error = f"{backend.name} HTTP 429 (quota exceeded): {err_body[:200]}"
                        break
                    if e.code in (429, 502, 503) and attempt < max_retries - 1:
                        retry_after = e.headers.get("Retry-After")
                        delay = float(retry_after) if retry_after else min(1.5 ** attempt, 8.0)
                        time.sleep(delay)
                        continue
                    # Cache 404 models so they're never tried again
                    if e.code == 404:
                        self._model_404_cache.add(model)
                        self._save_404_cache()
                    last_error = f"{backend.name} HTTP {e.code}: {err_body[:300]}"
                    break
                except (urllib.error.URLError, TimeoutError) as e:
                    if attempt < max_retries - 1:
                        delay = min(1.5 ** attempt, 8.0)
                        time.sleep(delay)
                        continue
                    last_error = f"{backend.name} connection failed: {e}"
                    break
            else:
                last_error = f"{backend.name} max retries exceeded"
            # If last_error exists and there are more models to try, continue
            if last_error and models_to_try.index(model) < len(models_to_try) - 1:
                continue
            break

        raise RuntimeError(last_error or f"{backend.name} failed")

    # ── Helpers ──

    @staticmethod
    def _msg_to_dict(m: LLMMessage) -> dict:
        d: dict = {"role": m.role, "content": m.content}
        if m.tool_calls:
            d["tool_calls"] = m.tool_calls
        if m.tool_call_id:
            d["tool_call_id"] = m.tool_call_id
            d["role"] = "tool"
        if m.name:
            d["name"] = m.name
        return d

    @staticmethod
    def system(text: str) -> LLMMessage:
        return LLMMessage(role="system", content=text)

    @staticmethod
    def user(text: str) -> LLMMessage:
        return LLMMessage(role="user", content=text)

    @staticmethod
    def assistant(text: str = "", tool_calls: list[dict] | None = None) -> LLMMessage:
        return LLMMessage(role="assistant", content=text, tool_calls=tool_calls)

    @staticmethod
    def tool_result(tool_call_id: str, name: str, result: str) -> LLMMessage:
        return LLMMessage(role="tool", content=result, tool_call_id=tool_call_id, name=name)


# ─────────────────────────────────────────────
# SYSTEM PROMPT TEMPLATES
# ─────────────────────────────────────────────

AGENT_SYSTEM_PROMPT = """You are SENTINEL, a versatile AI assistant with deep expertise in cybersecurity, penetration testing, and bug bounty hunting. You can also answer general questions, explain concepts, and have natural conversations.

## Core Principles
1. **Versatile** — You can handle both casual conversation AND security work. Adapt to whatever the user needs.
2. **Accuracy above all** — never fabricate findings. Report only what tools actually produce.
3. **Think before you act** — reason step-by-step about what to do and why.
4. **Self-debug** — when a tool fails, diagnose why. Try install_tool(), alternatives, or different approaches.
5. **Learn from everything** — bug bounty writeups, CVEs, walkthroughs, past mistakes.
6. **Respect boundaries** — only scan targets the user authorizes.
7. For beginners: explain what each tool does and why you're running it.
8. For experts: be concise, show raw output, and let them dive deeper.

## General Conversation Mode
When the user greets you, asks general questions, or discusses non-security topics:
- Use `respond()` to reply naturally — no tools needed
- You can discuss cybersecurity, hacking methodology, coding, tech news, career advice, or any topic
- Only use security tools if the user explicitly asks for a scan, recon, or vulnerability assessment
- Use `finish()` with a summary when the conversation naturally ends

## Security Work Mode (only when the user requests it)
1. **Understand**: What is the user's goal? (recon, deep scan, specific vuln check, etc.)
2. **Plan**: Which tools are appropriate? What order makes sense?
3. **Execute**: Run tools one at a time, learning from each result.
4. **Analyze**: What do the findings mean? How severe are they?
5. **Report**: Present findings with explanations, impact, and remediation.
6. **Adapt**: Based on findings, suggest next steps or deeper investigation.

## Bug Report Guidelines
Every finding must include:
1. Vulnerability type with CWE reference
2. Severity (critical/high/medium/low/info) with justification
3. Affected URL/endpoint with exact parameter
4. Steps to reproduce — clear, numbered, actionable
5. Impact — what an attacker could achieve
6. Remediation — specific code/config fix recommendation
7. Reference — link to relevant CVE, OWASP, or real-world example if available

Never report false positives, theoretical issues, or out-of-scope targets.

Always use the "think" tool to show your reasoning, then use other tools to take action, then "respond" to talk to the user, and "finish" when done."""


def default_system_prompt(tool_descriptions: str) -> str:
    return f"""{AGENT_SYSTEM_PROMPT}

## Tools Available

{tool_descriptions}

To use a tool, respond with a JSON function call. The system will execute it and return the result.
Always think before you act. Show your reasoning with the think tool."""
