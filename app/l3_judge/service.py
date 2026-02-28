"""L3 DeepSeek Judge — inference service using llama-cpp-python or vLLM.

Handles three outcomes: PHISHING, SAFE, or UNCERTAIN → operator review.
CRITICAL: LLM inference runs in a thread pool to avoid blocking the event loop.

Supports real-time Chain-of-Thought streaming via WebSocket events.
"""

import asyncio
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor

from app.config import settings
from app.schemas import (
    JudgeVerdict,
    Label,
    Verdict,
    ParsedEmail,
    EvidenceBundle,
)
from app.l3_judge.prompts import SYSTEM_PROMPT, build_judge_prompt

logger = logging.getLogger(__name__)

# Module-level model cache
_llm = None

# Thread pool for blocking LLM calls — single thread to avoid GPU contention
_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="llm")

# Semaphore to serialize L3 access (only 1 inference at a time)
_inference_lock = asyncio.Lock()

# Confidence threshold below which judge says "I'm not sure → operator"
UNCERTAIN_THRESHOLD = 0.65

# Judge timeout — 14B Q8 model can take 2-4 min on a single GPU
JUDGE_TIMEOUT = 300  # 5 minutes


def load_model() -> None:
    """Load DeepSeek-R1 14B model for inference."""
    global _llm

    if _llm is not None:
        return

    backend = settings.judge_backend

    if backend == "llama_cpp":
        _load_llama_cpp()
    elif backend == "vllm":
        _load_vllm()
    else:
        raise ValueError(f"Unknown judge backend: {backend}")


def _load_llama_cpp():
    """Load model using llama-cpp-python (GGUF)."""
    global _llm
    from llama_cpp import Llama

    model_path = settings.deepseek_gguf_path
    logger.info("Loading DeepSeek Judge (llama.cpp) from %s", model_path)

    _llm = Llama(
        model_path=model_path,
        n_gpu_layers=-1,  # Offload all layers to GPU
        n_ctx=4096,
        verbose=True,  # Show CUDA offload info on first load
    )

    # Log GPU VRAM usage
    try:
        import subprocess
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits"],
            text=True,
        ).strip()
        used, total = out.split(", ")
        logger.info(
            "DeepSeek Judge loaded (llama.cpp, CUDA). VRAM: %s / %s MiB",
            used.strip(), total.strip(),
        )
    except Exception:
        logger.info("DeepSeek Judge loaded (llama.cpp)")


def _load_vllm():
    """Load model using vLLM."""
    global _llm
    from vllm import LLM

    model_path = settings.deepseek_model_path
    logger.info("Loading DeepSeek Judge (vLLM) from %s", model_path)

    _llm = LLM(
        model=model_path,
        tensor_parallel_size=1,
        gpu_memory_utilization=0.65,
        max_model_len=4096,
    )
    logger.info("DeepSeek Judge loaded (vLLM)")


def _generate_sync(prompt: str) -> str:
    """Generate text from the model (BLOCKING — runs in thread pool)."""
    backend = settings.judge_backend

    if backend == "llama_cpp":
        response = _llm.create_chat_completion(
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1024,
            temperature=0.1,
        )
        return response["choices"][0]["message"]["content"]

    elif backend == "vllm":
        from vllm import SamplingParams
        full_prompt = f"<|system|>{SYSTEM_PROMPT}<|user|>{prompt}<|assistant|>"
        params = SamplingParams(max_tokens=1024, temperature=0.1)
        outputs = _llm.generate([full_prompt], params)
        return outputs[0].outputs[0].text

    raise ValueError(f"Unknown backend: {backend}")


def _generate_streaming_sync(prompt: str, token_queue: asyncio.Queue, loop) -> str:
    """Generate with STREAMING — puts tokens into an asyncio.Queue from the thread.

    Each token is pushed to the event loop via call_soon_threadsafe.
    A None sentinel signals completion.
    """
    if settings.judge_backend != "llama_cpp":
        # vLLM doesn't support this simple streaming; fall back
        result = _generate_sync(prompt)
        loop.call_soon_threadsafe(token_queue.put_nowait, None)
        return result

    response = _llm.create_chat_completion(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        max_tokens=1024,
        temperature=0.1,
        stream=True,
    )

    full_text = ""
    for chunk in response:
        delta = chunk["choices"][0].get("delta", {})
        content = delta.get("content", "")
        if content:
            full_text += content
            try:
                loop.call_soon_threadsafe(token_queue.put_nowait, content)
            except Exception:
                pass  # Queue full or loop closed — continue generating anyway

    # Signal completion
    loop.call_soon_threadsafe(token_queue.put_nowait, None)
    return full_text


def _summarize_sync(prompt: str) -> str:
    """Summarize text (BLOCKING — runs in thread pool)."""
    if settings.judge_backend == "llama_cpp":
        response = _llm.create_chat_completion(
            messages=[
                {"role": "system", "content": "You are a helpful email assistant. Summarize emails concisely."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=128,
            temperature=0.3,
        )
        return response["choices"][0]["message"]["content"].strip()
    return ""


async def _generate(prompt: str) -> str:
    """Non-blocking wrapper: runs LLM inference in thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, _generate_sync, prompt)


async def _generate_streaming(prompt: str, email_id: str) -> str:
    """Non-blocking STREAMING wrapper — publishes CoT tokens in real-time.

    Runs the LLM in a thread and bridges tokens to async WebSocket events.
    Batches tokens every ~0.4s to avoid WebSocket spam.
    """
    from app import events

    loop = asyncio.get_event_loop()
    token_queue: asyncio.Queue = asyncio.Queue(maxsize=2000)

    # Start generation in thread pool
    gen_future = loop.run_in_executor(
        _executor, _generate_streaming_sync, prompt, token_queue, loop
    )

    # Consume tokens from queue and publish as events
    full_text = ""
    batch = ""
    last_publish = time.time()
    token_count = 0

    while True:
        try:
            token = await asyncio.wait_for(token_queue.get(), timeout=JUDGE_TIMEOUT)
        except asyncio.TimeoutError:
            logger.error("CoT stream timed out after %ds", JUDGE_TIMEOUT)
            break

        if token is None:
            # Flush remaining batch
            if batch:
                full_text += batch
                token_count += len(batch)
                await events.publish("l3_cot_token", email_id, "L3", {
                    "token": batch,
                    "full_text": full_text[-1500:],
                    "token_count": token_count,
                    "done": True,
                })
            break

        batch += token
        now = time.time()

        # Publish in batches (every 0.4s or every 40 chars) to reduce WS pressure
        if now - last_publish >= 0.4 or len(batch) >= 40:
            full_text += batch
            token_count += len(batch)
            await events.publish("l3_cot_token", email_id, "L3", {
                "token": batch,
                "full_text": full_text[-1500:],
                "token_count": token_count,
                "done": False,
            })
            batch = ""
            last_publish = now

    # Ensure the thread finishes
    try:
        result = await asyncio.wait_for(gen_future, timeout=10)
    except (asyncio.TimeoutError, Exception):
        result = full_text  # Use what we accumulated

    return result or full_text


def _parse_verdict(raw_text: str) -> JudgeVerdict:
    """Parse the model's JSON response into a JudgeVerdict.

    Three possible outcomes:
      - PHISHING (high confidence) → DELETE
      - SAFE (high confidence) → RELEASE
      - UNCERTAIN (low confidence) → OPERATOR_REVIEW
    """
    # Try to extract JSON from the response
    json_match = re.search(r"\{[^{}]*\}", raw_text, re.DOTALL)

    if json_match:
        try:
            data = json.loads(json_match.group())
            verdict_str = data.get("verdict", "phishing").lower()
            confidence = float(data.get("confidence", 0.5))
            reasoning = data.get("reasoning", raw_text)

            # Map verdict string
            if verdict_str in ("uncertain", "unknown", "unclear"):
                label = Label.UNCERTAIN
            elif verdict_str == "safe":
                label = Label.SAFE
            else:
                label = Label.PHISHING

            # If confidence is low → mark as uncertain regardless of verdict
            if 0.0 < confidence < UNCERTAIN_THRESHOLD and label != Label.UNCERTAIN:
                logger.info(
                    "Judge confidence %.2f < %.2f → escalating to UNCERTAIN",
                    confidence, UNCERTAIN_THRESHOLD,
                )
                label = Label.UNCERTAIN

            # Determine action
            if label == Label.UNCERTAIN:
                action = Verdict.OPERATOR_REVIEW
            elif label == Label.SAFE:
                action = Verdict.RELEASE
            else:
                action = Verdict.DELETE

            return JudgeVerdict(
                verdict=label,
                confidence=min(max(confidence, 0.0), 1.0),
                reasoning=reasoning,
                recommended_action=action,
            )
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("Failed to parse judge JSON: %s", e)

    # Fallback: look for keywords
    lower = raw_text.lower()
    if "uncertain" in lower or "not sure" in lower or "cannot determine" in lower:
        return JudgeVerdict(
            verdict=Label.UNCERTAIN,
            confidence=0.5,
            reasoning=raw_text[:500],
            recommended_action=Verdict.OPERATOR_REVIEW,
        )

    if "phishing" in lower:
        return JudgeVerdict(
            verdict=Label.PHISHING,
            confidence=0.7,
            reasoning=raw_text[:500],
            recommended_action=Verdict.DELETE,
        )

    return JudgeVerdict(
        verdict=Label.SAFE,
        confidence=0.5,
        reasoning=raw_text[:500],
        recommended_action=Verdict.RELEASE,
    )


async def judge(
    email: ParsedEmail,
    evidence: EvidenceBundle | None = None,
    email_id: str = "",
) -> JudgeVerdict:
    """Run the DeepSeek Judge on an email with its evidence bundle.

    Uses asyncio.Lock to serialize access (only one inference at a time).
    When email_id is provided, streams Chain-of-Thought tokens to dashboard.
    """
    async with _inference_lock:
        if _llm is None:
            # Load in thread pool too — it's heavy
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(_executor, load_model)

        prompt = build_judge_prompt(
            sender=email.sender,
            recipient=email.recipient,
            subject=email.subject,
            body=email.body,
            urls=email.urls,
            evidence=evidence,
        )

        logger.info("L3 Judge: analyzing email from %s, subject='%s'", email.sender, email.subject)

        try:
            if email_id and settings.judge_backend == "llama_cpp":
                # Streaming mode: publish CoT tokens in real-time
                raw_output = await asyncio.wait_for(
                    _generate_streaming(prompt, email_id),
                    timeout=JUDGE_TIMEOUT,
                )
            else:
                # Non-streaming fallback
                raw_output = await asyncio.wait_for(
                    _generate(prompt),
                    timeout=JUDGE_TIMEOUT,
                )
        except asyncio.TimeoutError:
            logger.error("L3 Judge timed out after %ds", JUDGE_TIMEOUT)
            return JudgeVerdict(
                verdict=Label.UNCERTAIN,
                confidence=0.3,
                reasoning="Judge timed out — escalating to operator",
                recommended_action=Verdict.OPERATOR_REVIEW,
            )

        logger.debug("Judge raw output: %s", raw_output[:200])

        verdict = _parse_verdict(raw_output)
        logger.info(
            "L3 Judge verdict: %s (confidence=%.2f, action=%s)",
            verdict.verdict,
            verdict.confidence,
            verdict.recommended_action,
        )

        return verdict


async def summarize_email(email: ParsedEmail) -> str:
    """Use DeepSeek to generate a short summary of an email for the user inbox.

    Falls back to a simple truncation if model isn't loaded.
    """
    if _llm is None:
        # Simple fallback without loading the heavy model
        text = f"{email.subject}. {email.body[:200]}"
        return text[:150] + "..." if len(text) > 150 else text

    try:
        prompt = (
            "Summarize the following email in 1-2 sentences in the same language as the email. "
            "Be concise and factual.\n\n"
            f"From: {email.sender}\n"
            f"Subject: {email.subject}\n"
            f"Body: {email.body[:500]}\n\n"
            "Summary:"
        )

        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(_executor, _summarize_sync, prompt),
            timeout=30,
        )
        return result if result else email.body[:150] + "..."
    except asyncio.TimeoutError:
        logger.warning("Summarization timed out")
        return email.body[:150] + "..." if email.body else email.subject
    except Exception as e:
        logger.warning("Summarization failed: %s", e)
        return email.body[:150] + "..." if email.body else email.subject
