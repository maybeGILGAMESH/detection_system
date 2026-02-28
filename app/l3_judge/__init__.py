"""L3 DeepSeek Judge — Chain-of-Thought LLM verdict for grey-zone emails.

Uses DeepSeek-R1 14B (Q8 GGUF via llama-cpp-python or vLLM) to analyze
email content + evidence bundle and produce a phishing/safe verdict with
confidence score and reasoning.

Components:
  - service : model loading + async judge(email, evidence) → JudgeVerdict
  - prompts : system prompt + CoT template builder

VRAM: ~15 GB (Q8_0 quantization, full GPU offload)
"""

from app.l3_judge.service import judge, load_model

__all__ = ["judge", "load_model"]

