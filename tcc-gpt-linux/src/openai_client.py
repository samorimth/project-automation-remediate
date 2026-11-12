"""Cliente OpenAI para geração de scripts Bash de remediação.

Nunca registra a chave de API. Preserva prompt, resposta, hashes, tokens e latência.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import GENERATED_SCRIPTS_DIR, Settings, ConfigError


@dataclass
class GenerationResult:
    cve_id: str
    repetition: int
    model: str
    timestamp_utc: str
    latency_ms: int
    prompt_hash_sha256: str
    response_hash_sha256: str
    script_hash_sha256: str
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None
    script_text: str
    raw_response_text: str
    error: str | None = None
    output_dir: str | None = None
    metadata_path: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.script_text.strip())

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Não incluir o texto completo no summary externo se desejado;
        # aqui preservamos tudo em metadata.json local.
        return data


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract_bash_script(raw: str) -> str:
    """Remove cercas markdown se o modelo as incluir apesar das instruções."""
    text = raw.strip()
    fenced = re.search(r"```(?:bash|sh)?\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced.group(1).strip()
    if not text.startswith("#!"):
        text = "#!/usr/bin/env bash\n" + text
    return text.rstrip() + "\n"


def next_repetition_dir(cve_id: str) -> Path:
    base = GENERATED_SCRIPTS_DIR / cve_id
    base.mkdir(parents=True, exist_ok=True)
    existing = sorted(base.glob("rep*"))
    next_num = 1
    for path in existing:
        match = re.fullmatch(r"rep(\d+)", path.name)
        if match:
            next_num = max(next_num, int(match.group(1)) + 1)
    target = base / f"rep{next_num:02d}"
    target.mkdir(parents=True, exist_ok=False)
    return target


class OpenAIClient:
    """Wrapper fino sobre o SDK oficial, com telemetria local."""

    def __init__(self, settings: Settings):
        settings.require_openai()
        self.settings = settings
        # Import local para permitir testes sem o pacote instalado quando mockado.
        from openai import OpenAI

        self._client = OpenAI(
            api_key=settings.openai_api_key,
            timeout=float(settings.openai_timeout),
            max_retries=settings.openai_max_retries,
        )

    def generate_remediation_script(
        self,
        *,
        cve_id: str,
        prompt: str,
        repetition: int | None = None,
    ) -> GenerationResult:
        output_dir = next_repetition_dir(cve_id)
        rep_num = repetition or int(output_dir.name.replace("rep", ""))
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        prompt_hash = sha256_text(prompt)
        started = time.perf_counter()
        error: str | None = None
        raw_text = ""
        usage: dict[str, int | None] = {
            "prompt_tokens": None,
            "completion_tokens": None,
            "total_tokens": None,
        }
        model_used = self.settings.openai_model

        try:
            response = self._client.chat.completions.create(
                model=self.settings.openai_model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "Você gera apenas scripts Bash seguros para remediação "
                            "de CVEs em laboratório Ubuntu."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            model_used = getattr(response, "model", None) or model_used
            choice = response.choices[0].message.content or ""
            raw_text = choice
            if response.usage is not None:
                usage = {
                    "prompt_tokens": getattr(response.usage, "prompt_tokens", None),
                    "completion_tokens": getattr(response.usage, "completion_tokens", None),
                    "total_tokens": getattr(response.usage, "total_tokens", None),
                }
        except Exception as exc:  # noqa: BLE001 — registrar qualquer falha da API
            # Não incluir headers/corpo que possam carregar a chave.
            error = f"{type(exc).__name__}: {exc}"
            raw_text = ""

        latency_ms = int((time.perf_counter() - started) * 1000)
        script_text = extract_bash_script(raw_text) if raw_text.strip() else ""
        result = GenerationResult(
            cve_id=cve_id,
            repetition=rep_num,
            model=model_used,
            timestamp_utc=timestamp,
            latency_ms=latency_ms,
            prompt_hash_sha256=prompt_hash,
            response_hash_sha256=sha256_text(raw_text) if raw_text else "",
            script_hash_sha256=sha256_text(script_text) if script_text else "",
            prompt_tokens=usage["prompt_tokens"],
            completion_tokens=usage["completion_tokens"],
            total_tokens=usage["total_tokens"],
            script_text=script_text,
            raw_response_text=raw_text,
            error=error,
            output_dir=str(output_dir),
        )
        _persist(output_dir, prompt, result)
        return result


def _persist(output_dir: Path, prompt: str, result: GenerationResult) -> None:
    (output_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
    (output_dir / "response.txt").write_text(result.raw_response_text, encoding="utf-8")
    if result.script_text:
        script_path = output_dir / "remediation.sh"
        script_path.write_text(result.script_text, encoding="utf-8")
        # Scripts falhos na validação terão o bit removido depois; aqui ainda não validamos.
        script_path.chmod(0o644)
    metadata = result.to_dict()
    # Evitar persistir chave; ela nunca entra no GenerationResult.
    metadata_path = output_dir / "metadata.json"
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    result.metadata_path = str(metadata_path)


def generate_for_cve(settings: Settings, cve_id: str, prompt: str) -> GenerationResult:
    if not settings.openai_api_key:
        raise ConfigError(
            "OPENAI_API_KEY ausente. Configure o secret antes de generate."
        )
    client = OpenAIClient(settings)
    return client.generate_remediation_script(cve_id=cve_id, prompt=prompt)
