from types import SimpleNamespace

import src.openai_client as openai_client
from src.config import Settings
from src.openai_client import (
    OpenAIClient,
    completion_params,
    extract_bash_script,
    sha256_text,
)


def _settings() -> Settings:
    return Settings(
        aws_region="us-east-2",
        max_instances=3,
        instance_count=1,
        openai_api_key="test-key-not-real",
        openai_model="gpt-test",
        openai_timeout=30,
        openai_max_retries=0,
        repetitions=1,
    )


class _FakeCompletions:
    def __init__(self, content: str):
        self.content = content

    def create(self, **kwargs):
        assert "api_key" not in str(kwargs)
        return SimpleNamespace(
            model=kwargs["model"],
            choices=[SimpleNamespace(message=SimpleNamespace(content=self.content))],
            usage=SimpleNamespace(prompt_tokens=11, completion_tokens=22, total_tokens=33),
        )


class _FakeClient:
    def __init__(self, content: str):
        self.chat = SimpleNamespace(completions=_FakeCompletions(content))


def test_gpt6_luna_keeps_temperature_and_disables_reasoning():
    assert completion_params("gpt-6-luna") == {  # pragma: allowlist secret
        "temperature": 0.2,
        "reasoning_effort": "none",
    }


def test_other_models_keep_temperature_only():
    assert completion_params("gpt-4.1") == {"temperature": 0.2}


def test_extract_bash_from_fenced_block():
    raw = "```bash\necho hi\n```"
    script = extract_bash_script(raw)
    assert script.startswith("#!/usr/bin/env bash")
    assert "echo hi" in script


def test_generate_persists_artifacts_without_logging_key(tmp_path, monkeypatch):
    monkeypatch.setattr(openai_client, "GENERATED_SCRIPTS_DIR", tmp_path)

    def fake_openai(**kwargs):
        assert kwargs["api_key"] == "test-key-not-real"
        return _FakeClient("#!/usr/bin/env bash\napt-get install -y wget\n")

    monkeypatch.setitem(
        __import__("sys").modules,
        "openai",
        SimpleNamespace(OpenAI=fake_openai),
    )
    # Force re-import path used inside OpenAIClient
    client = OpenAIClient.__new__(OpenAIClient)
    client.settings = _settings()
    client._client = _FakeClient(
        "#!/usr/bin/env bash\napt-get update\napt-get install -y --only-upgrade wget\n"
    )
    result = client.generate_remediation_script(
        cve_id="CVE-2024-38428",
        prompt="PROMPT_TEST",
    )
    assert result.ok
    assert result.model == "gpt-test"
    assert result.total_tokens == 33
    assert result.prompt_hash_sha256 == sha256_text("PROMPT_TEST")
    out = tmp_path / "CVE-2024-38428" / "rep01"
    assert (out / "prompt.txt").read_text(encoding="utf-8") == "PROMPT_TEST"
    assert (out / "remediation.sh").is_file()
    meta = (out / "metadata.json").read_text(encoding="utf-8")
    assert "test-key-not-real" not in meta
    assert "sk-" not in meta
