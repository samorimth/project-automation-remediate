from src import reexecution


def _record(kind: str, functional: dict[str, str]) -> dict[str, object]:
    return {
        "experiment_id": "REEXEC-TESTE",
        "set": kind,
        "ami_id": "ami-teste",
        "instance_id": "i-teste",
        "script_sha256": "abc",
        "version_before": "1",
        "version_after": "2",
        "execution_status": "Success",
        "classification": "SUCESSO",
        "classification_reason": "registro sintético",
        "functional": functional,
    }


def test_http_markdown_uses_the_recorded_http_probe(tmp_path, monkeypatch):
    monkeypatch.setattr(reexecution, "LAB_ROOT", tmp_path)
    destination = tmp_path / "results" / "reexecution" / "http"
    destination.mkdir(parents=True)
    untouched = destination / "functional.json"
    untouched.write_text('{"original": true}\n', encoding="utf-8")
    before = untouched.read_bytes()
    reexecution._write_markdown(
        destination / "evidence.md",
        _record(
            "reexecucao_http_local",
            {
                "exit_code": "0",
                "bytes": "16",
                "first_line": "tcc-lab-wget-ok",
                "file_exit": "1",
            },
        ),
        {"timestamp_utc": "2026-11-12T00:00:00Z"},
        {"command_id": "cmd", "response_code": 0, "duration_seconds": 1},
    )
    text = (destination / "evidence.md").read_text(encoding="utf-8")
    assert "http://127.0.0.1:9876/lab" in text
    assert "código 0" in text
    assert "16 bytes" in text
    assert "`tcc-lab-wget-ok`" in text
    assert "file:///etc/os-release" in text
    assert "código 1" in text
    assert "não compõe o critério" in text
    assert untouched.read_bytes() == before


def test_file_markdown_stays_on_the_file_probe(tmp_path, monkeypatch):
    monkeypatch.setattr(reexecution, "LAB_ROOT", tmp_path)
    destination = tmp_path / "results" / "reexecution" / "file"
    destination.mkdir(parents=True)
    reexecution._write_markdown(
        destination / "evidence.md",
        _record("reexecucao_controlada", {"exit_code": "1", "bytes": "0", "first_line": ""}),
        {"timestamp_utc": "2026-11-12T00:00:00Z"},
        None,
    )
    text = (destination / "evidence.md").read_text(encoding="utf-8")
    assert "file:///etc/os-release" in text
    assert "código 1" in text
    assert "127.0.0.1" not in text
