from src.prompt_builder import build_prompt, load_scenario


def test_load_cve_2024_38428_scenario_json():
    scenario = load_scenario("CVE-2024-38428")
    assert scenario.cve_id == "CVE-2024-38428"
    assert scenario.package_name == "wget"
    assert scenario.installed_version == "1.21.4-1ubuntu4"
    assert scenario.fixed_version == "1.21.4-1ubuntu4.1"


def test_build_prompt_fills_placeholders():
    scenario = load_scenario("CVE-2024-38428")
    prompt = build_prompt(scenario)
    assert "CVE-2024-38428" in prompt
    assert "1.21.4-1ubuntu4.1" in prompt
    assert "{{" not in prompt
    assert "#!/usr/bin/env bash" in prompt
