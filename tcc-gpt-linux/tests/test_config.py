from src.config import (
    ENV_EXAMPLE,
    REQUIRED_ENV_KEYS,
    TERRAFORM_DIR,
    TFVARS_EXAMPLE,
    ConfigError,
    Settings,
    assert_safe_example,
    load_tfvars,
    parse_tfvars,
)


def test_instance_count_cannot_exceed_max_instances():
    settings = Settings(aws_region="us-east-1", max_instances=3, instance_count=4)  # pragma: allowlist secret
    try:
        settings.validate_instance_bounds()
    except ConfigError as exc:
        assert "não pode ser maior" in str(exc)
    else:
        raise AssertionError("o limite de instâncias deveria ter sido recusado")


def test_instance_count_equal_to_max_instances_is_valid():
    Settings(aws_region="us-east-1", max_instances=3, instance_count=3).validate_instance_bounds()  # pragma: allowlist secret


def test_negative_instance_count_is_refused():
    settings = Settings(aws_region="us-east-1", max_instances=3, instance_count=-1)  # pragma: allowlist secret
    try:
        settings.validate_instance_bounds()
    except ConfigError as exc:
        assert "negativo" in str(exc)
    else:
        raise AssertionError("instance_count negativo deveria ter sido recusado")


def test_example_tfvars_keep_paid_resources_disabled():
    values = load_tfvars(TFVARS_EXAMPLE)
    assert_safe_example(values)
    assert values["aws_region"] == "us-east-2"
    assert values["enable_execution"] == "false"
    assert values["enable_nat_gateway"] == "false"
    assert values["enable_ssm_vpc_endpoints"] == "false"


def test_paid_flag_in_example_is_refused():
    values = parse_tfvars('enable_execution = true\ninstance_count = 1\nmax_instances = 3\n')
    try:
        assert_safe_example(values)
    except ConfigError as exc:
        assert "enable_execution" in str(exc)
    else:
        raise AssertionError("o exemplo com execução ligada deveria ter sido recusado")


def test_env_example_has_required_keys_without_secrets():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    values = {}
    for line in text.splitlines():
        key, value = line.split("=", 1)
        values[key] = value
    assert tuple(values) == REQUIRED_ENV_KEYS
    assert values["OPENAI_API_KEY"] == ""
    assert values["AWS_REGION"] == "us-east-2"
    assert "sk-" not in text
    assert "AKIA" not in text


def test_terraform_does_not_adopt_the_default_network():
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in TERRAFORM_DIR.glob("*.tf")
    )
    assert "aws_default_vpc" not in source
    assert "aws_default_subnet" not in source
    assert 'data "aws_vpc"' not in source
    assert "10.42.0.0/16" in source
