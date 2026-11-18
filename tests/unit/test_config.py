import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_production_requires_signing_key() -> None:
    with pytest.raises(ValidationError, match="JWT_PRIVATE_KEY"):
        Settings(_env_file=None, environment="production", email_backend="smtp")


def test_production_rejects_console_email_and_cors_wildcard() -> None:
    with pytest.raises(ValidationError, match="console"):
        Settings(_env_file=None, environment="staging", jwt_private_key="x")
    with pytest.raises(ValidationError, match="wildcard"):
        Settings(
            _env_file=None,
            environment="staging",
            jwt_private_key="x",
            email_backend="smtp",
            cors_origins="*",
        )


def test_lists_parse_from_csv_and_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORS_ORIGINS", "https://a.example, https://b.example")
    monkeypatch.setenv("METRICS_ALLOWED_CIDRS", '["10.0.0.0/8"]')
    s = Settings(_env_file=None)
    assert s.cors_origins == ["https://a.example", "https://b.example"]
    assert s.metrics_allowed_cidrs == ["10.0.0.0/8"]


def test_private_key_newline_escapes(tmp_path) -> None:
    s = Settings(_env_file=None, jwt_private_key="-----BEGIN-----\\nabc\\n-----END-----")
    assert s.load_private_key_pem() == "-----BEGIN-----\nabc\n-----END-----"
    f = tmp_path / "k.pem"
    f.write_text("PEM")
    assert Settings(_env_file=None, jwt_private_key_file=f).load_private_key_pem() == "PEM"
