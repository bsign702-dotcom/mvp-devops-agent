from api.services.platform_service import (
    build_log_fingerprint,
    lint_compose_yaml,
    lint_nginx_conf,
)


def test_compose_lint_detects_port_conflict_and_latest_warning() -> None:
    content = """
services:
  api:
    image: my/api:latest
    ports:
      - "8080:8000"
  web:
    image: my/web:1.0.0
    ports:
      - "8080:80"
"""
    result = lint_compose_yaml(content)
    assert result["ok"] is False
    assert any("Host port conflict" in msg for msg in result["errors"])
    assert any("uses latest tag" in msg for msg in result["warnings"])


def test_nginx_lint_detects_missing_server_name() -> None:
    conf = """
server {
  listen 80;
  location / {
    proxy_pass http://127.0.0.1:8000;
  }
}
"""
    result = lint_nginx_conf(conf)
    assert result["ok"] is False
    assert any("server_name" in msg for msg in result["errors"])


def test_log_fingerprint_is_stable_after_numeric_changes() -> None:
    fp1 = build_log_fingerprint("nginx", "nginx", "[error] connect() failed 10.0.0.1 code 500")
    fp2 = build_log_fingerprint("nginx", "nginx", "[error] connect() failed 10.0.0.2 code 502")
    assert fp1 == fp2
