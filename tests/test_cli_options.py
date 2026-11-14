from __future__ import annotations

import io
import json

import pytest

from api_checker.cli import _baseline_fingerprints, _config_options, _input_paths, main


def _write_spec(path):
    path.write_text(json.dumps({
        "openapi": "3.0.3", "info": {"title": "CLI", "version": "1"},
        "paths": {"/items": {"get": {}, "post": {"responses": {"201": {"description": "ok"}}}}},
    }), encoding="utf-8")
    return path


def test_config_and_baseline_helpers_accept_supported_shapes(tmp_path):
    toml = tmp_path / "settings.toml"
    toml.write_text('[tool.openapi-sec-lint]\nformat = "md"\ndisable = ["AUTH-001"]\n', encoding="utf-8")
    assert _config_options(toml)["format"] == "md"
    config_json = tmp_path / "settings.json"
    config_json.write_text('{"format":"json"}', encoding="utf-8")
    assert _config_options(config_json)["format"] == "json"
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"version":2,"artifacts":{"a.yaml":["abc"]}}', encoding="utf-8")
    assert _baseline_fingerprints(baseline) == (set(), {"a.yaml": {"abc"}})
    baseline.write_text('{"fingerprints":["legacy"]}', encoding="utf-8")
    assert _baseline_fingerprints(baseline) == ({"legacy"}, {})


def test_cli_directory_output_filter_disable_and_baselines(tmp_path, capsys):
    specs = tmp_path / "specs"
    specs.mkdir()
    source = _write_spec(specs / "api.json")
    assert _input_paths([str(specs)]) == [source]
    output, baseline = tmp_path / "report.json", tmp_path / "baseline.json"
    assert main(["scan", str(specs), "--format", "json", "--disable", "AUTH-001,MASS-001",
                 "--min-severity", "high", "--output", str(output), "--write-baseline", str(baseline)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["findings"] == []
    assert json.loads(baseline.read_text(encoding="utf-8"))["version"] == 2
    assert capsys.readouterr().out == ""
    assert main(["scan", str(source), "--baseline", str(baseline)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["findings"] == len(report["findings"])


def test_cli_stdin_and_fail_on_info(tmp_path, monkeypatch, capsys):
    spec = '{"openapi":"3.0.3","info":{"title":"stdin","version":"1"},"paths":{"/x":{"get":{}}}}'
    monkeypatch.setattr("sys.stdin", io.StringIO(spec))
    assert main(["scan", "-", "--fail-on", "info", "--format", "sarif"]) == 1
    assert json.loads(capsys.readouterr().out)["version"] == "2.1.0"


def test_cli_invalid_inputs_and_config_return_usage_error(tmp_path, capsys):
    bad = tmp_path / "bad.toml"
    bad.write_text("disable = 'AUTH-001'\n", encoding="utf-8")
    assert main(["scan", "missing.yaml", "--config", str(bad)]) == 2
    assert "Config 'disable'" in capsys.readouterr().err
    assert main(["scan", "-", "-"]) == 2
    assert "only input" in capsys.readouterr().err


def test_cli_version_option_exits_cleanly(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "openapi-sec-lint" in capsys.readouterr().out
