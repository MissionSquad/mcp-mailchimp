"""Tests for MissionSquad hidden secret injection.

MissionSquad's mcp-api merges a user's saved server secrets (`apiKey`, optional `readOnly` /
`dryRun`) into the tools/call arguments. None of those keys is declared in any tool schema.
`HiddenArgsServer.call_tool` strips them before the SDK validates the arguments and exposes
them to `_resolve_account` through a per-call context variable. These tests exercise that path
in-process through the real `call_tool` entrypoint and, once, over a real stdio subprocess.
"""

from __future__ import annotations

import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import anyio
import pytest
import requests

from mailchimp_mcp_server import server

INJECTED_KEY = "injectedsecret-us9"
ENV_KEY = "test-key-us1"  # what conftest installs as the environment fallback


def _text(result) -> str:
    """Tool text from a call_tool result on either SDK line (CallToolResult on 2.x, a
    content list or (content, structured) tuple on 1.x)."""
    content = getattr(result, "content", result)
    if isinstance(content, tuple):
        content = content[0]
    return content[0].text


def _call(name: str, arguments: dict) -> dict:
    return json.loads(_text(anyio.run(server.mcp.call_tool, name, arguments)))


def _ok_resp(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.ok = True
    resp.json.return_value = payload
    return resp


class TestToolSurface:
    def test_no_tool_declares_a_hidden_name(self) -> None:
        tools = server.mcp._tool_manager.list_tools()
        assert len(tools) > 200
        for tool in tools:
            props = set(tool.parameters.get("properties", {}))
            collisions = props & set(server.HIDDEN_ARG_NAMES)
            assert not collisions, f"{tool.name} declares hidden key(s) publicly: {collisions}"

    def test_no_tool_declares_an_auth_looking_field(self) -> None:
        for tool in server.mcp._tool_manager.list_tools():
            for prop in tool.parameters.get("properties", {}):
                lowered = prop.lower()
                assert not any(word in lowered for word in ("apikey", "api_key", "token", "secret", "password")), (
                    f"{tool.name}.{prop} looks like an auth field in the visible schema"
                )

    def test_tool_descriptions_never_ask_the_model_for_a_key(self) -> None:
        for tool in server.mcp._tool_manager.list_tools():
            description = (tool.description or "").lower()
            assert "apikey" not in description
            assert "api key as an argument" not in description


class TestPrecedence:
    def test_hidden_key_overrides_environment(self) -> None:
        with patch.object(requests.Session, "request", return_value=_ok_resp({"health_check": "ok"})) as req:
            payload = _call("ping", {"apiKey": INJECTED_KEY})
        assert payload["health_check"] == "ok"
        assert req.call_args.kwargs["auth"] == ("anystring", INJECTED_KEY)
        # datacenter derives from the injected key, not from the environment key
        assert req.call_args.args[1] == "https://us9.api.mailchimp.com/3.0/ping"

    def test_environment_fallback_when_nothing_injected(self) -> None:
        with patch.object(requests.Session, "request", return_value=_ok_resp({"health_check": "ok"})) as req:
            _call("ping", {})
        assert req.call_args.kwargs["auth"] == ("anystring", ENV_KEY)
        assert req.call_args.args[1] == "https://us1.api.mailchimp.com/3.0/ping"

    def test_hidden_args_do_not_leak_into_the_next_call(self) -> None:
        with patch.object(requests.Session, "request", return_value=_ok_resp({"health_check": "ok"})) as req:
            _call("ping", {"apiKey": INJECTED_KEY})
            _call("ping", {})
        assert req.call_args_list[0].kwargs["auth"] == ("anystring", INJECTED_KEY)
        assert req.call_args_list[1].kwargs["auth"] == ("anystring", ENV_KEY)

    def test_missing_key_is_a_user_facing_error_naming_both_remediations(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "MAILCHIMP_API_KEY", "")
        with patch.object(requests.Session, "request") as req:
            payload = _call("ping", {})
        req.assert_not_called()
        assert "apiKey" in payload["error"]
        assert "MAILCHIMP_API_KEY" in payload["error"]

    def test_unknown_undeclared_keys_are_dropped_silently(self) -> None:
        # Behaviour the SDK already had (pydantic ignored extras) must be preserved.
        with patch.object(requests.Session, "request", return_value=_ok_resp({"health_check": "ok"})):
            payload = _call("ping", {"somethingElse": 1, "apiKey": INJECTED_KEY})
        assert payload["health_check"] == "ok"


class TestValidation:
    @pytest.mark.parametrize("bad", [123, True, None, {"k": "v"}, ["a"]])
    def test_wrong_type_fails_with_user_facing_error(self, bad) -> None:
        with patch.object(requests.Session, "request") as req:
            payload = _call("ping", {"apiKey": bad})
        req.assert_not_called()
        assert "must be a string" in payload["error"]
        assert "apiKey" in payload["error"]

    @pytest.mark.parametrize("blank", ["", "   ", "\n"])
    def test_empty_string_fails_with_user_facing_error(self, blank) -> None:
        with patch.object(requests.Session, "request") as req:
            payload = _call("ping", {"apiKey": blank})
        req.assert_not_called()
        assert "empty" in payload["error"]
        assert "apiKey" in payload["error"]

    def test_key_is_trimmed(self) -> None:
        with patch.object(requests.Session, "request", return_value=_ok_resp({"health_check": "ok"})) as req:
            _call("ping", {"apiKey": f"  {INJECTED_KEY}\n"})
        assert req.call_args.kwargs["auth"] == ("anystring", INJECTED_KEY)

    @pytest.mark.parametrize("bad", ["maybe", "2", "on"])
    def test_invalid_flag_value_is_rejected(self, bad) -> None:
        with patch.object(requests.Session, "request") as req:
            payload = _call("ping", {"apiKey": INJECTED_KEY, "readOnly": bad})
        req.assert_not_called()
        assert "readOnly" in payload["error"]
        assert "'true' or 'false'" in payload["error"]

    def test_flag_must_be_a_string(self) -> None:
        with patch.object(requests.Session, "request") as req:
            payload = _call("ping", {"apiKey": INJECTED_KEY, "dryRun": True})
        req.assert_not_called()
        assert "dryRun" in payload["error"]

    @pytest.mark.parametrize("blank", ["", "   ", None])
    def test_blank_optional_flag_counts_as_unset(self, blank, monkeypatch: pytest.MonkeyPatch, mock_mc_request) -> None:
        # An unset optional field that the configuration surface submits as empty must fall back
        # to the environment flag, never fail the call.
        monkeypatch.setattr(server, "READ_ONLY", True)
        calls = mock_mc_request({"should": "not-be-called"})
        payload = _call("add_member", {"list_id": "abc", "email_address": "a@b.com", "apiKey": INJECTED_KEY, "readOnly": blank, "dryRun": blank})
        assert "MAILCHIMP_READ_ONLY" in payload["error"]
        assert calls == []

    @pytest.mark.parametrize(
        "unsafe",
        ["x-localhost#", "x-evil.com/", "x-us1@evil.com", "x-us9?x=1", "x-us1.evil.com", "x-", "x-us 1"],
    )
    def test_unsafe_datacenter_suffix_is_rejected_before_any_request(self, unsafe) -> None:
        with patch.object(requests.Session, "request") as req:
            payload = _call("ping", {"apiKey": unsafe})
        req.assert_not_called()
        assert "<key>-<dc>" in payload["error"]
        assert "apiKey" in payload["error"]
        assert unsafe not in payload["error"]

    def test_datacenter_suffix_is_lowercased_into_host(self) -> None:
        with patch.object(requests.Session, "request", return_value=_ok_resp({"health_check": "ok"})) as req:
            _call("ping", {"apiKey": "key-US21"})
        assert req.call_args.args[1] == "https://us21.api.mailchimp.com/3.0/ping"

    def test_environment_key_with_unsafe_suffix_fails_at_request_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "MAILCHIMP_API_KEY", "envkey-evil.com/")
        monkeypatch.setattr(server, "MAILCHIMP_BASE_URL", server._base_url_for("envkey-evil.com/"))
        with patch.object(requests.Session, "request") as req:
            payload = _call("ping", {})
        req.assert_not_called()
        assert "MAILCHIMP_API_KEY" in payload["error"]


class TestSafetyFlags:
    def test_injected_read_only_blocks_writes_with_platform_remediation(self, mock_mc_request) -> None:
        calls = mock_mc_request({"should": "not-be-called"})
        payload = _call("add_member", {"list_id": "abc", "email_address": "a@b.com", "apiKey": INJECTED_KEY, "readOnly": "true"})
        assert "read-only" in payload["error"].lower()
        assert "readOnly" in payload["error"]
        assert "MAILCHIMP_READ_ONLY" not in payload["error"]
        assert calls == []

    def test_injected_read_only_false_overrides_environment_lockdown(self, monkeypatch: pytest.MonkeyPatch, mock_mc_request) -> None:
        monkeypatch.setattr(server, "READ_ONLY", True)
        calls = mock_mc_request({"id": "h", "email_address": "a@b.com", "status": "subscribed", "full_name": ""})
        payload = _call("add_member", {"list_id": "abc", "email_address": "a@b.com", "apiKey": INJECTED_KEY, "readOnly": "false"})
        assert payload["email_address"] == "a@b.com"
        assert len(calls) == 1

    def test_environment_read_only_applies_when_flag_not_injected(self, monkeypatch: pytest.MonkeyPatch, mock_mc_request) -> None:
        monkeypatch.setattr(server, "READ_ONLY", True)
        calls = mock_mc_request({"should": "not-be-called"})
        payload = _call("add_member", {"list_id": "abc", "email_address": "a@b.com", "apiKey": INJECTED_KEY})
        assert "MAILCHIMP_READ_ONLY" in payload["error"]
        assert calls == []

    @pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes"])
    def test_injected_dry_run_returns_preview(self, value, mock_mc_request) -> None:
        calls = mock_mc_request({"should": "not-be-called"})
        payload = _call("add_member", {"list_id": "abc", "email_address": "a@b.com", "apiKey": INJECTED_KEY, "dryRun": value})
        assert payload["dry_run"] is True
        assert payload["list_id"] == "abc"
        assert calls == []


class TestAccountSelector:
    def test_named_account_is_rejected_when_key_is_injected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            server,
            "MAILCHIMP_ACCOUNTS",
            {"marketing": {"api_key": "envkey-us5", "dc": "us5", "base_url": "https://us5.api.mailchimp.com/3.0", "read_only": False, "dry_run": False}},
        )
        with patch.object(requests.Session, "request") as req:
            read = _call("get_account_info", {"account": "marketing", "apiKey": INJECTED_KEY})
            write = _call("add_member", {"list_id": "abc", "email_address": "a@b.com", "account": "marketing", "apiKey": INJECTED_KEY})
        req.assert_not_called()
        for payload in (read, write):
            assert "omit the `account` argument" in payload["error"].lower()
            assert "envkey" not in json.dumps(payload)

    @pytest.mark.parametrize("selector", [None, "default", "Default"])
    def test_default_selector_is_accepted_with_injected_key(self, selector) -> None:
        args = {"apiKey": INJECTED_KEY}
        if selector is not None:
            args["account"] = selector
        with patch.object(requests.Session, "request", return_value=_ok_resp({"health_check": "ok"})) as req:
            _call("ping", args)
        assert req.call_args.kwargs["auth"] == ("anystring", INJECTED_KEY)

    def test_list_accounts_reports_single_injected_target_without_secret_material(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "MAILCHIMP_API_KEY", "")
        monkeypatch.setattr(server, "MAILCHIMP_ACCOUNTS", {"envonly": {"read_only": False, "dry_run": False}})
        raw = _text(anyio.run(server.mcp.call_tool, "list_accounts", {"apiKey": INJECTED_KEY, "readOnly": "true"}))
        payload = json.loads(raw)
        assert payload["credentials"] == "injected"
        assert payload["accounts"] == [{"name": "default", "read_only": True, "dry_run": False, "is_default": True}]
        assert INJECTED_KEY not in raw
        assert "injectedsecret" not in raw

    def test_list_accounts_reports_environment_mode_without_injection(self) -> None:
        payload = _call("list_accounts", {})
        assert payload["credentials"] == "environment"
        assert payload["accounts"][0]["name"] == "default"


class TestNoLeakage:
    def test_hidden_values_are_not_forwarded_in_params_or_body(self) -> None:
        with patch.object(requests.Session, "request", return_value=_ok_resp({"id": "h", "email_address": "a@b.com", "status": "subscribed", "full_name": ""})) as req:
            _call("add_member", {"list_id": "abc", "email_address": "a@b.com", "apiKey": INJECTED_KEY, "readOnly": "false", "dryRun": "false"})
        kwargs = req.call_args.kwargs
        assert kwargs["auth"] == ("anystring", INJECTED_KEY)
        body = kwargs["json"]
        assert "apiKey" not in body and "readOnly" not in body and "dryRun" not in body
        assert INJECTED_KEY not in json.dumps(body)
        assert not kwargs["params"] or "apiKey" not in kwargs["params"]

    def test_hidden_values_are_not_in_dry_run_preview(self) -> None:
        raw = _text(anyio.run(server.mcp.call_tool, "add_member", {"list_id": "abc", "email_address": "a@b.com", "apiKey": INJECTED_KEY, "dryRun": "true"}))
        assert json.loads(raw)["dry_run"] is True
        assert INJECTED_KEY not in raw
        assert "apiKey" not in raw

    def test_hidden_values_never_reach_the_audit_log(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        monkeypatch.setattr(server, "AUDIT_LOG", True)
        with patch.object(requests.Session, "request", return_value=_ok_resp({"lists": [], "total_items": 0})):
            _call("list_audiences", {"apiKey": INJECTED_KEY, "readOnly": "false"})
        _call("add_member", {"list_id": "abc", "email_address": "a@b.com", "apiKey": INJECTED_KEY, "readOnly": "true"})
        err = capsys.readouterr().err
        assert '"tool": "list_audiences"' in err and '"tool": "add_member"' in err
        assert INJECTED_KEY not in err
        assert "injectedsecret" not in err

    def test_error_messages_never_echo_the_value(self) -> None:
        payload = _call("ping", {"apiKey": INJECTED_KEY, "readOnly": "definitely-not-a-flag"})
        assert "definitely-not-a-flag" not in payload["error"]
        assert INJECTED_KEY not in payload["error"]


class TestMultiUserIsolation:
    def test_two_users_on_one_process_use_their_own_keys(self) -> None:
        with patch.object(requests.Session, "request", return_value=_ok_resp({"health_check": "ok"})) as req:
            _call("ping", {"apiKey": "alice-us3"})
            _call("ping", {"apiKey": "bob-us7"})
        first, second = req.call_args_list
        assert first.kwargs["auth"] == ("anystring", "alice-us3")
        assert first.args[1].startswith("https://us3.")
        assert second.kwargs["auth"] == ("anystring", "bob-us7")
        assert second.args[1].startswith("https://us7.")

    def test_session_pool_is_isolated_per_key_and_reused_for_same_key(self) -> None:
        server._SESSIONS.clear()
        with patch.object(requests.Session, "request", return_value=_ok_resp({"health_check": "ok"})):
            _call("ping", {"apiKey": "alice-us3"})
            _call("ping", {"apiKey": "bob-us7"})
            _call("ping", {"apiKey": "alice-us3"})
        assert len(server._SESSIONS) == 2
        for fingerprint in server._SESSIONS:
            assert "alice" not in fingerprint and "bob" not in fingerprint

    def test_session_pool_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(server, "_MAX_SESSIONS", 3)
        server._SESSIONS.clear()
        with patch.object(requests.Session, "request", return_value=_ok_resp({"health_check": "ok"})):
            for i in range(10):
                _call("ping", {"apiKey": f"user{i}-us1"})
        assert len(server._SESSIONS) == 3

    def test_concurrent_calls_keep_their_own_hidden_values(self) -> None:
        # Sync tools run on worker threads on mcp 2.x; the per-call context must not bleed
        # between overlapping calls.
        def fake_request(self, method, url, auth=None, **kwargs):
            time.sleep(0.02)
            return _ok_resp({"health_check": auth[1]})

        keys = [f"user{i}-us1" for i in range(6)]
        seen: dict[str, str] = {}

        async def run_all():
            async def one(key):
                result = await server.mcp.call_tool("ping", {"apiKey": key})
                seen[key] = json.loads(_text(result))["health_check"]

            async with anyio.create_task_group() as tg:
                for key in keys:
                    tg.start_soon(one, key)

        with patch.object(requests.Session, "request", fake_request):
            anyio.run(run_all)
        assert seen == {key: key for key in keys}


class TestStdioEndToEnd:
    """Spawn the real entrypoint over stdio with no MAILCHIMP_* variables at all: the process must
    start, serve tools/list without any hidden field, and resolve an injected apiKey on
    tools/call. No network call is made (list_accounts and a keyless ping are both local)."""

    def test_server_starts_without_secrets_and_accepts_injected_ones(self) -> None:
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        env = {k: v for k, v in os.environ.items() if not k.startswith("MAILCHIMP_")}
        params = StdioServerParameters(command=sys.executable, args=["-m", "mailchimp_mcp_server.server"], env=env)

        async def scenario() -> dict:
            with anyio.fail_after(90):
                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        tools = [t.model_dump(by_alias=True) for t in listed.tools]
                        no_key = await session.call_tool("ping", {})
                        injected = await session.call_tool("list_accounts", {"apiKey": "e2e-secret-us4", "dryRun": "true"})
                        return {
                            "tools": tools,
                            "no_key": no_key.model_dump(by_alias=True),
                            "injected": injected.model_dump(by_alias=True),
                        }

        out = anyio.run(scenario)
        assert len(out["tools"]) > 200
        for tool in out["tools"]:
            props = set((tool.get("inputSchema") or {}).get("properties", {}))
            assert not props & set(server.HIDDEN_ARG_NAMES), tool["name"]

        no_key = json.loads(out["no_key"]["content"][0]["text"])
        assert "apiKey" in no_key["error"] and "MAILCHIMP_API_KEY" in no_key["error"]

        injected_raw = out["injected"]["content"][0]["text"]
        injected = json.loads(injected_raw)
        assert injected["credentials"] == "injected"
        assert injected["accounts"] == [{"name": "default", "read_only": False, "dry_run": True, "is_default": True}]
        assert "e2e-secret" not in injected_raw
