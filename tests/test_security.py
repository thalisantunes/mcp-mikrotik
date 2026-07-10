"""Unit tests for src/mcp_mikrotik/security.py - security_audit's individual
checks/aggregation, and security_events' log filter - driven directly
against MikrotikClient + FakeConnection (not through the MCP tool layer;
see test_server.py's "security_audit / security_events (v0.12)" section for
end-to-end tool-call tests).
"""

from __future__ import annotations

import pytest
from librouteros.exceptions import LibRouterosError

from mcp_mikrotik import security
from mcp_mikrotik.client import MikrotikClient
from mcp_mikrotik.config import Device
from mcp_mikrotik.exceptions import DeviceCommandError

from .fakes import FakeConnection

# --- helpers ----------------------------------------------------------


def _client(device: Device, data: dict | None = None, raise_for: dict | None = None) -> MikrotikClient:
    fake = FakeConnection(data=data or {}, raise_for=raise_for or {})
    return MikrotikClient(device, connection=fake)


# --- Check 1: insecure management services (/ip/service) --------------


def test_management_services_flags_telnet_open_to_any_as_high(device: Device):
    client = _client(
        device,
        data={("ip", "service"): [{"name": "telnet", "disabled": "false", "address": ""}]},
    )
    findings = security._check_management_services(client)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].category == "management-services"
    assert "telnet" in findings[0].title


def test_management_services_flags_ftp_open_to_any_as_high(device: Device):
    client = _client(
        device,
        data={("ip", "service"): [{"name": "ftp", "disabled": "false", "address": "0.0.0.0/0"}]},
    )
    findings = security._check_management_services(client)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_management_services_flags_www_and_api_open_to_any_as_medium(device: Device):
    client = _client(
        device,
        data={
            ("ip", "service"): [
                {"name": "www", "disabled": "false", "address": ""},
                {"name": "api", "disabled": "false", "address": "0.0.0.0/0"},
            ]
        },
    )
    findings = security._check_management_services(client)
    assert len(findings) == 2
    assert {f.severity for f in findings} == {"medium"}


def test_management_services_flags_winbox_open_to_any_as_medium(device: Device):
    client = _client(
        device,
        data={("ip", "service"): [{"name": "winbox", "disabled": "false", "address": ""}]},
    )
    findings = security._check_management_services(client)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "winbox" in findings[0].title.lower()


def test_management_services_winbox_restricted_produces_no_finding(device: Device):
    client = _client(
        device,
        data={("ip", "service"): [{"name": "winbox", "disabled": "false", "address": "10.0.0.0/24"}]},
    )
    assert security._check_management_services(client) == []


def test_management_services_insecure_but_restricted_is_low(device: Device):
    client = _client(
        device,
        data={("ip", "service"): [{"name": "telnet", "disabled": "false", "address": "10.0.0.0/24"}]},
    )
    findings = security._check_management_services(client)
    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_management_services_disabled_service_produces_no_finding(device: Device):
    client = _client(
        device,
        data={("ip", "service"): [{"name": "telnet", "disabled": "true", "address": ""}]},
    )
    assert security._check_management_services(client) == []


def test_management_services_ssh_and_ssl_variants_never_flagged(device: Device):
    client = _client(
        device,
        data={
            ("ip", "service"): [
                {"name": "ssh", "disabled": "false", "address": ""},
                {"name": "api-ssl", "disabled": "false", "address": ""},
                {"name": "www-ssl", "disabled": "false", "address": ""},
            ]
        },
    )
    assert security._check_management_services(client) == []


def test_management_services_skips_when_menu_absent(device: Device):
    client = _client(device, raise_for={("ip", "service"): LibRouterosError("no such command")})
    assert security._check_management_services(client) == []


# --- Check 2: firewall input chain drop -----------------------------


def test_firewall_input_drop_flags_missing_input_chain(device: Device):
    client = _client(device, data={("ip", "firewall", "filter"): []})
    findings = security._check_firewall_input_drop(client)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "input" in findings[0].title.lower()


def test_firewall_input_drop_flags_last_rule_not_drop(device: Device):
    client = _client(
        device,
        data={
            ("ip", "firewall", "filter"): [
                {"chain": "input", "action": "accept", "disabled": "false"},
            ]
        },
    )
    findings = security._check_firewall_input_drop(client)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_firewall_input_drop_no_finding_when_last_enabled_rule_is_drop(device: Device):
    client = _client(
        device,
        data={
            ("ip", "firewall", "filter"): [
                {"chain": "input", "action": "accept", "disabled": "false"},
                {"chain": "input", "action": "drop", "disabled": "false"},
            ]
        },
    )
    assert security._check_firewall_input_drop(client) == []


def test_firewall_input_drop_no_finding_when_last_enabled_rule_is_reject(device: Device):
    client = _client(
        device,
        data={
            ("ip", "firewall", "filter"): [
                {"chain": "input", "action": "reject", "disabled": "false"},
            ]
        },
    )
    assert security._check_firewall_input_drop(client) == []


def test_firewall_input_drop_ignores_disabled_trailing_drop_rule(device: Device):
    """A disabled drop rule at the very end must not count - only ENABLED
    rules are considered, so the last ENABLED rule (accept) is what's
    evaluated here."""
    client = _client(
        device,
        data={
            ("ip", "firewall", "filter"): [
                {"chain": "input", "action": "accept", "disabled": "false"},
                {"chain": "input", "action": "drop", "disabled": "true"},
            ]
        },
    )
    findings = security._check_firewall_input_drop(client)
    assert len(findings) == 1


def test_firewall_input_drop_ignores_other_chains(device: Device):
    client = _client(
        device,
        data={
            ("ip", "firewall", "filter"): [
                {"chain": "forward", "action": "accept", "disabled": "false"},
            ]
        },
    )
    findings = security._check_firewall_input_drop(client)
    assert len(findings) == 1
    assert "no enabled" in findings[0].title.lower()


def test_firewall_input_drop_skips_when_menu_absent(device: Device):
    client = _client(device, raise_for={("ip", "firewall", "filter"): LibRouterosError("no such command")})
    assert security._check_firewall_input_drop(client) == []


# --- Check 3: SNMP community open -------------------------------------


def test_snmp_flags_default_public_community(device: Device):
    client = _client(
        device,
        data={("snmp", "community"): [{"name": "public", "addresses": "10.0.0.0/24"}]},
    )
    findings = security._check_snmp(client)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "public" in findings[0].title


def test_snmp_flags_unrestricted_addresses(device: Device):
    client = _client(
        device,
        data={("snmp", "community"): [{"name": "monitoring", "addresses": "0.0.0.0/0"}]},
    )
    findings = security._check_snmp(client)
    assert len(findings) == 1


def test_snmp_no_finding_when_named_and_restricted(device: Device):
    client = _client(
        device,
        data={("snmp", "community"): [{"name": "monitoring", "addresses": "10.0.0.0/24"}]},
    )
    assert security._check_snmp(client) == []


def test_snmp_skips_when_menu_absent(device: Device):
    client = _client(device, raise_for={("snmp", "community"): LibRouterosError("no such command")})
    assert security._check_snmp(client) == []


# --- Check 4: DNS open resolver -----------------------------------------


def test_dns_flags_allow_remote_requests(device: Device):
    client = _client(device, data={("ip", "dns"): [{"allow-remote-requests": "true"}]})
    findings = security._check_dns_open_resolver(client)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_dns_no_finding_when_remote_requests_disabled(device: Device):
    client = _client(device, data={("ip", "dns"): [{"allow-remote-requests": "false"}]})
    assert security._check_dns_open_resolver(client) == []


def test_dns_no_finding_when_no_rows(device: Device):
    client = _client(device, data={("ip", "dns"): []})
    assert security._check_dns_open_resolver(client) == []


def test_dns_skips_when_menu_absent(device: Device):
    client = _client(device, raise_for={("ip", "dns"): LibRouterosError("no such command")})
    assert security._check_dns_open_resolver(client) == []


# --- Check 5: outdated RouterOS -----------------------------------------


def test_routeros_version_flags_outdated(device: Device):
    client = _client(
        device,
        data={("system", "package", "update"): [{"installed-version": "7.14", "latest-version": "7.16.1"}]},
    )
    findings = security._check_routeros_version(client)
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert "7.14" in findings[0].detail
    assert "7.16.1" in findings[0].detail


def test_routeros_version_no_finding_when_up_to_date(device: Device):
    client = _client(
        device,
        data={("system", "package", "update"): [{"installed-version": "7.16.1", "latest-version": "7.16.1"}]},
    )
    assert security._check_routeros_version(client) == []


def test_routeros_version_no_finding_when_data_missing(device: Device):
    client = _client(device, data={("system", "package", "update"): [{}]})
    assert security._check_routeros_version(client) == []


def test_routeros_version_skips_when_menu_absent(device: Device):
    client = _client(device, raise_for={("system", "package", "update"): LibRouterosError("no such command")})
    assert security._check_routeros_version(client) == []


# --- Check 6: open wireless/wifi ----------------------------------------


def test_open_wireless_flags_ros6_mode_none(device: Device):
    client = _client(
        device,
        data={
            ("interface", "wireless", "security-profiles"): [
                {"name": "default", "mode": "none"},
            ]
        },
    )
    findings = security._check_open_wireless(client)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].category == "wireless"


def test_open_wireless_ros6_secured_profile_no_finding(device: Device):
    client = _client(
        device,
        data={
            ("interface", "wireless", "security-profiles"): [
                {"name": "default", "mode": "dynamic-keys", "wpa2-pre-shared-key": "s3cr3tpass"},
            ]
        },
    )
    assert security._check_open_wireless(client) == []


def test_open_wireless_flags_ros7_no_passphrase(device: Device):
    client = _client(
        device,
        data={
            ("interface", "wifi", "security"): [
                {"name": "sec1", "passphrase": "", "authentication-types": ""},
            ]
        },
    )
    findings = security._check_open_wireless(client)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_open_wireless_ros7_with_passphrase_no_finding(device: Device):
    client = _client(
        device,
        data={
            ("interface", "wifi", "security"): [
                {"name": "sec1", "passphrase": "s3cr3tpass", "authentication-types": "wpa2-psk"},
            ]
        },
    )
    assert security._check_open_wireless(client) == []


def test_open_wireless_ros7_with_authentication_types_but_no_passphrase_no_finding(device: Device):
    """802.1X-style configs can have authentication-types set with no
    passphrase at all (EAP, not PSK) - only flag when BOTH are absent."""
    client = _client(
        device,
        data={
            ("interface", "wifi", "security"): [
                {"name": "sec1", "passphrase": "", "authentication-types": "wpa2-eap"},
            ]
        },
    )
    assert security._check_open_wireless(client) == []


def test_open_wireless_skips_when_both_menus_absent(device: Device):
    client = _client(
        device,
        raise_for={
            ("interface", "wireless", "security-profiles"): LibRouterosError("no such command"),
            ("interface", "wifi", "security"): LibRouterosError("no such command"),
        },
    )
    assert security._check_open_wireless(client) == []


# --- Check 7: users with sensitive policy --------------------------------


def test_users_reports_write_and_full_policy_count(device: Device):
    client = _client(
        device,
        data={
            ("user",): [
                {"name": "admin", "group": "full"},
                {"name": "operator", "group": "write"},
                {"name": "viewer", "group": "read"},
            ]
        },
    )
    findings = security._check_users(client)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "info"
    assert "admin" in finding.detail
    assert "operator" in finding.detail
    assert "viewer" not in finding.detail
    assert "2 of 3" in finding.title


def test_users_no_finding_when_all_read_only(device: Device):
    client = _client(device, data={("user",): [{"name": "viewer", "group": "read"}]})
    assert security._check_users(client) == []


def test_users_no_finding_when_no_users(device: Device):
    client = _client(device, data={("user",): []})
    assert security._check_users(client) == []


def test_users_skips_when_menu_absent(device: Device):
    client = _client(device, raise_for={("user",): LibRouterosError("no such command")})
    assert security._check_users(client) == []


# --- run_security_audit: aggregation, sorting, summary, resilience -------


def test_run_security_audit_sorts_by_severity_and_summarizes(device: Device):
    client = _client(
        device,
        data={
            ("ip", "service"): [{"name": "telnet", "disabled": "false", "address": ""}],  # high
            ("snmp", "community"): [{"name": "public", "addresses": "0.0.0.0/0"}],  # medium
            ("system", "package", "update"): [{"installed-version": "7.14", "latest-version": "7.16"}],  # low
            ("user",): [{"name": "admin", "group": "full"}],  # info
            ("ip", "firewall", "filter"): [{"chain": "input", "action": "drop", "disabled": "false"}],
            ("ip", "dns"): [{"allow-remote-requests": "false"}],
        },
    )
    result = security.run_security_audit(client)
    severities = [f["severity"] for f in result["findings"]]
    assert severities == sorted(severities, key=lambda s: {"high": 0, "medium": 1, "low": 2, "info": 3}[s])
    assert severities[0] == "high"
    assert severities[-1] == "info"
    assert result["summary"] == {"high": 1, "medium": 1, "low": 1, "info": 1}


def test_run_security_audit_returns_zeroed_summary_when_nothing_flagged(device: Device):
    client = _client(
        device,
        data={
            ("ip", "service"): [{"name": "ssh", "disabled": "false", "address": ""}],
            ("ip", "firewall", "filter"): [{"chain": "input", "action": "drop", "disabled": "false"}],
        },
    )
    result = security.run_security_audit(client)
    assert result["findings"] == []
    assert result["summary"] == {"high": 0, "medium": 0, "low": 0, "info": 0}


def test_run_security_audit_never_fails_when_every_menu_is_absent(device: Device):
    """Every single check's menu missing at once - the audit must still
    return a well-formed (empty) result rather than raising."""
    missing = LibRouterosError("no such command")
    client = _client(
        device,
        raise_for={
            ("ip", "service"): missing,
            ("ip", "firewall", "filter"): missing,
            ("snmp", "community"): missing,
            ("ip", "dns"): missing,
            ("system", "package", "update"): missing,
            ("interface", "wireless", "security-profiles"): missing,
            ("interface", "wifi", "security"): missing,
            ("user",): missing,
        },
    )
    result = security.run_security_audit(client)
    assert result["findings"] == []
    assert result["summary"] == {"high": 0, "medium": 0, "low": 0, "info": 0}


def test_run_security_audit_outer_backstop_survives_a_check_raising_directly(
    device: Device, monkeypatch: pytest.MonkeyPatch
):
    """Every real `_check_*` already catches its own `DeviceCommandError`
    (see test_run_security_audit_never_fails_when_every_menu_is_absent
    above) - `run_security_audit`'s own `except DeviceCommandError:
    continue` is a second, outer backstop for a hypothetical future check
    that doesn't. Proven directly here by monkeypatching `_CHECKS` with one
    check that raises without catching, alongside a normal one - the audit
    must still return the normal check's findings rather than raising."""

    def _broken_check(client: MikrotikClient) -> list[security.Finding]:
        raise DeviceCommandError(client.device.name, "some/broken/menu", "simulated failure")

    working_finding = security.Finding(
        severity="info",
        category="test",
        title="Working check ran",
        detail="detail",
        recommendation="recommendation",
    )

    def _working_check(client: MikrotikClient) -> list[security.Finding]:
        return [working_finding]

    monkeypatch.setattr(security, "_CHECKS", (_broken_check, _working_check))

    client = _client(device)
    result = security.run_security_audit(client)

    assert result["findings"] == [
        {
            "severity": "info",
            "category": "test",
            "title": "Working check ran",
            "detail": "detail",
            "recommendation": "recommendation",
        }
    ]
    assert result["summary"]["info"] == 1


def test_run_security_audit_never_leaks_a_secret(device: Device):
    """Every menu that can carry a secret-shaped field is populated with a
    distinctive marker value; multiple checks are made to actually FIRE
    (open telnet, public SNMP, open ROS6 wireless, open ROS7 wifi, sensitive
    user) - and the marker must not appear anywhere in the result, even
    though it sits right next to the fields those checks DO read."""
    marker = "MARKER_SECRET_VALUE_DO_NOT_LEAK"
    client = _client(
        device,
        data={
            ("ip", "service"): [
                {"name": "telnet", "disabled": "false", "address": "", "password": marker},
            ],
            ("ip", "firewall", "filter"): [{"chain": "input", "action": "accept", "disabled": "false"}],
            ("snmp", "community"): [{"name": "public", "addresses": "0.0.0.0/0", "authentication-password": marker}],
            ("ip", "dns"): [{"allow-remote-requests": "true"}],
            ("system", "package", "update"): [{"installed-version": "7.14", "latest-version": "7.16"}],
            ("interface", "wireless", "security-profiles"): [
                {"name": "default", "mode": "none", "wpa2-pre-shared-key": marker},
            ],
            ("interface", "wifi", "security"): [
                {"name": "sec1", "passphrase": marker, "authentication-types": "wpa2-psk"},
            ],
            ("user",): [{"name": "admin", "group": "full", "password": marker}],
        },
    )
    result = security.run_security_audit(client)
    # At least the telnet/snmp/ros6-wireless/user checks should have fired.
    assert len(result["findings"]) >= 4
    assert marker not in str(result)


# --- security_events / filter_security_events ----------------------------


def test_filter_security_events_matches_account_topic():
    rows = [
        {"topics": "system,info,account", "message": "user admin logged in via winbox from 10.0.0.5"},
        {"topics": "interface,link", "message": "ether1 link up"},
    ]
    result = security.filter_security_events(rows, limit=50)
    assert result == [rows[0]]


def test_filter_security_events_matches_critical_and_error_topics():
    rows = [
        {"topics": "system,error", "message": "something failed"},
        {"topics": "critical", "message": "config lost"},
        {"topics": "interface,link", "message": "ether1 link up"},
    ]
    result = security.filter_security_events(rows, limit=50)
    assert result == rows[:2]


def test_filter_security_events_matches_login_message_on_system_info_topic():
    rows = [
        {"topics": "system,info", "message": "user admin logged in via ssh"},
        {"topics": "system,info", "message": "router rebooted"},
    ]
    result = security.filter_security_events(rows, limit=50)
    assert result == [rows[0]]


def test_filter_security_events_ignores_unrelated_topics():
    rows = [
        {"topics": "interface,link", "message": "ether1 up"},
        {"topics": "dhcp,info", "message": "lease assigned"},
    ]
    assert security.filter_security_events(rows, limit=50) == []


def test_filter_security_events_filters_before_limiting():
    """Same ordering guarantee as `logs`' topics filter: the limit applies
    to MATCHING rows, not to the raw tail of the table."""
    rows = [{"topics": "interface,link", "message": f"noise {i}"} for i in range(10)]
    rows += [{"topics": "system,info,account", "message": f"login {i}"} for i in range(3)]
    result = security.filter_security_events(rows, limit=2)
    assert [r["message"] for r in result] == ["login 1", "login 2"]
