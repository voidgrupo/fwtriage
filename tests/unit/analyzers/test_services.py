from fwtriage.analyzers.services import Services, startups

from .helpers import filesystem, rules, run


def test_login_program_on_console_is_not_a_shell() -> None:
    fs = filesystem({"/etc/inittab": b"::askconsole:/usr/libexec/login.sh\nttyS0::respawn:/sbin/getty -L ttyS0\n"})
    assert rules(run(Services(), fs)) == []


def test_shell_on_console_is_reported_with_its_line() -> None:
    fs = filesystem({"/etc/inittab": b"::sysinit:/etc/init.d/rcS\nttyS0::respawn:-/bin/sh\n"})
    finding = run(Services(), fs).findings[0]
    assert finding.rule == "FWT-SVC-001"
    assert finding.location.line == 2


def test_busybox_s_scripts_run_and_stop_lines_do_not_count() -> None:
    script = b"#!/bin/sh\ncase $1 in stop) killall telnetd ;; esac\n# telnetd -l /bin/sh\ntelnetd -l /bin/login\n"
    fs = filesystem({"/etc/init.d/S50telnet": script, "/usr/sbin/telnetd": b"\x7fELF"})
    starts = startups(fs)
    assert [(start.daemon, start.line) for start in starts] == [("telnetd", 4)]
    assert rules(run(Services(), fs)) == ["FWT-SVC-002", "FWT-SVC-004"]


def test_openwrt_scripts_count_only_when_enabled() -> None:
    script = b"#!/bin/sh /etc/rc.common\nstart_service() {\n\tprocd_set_param command /usr/sbin/dropbear -F\n}\n"
    disabled = filesystem({"/etc/init.d/dropbear": script})
    enabled = filesystem({"/etc/init.d/dropbear": script}, {"/etc/rc.d/S19dropbear": "../init.d/dropbear"})
    assert startups(disabled) == []
    assert [start.daemon for start in startups(enabled)] == ["dropbear"]


def test_cleartext_daemon_present_but_not_started_is_an_indicator() -> None:
    fs = filesystem({"/usr/sbin/tftpd": b"\x7fELF"})
    finding = run(Services(), fs).findings[0]
    assert (finding.rule, finding.confidence.label) == ("FWT-SVC-003", "indicator")


def test_systemd_units_count_only_when_wanted_and_inetd_is_read() -> None:
    unit = b"[Service]\nExecStart=/usr/sbin/sshd -D\n"
    fs = filesystem(
        {
            "/lib/systemd/system/sshd.service": unit,
            "/etc/inetd.conf": b"ftp stream tcp nowait root /usr/sbin/ftpd ftpd\n",
        },
        {"/etc/systemd/system/multi-user.target.wants/sshd.service": "/lib/systemd/system/sshd.service"},
    )
    assert sorted(start.daemon for start in startups(fs)) == ["ftpd", "sshd"]


LOGIN_SH = b'#!/bin/sh\n[ "$(uci -q get system.@system[0].ttylogin)" = 1 ] || exec /bin/ash --login\nexec /bin/login\n'


def test_console_shell_through_a_wrapper_script_is_likely() -> None:
    fs = filesystem({"/etc/inittab": b"::askconsole:/usr/libexec/login.sh\n", "/usr/libexec/login.sh": LOGIN_SH})
    finding = run(Services(), fs).findings[0]
    assert (finding.rule, finding.confidence.label, finding.location.line) == ("FWT-SVC-001", "likely", 1)


def test_wrapper_is_silent_when_tty_login_is_switched_on() -> None:
    files = {
        "/etc/inittab": b"::askconsole:/usr/libexec/login.sh\n",
        "/usr/libexec/login.sh": LOGIN_SH,
        "/etc/config/system": b"config system\n\toption ttylogin '1'\n",
    }
    assert rules(run(Services(), filesystem(files))) == []


def test_router_daemons_are_in_the_inventory() -> None:
    script = b"#!/bin/sh /etc/rc.common\nprocd_set_param command /usr/sbin/odhcpd\n"
    fs = filesystem({"/etc/init.d/odhcpd": script}, {"/etc/rc.d/S35odhcpd": "../init.d/odhcpd"})
    assert [start.daemon for start in startups(fs)] == ["odhcpd"]


def test_telnet_with_a_shell_as_login_program_is_critical() -> None:
    fs = filesystem({"/etc/init.d/S50telnet": b"#!/bin/sh\ntelnetd -l /bin/sh\n", "/usr/sbin/telnetd": b"\x7fELF"})
    assert rules(run(Services(), fs)) == ["FWT-SVC-002", "FWT-SVC-004", "FWT-SVC-005"]


def test_telnet_with_login_is_not_a_shell() -> None:
    fs = filesystem({"/etc/init.d/S50telnet": b"#!/bin/sh\ntelnetd -l /bin/login\n", "/usr/sbin/telnetd": b"\x7fELF"})
    assert "FWT-SVC-005" not in rules(run(Services(), fs))


def test_dropbear_with_blank_passwords_allowed() -> None:
    fs = filesystem(
        {"/etc/init.d/S40ssh": b"#!/bin/sh\n/usr/sbin/dropbear -R -B -p 22\n", "/usr/sbin/dropbear": b"\x7fELF"}
    )
    assert "FWT-SVC-006" in rules(run(Services(), fs))
    clean = filesystem({"/etc/init.d/S40ssh": b"#!/bin/sh\n/usr/sbin/dropbear -R -p 22\n"})
    assert "FWT-SVC-006" not in rules(run(Services(), clean))


def test_sshd_permit_empty_passwords() -> None:
    fs = filesystem({"/etc/ssh/sshd_config": b"Port 22\n#PermitEmptyPasswords yes\nPermitEmptyPasswords yes\n"})
    findings = [f for f in run(Services(), fs).findings if f.rule == "FWT-SVC-006"]
    assert [(f.location.line, f.confidence.label) for f in findings] == [(3, "likely")]


def test_xinetd_enabled_services_start_and_disabled_ones_do_not() -> None:
    enabled = b"service telnet\n{\n  disable = no\n  server = /usr/sbin/telnetd\n  server_args = -l /bin/sh\n}\n"
    disabled = b"service ftp\n{\n  disable = yes\n  server = /usr/sbin/vsftpd\n}\n"
    fs = filesystem({"/etc/xinetd.d/telnet": enabled, "/etc/xinetd.d/ftp": disabled, "/usr/sbin/telnetd": b"\x7fELF"})
    starts = startups(fs)
    assert [(s.daemon, s.entry) for s in starts] == [("telnetd", "/etc/xinetd.d/telnet")]
    assert "FWT-SVC-005" in rules(run(Services(), fs))


def test_conditional_starts_are_likely_and_absent_daemons_do_not_start() -> None:
    script = b'#!/bin/sh\n[ "$enabled" -ne 1 ] && return\ntelnetd -l /bin/login\nhttpd -p 80\n'
    fs = filesystem({"/etc/init.d/S50telnet": script, "/usr/sbin/telnetd": b"\x7fELF"})
    finding = next(f for f in run(Services(), fs).findings if f.rule == "FWT-SVC-002")
    assert finding.confidence.label == "likely"
    inventory = next(f for f in run(Services(), fs).findings if f.rule == "FWT-SVC-004")
    assert inventory.evidence.excerpt == "telnetd (conditional)"


def test_block_conditions_and_inline_blocks() -> None:
    from fwtriage.analyzers.services import conditions  # noqa: PLC0415

    lines = ["case $1 in stop) killall x ;; esac", "a", "if [ x ]; then", "b", "fi", "c", "[ -f y ] && d"]
    assert conditions(lines) == [True, False, True, True, False, False, True]


def test_virtual_console_is_an_indicator_and_respawnlate_counts() -> None:
    fs = filesystem({"/etc/inittab": b"tty1::askfirst:/bin/ash --login\nttyS0::respawnlate:/bin/sh\n"})
    found = [(f.confidence.label, f.location.line) for f in run(Services(), fs).findings if f.rule == "FWT-SVC-001"]
    assert sorted(found) == [("confirmed", 2), ("indicator", 1)]


def test_dropbear_blank_password_flag_added_to_arguments() -> None:
    script = (
        b'#!/bin/sh /etc/rc.common\nstart_service() {\n\tappend args "-B"\n'
        b"\tprocd_set_param command /usr/sbin/dropbear -F $args\n}\n"
    )
    fs = filesystem(
        {"/etc/init.d/dropbear": script, "/usr/sbin/dropbear": b"\x7fELF"},
        {"/etc/rc.d/S50dropbear": "../init.d/dropbear"},
    )
    finding = next(f for f in run(Services(), fs).findings if f.rule == "FWT-SVC-006")
    assert (finding.confidence.label, finding.location.line) == ("likely", 3)


def test_a_start_inside_a_function_behind_an_early_exit_is_likely() -> None:
    from fwtriage.analyzers.services import is_gated  # noqa: PLC0415

    script = [
        "init_config() {",
        "    telnetd -l /bin/sh",
        "}",
        "start() {",
        '    if [ "$status" = "0" ]; then',
        "        exit",
        "    fi",
        "    init_config",
        "}",
    ]
    assert is_gated(script)
    assert not is_gated(["[ -x /usr/sbin/telnetd ] || exit 0", "telnetd -l /bin/login"])
