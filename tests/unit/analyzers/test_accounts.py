from fwtriage.analyzers.accounts import Accounts, parse

from .helpers import filesystem, rules, run


def test_empty_password_on_a_login_account() -> None:
    fs = filesystem({"/etc/passwd": b"guest::1000:1000::/home:/bin/sh\n"})
    analysis = run(Accounts(), fs)
    assert rules(analysis) == ["FWT-ACC-001"]
    assert analysis.findings[0].location.line == 1


def test_shadow_is_preferred_over_passwd() -> None:
    fs = filesystem({"/etc/passwd": b"root:x:0:0::/root:/bin/sh\n", "/etc/shadow": b"root::0:0:99999:7:::\n"})
    finding = run(Accounts(), fs).findings[0]
    assert finding.location.entry == "/etc/shadow"


def test_second_uid_zero_is_reported_even_without_login() -> None:
    fs = filesystem({"/etc/passwd": b"root:*:0:0::/root:/bin/sh\nops:*:0:0::/:/bin/false\n"})
    assert rules(run(Accounts(), fs)) == ["FWT-ACC-004"]


def test_locked_and_nologin_accounts_are_silent() -> None:
    passwd = b"root:x:0:0::/root:/bin/sh\ndaemon:x:1:1::/:/sbin/nologin\nlp::7:7::/:/bin/false\n"
    shadow = b"root:!:0:0:99999:7:::\ndaemon:*:0:0:99999:7:::\n"
    assert rules(run(Accounts(), filesystem({"/etc/passwd": passwd, "/etc/shadow": shadow}))) == []


def test_comments_and_malformed_lines_are_ignored() -> None:
    fs = filesystem({"/etc/passwd": b"# guest::1000:1000::/home:/bin/sh\nbroken:line\n"})
    assert parse(fs) == []
    assert rules(run(Accounts(), fs)) == []
