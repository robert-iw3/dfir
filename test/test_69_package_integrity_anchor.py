"""adjudicate.pkg_modified() -- the DEFINITIVE package-integrity dimension.

Three-valued by contract: True modified, False verified intact, None NOT VERIFIABLE.
The third value carries the weight. This dimension is the strongest verdict the Linux
side reaches, on the premise that a package manager does not let installed files drift
from their recorded contents -- so a tool that could not answer must not be recorded as
either answer. "No checksum data for this package" is not evidence of tampering, and
"the audit did not run" is not evidence of integrity.

Every case below is a recorded real invocation. The clean cases matter as much as the
tampered ones: an implementation that returns True unconditionally satisfies a suite
that only ever asks about files it tampered with itself.
"""
import sys

import pytest
from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import adjudicate as adj  # noqa: E402


class R:
    """A completed subprocess, as adjudicate.run() returns one."""

    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


@pytest.fixture
def anchor(monkeypatch):
    """Pin which package manager is 'installed' and what it replies."""

    def configure(tool, result):
        monkeypatch.setattr(adj.shutil, "which", lambda c, t=tool: c if c == t else None)
        calls = []

        def fake_run(cmd):
            calls.append(cmd)
            return result

        monkeypatch.setattr(adj, "run", fake_run)
        monkeypatch.setattr(adj, "_APK_AUDIT", None)
        monkeypatch.setattr(adj, "_APK_AUDIT_OK", None)
        return calls

    return configure


# --- dpkg / debsums ---------------------------------------------------------------------
def test_debsums_clean_package_verifies_intact(anchor):
    anchor("debsums", R(stdout="", returncode=0))
    assert adj.pkg_modified("/usr/bin/passwd", "passwd") is False


def test_debsums_reports_the_changed_path(anchor):
    anchor("debsums", R(stdout="/usr/bin/ssh\n", returncode=2))
    assert adj.pkg_modified("/usr/bin/ssh", "openssh-client") is True


def test_debsums_change_in_a_sibling_file_is_not_this_files_verdict(anchor):
    anchor("debsums", R(stdout="/usr/bin/scp\n", returncode=2))
    assert adj.pkg_modified("/usr/bin/ssh", "openssh-client") is False


def test_debsums_without_md5sums_cannot_verify(anchor):
    # Note the return code: 0. A package with no checksum data reports success and says
    # so only on stderr, so the exit status decides nothing here.
    anchor("debsums", R(stderr="debsums: no md5sums for coreutils\n", returncode=0))
    assert adj.pkg_modified("/usr/bin/base64", "coreutils") is None


def test_debsums_is_asked_for_the_package_not_the_path(anchor):
    # Handed a path it exits non-zero with "invalid package name", which says nothing
    # about the file -- and read as a verdict it marks every file on the host modified.
    calls = anchor("debsums", R(stdout="", returncode=0))
    adj.pkg_modified("/usr/bin/ssh", "openssh-client")
    assert calls and calls[0][-1] == "openssh-client"


def test_debsums_multi_package_owner_uses_the_first(anchor):
    calls = anchor("debsums", R(stdout="", returncode=0))
    adj.pkg_modified("/usr/bin/ssh", "openssh-client, openssh-server")
    assert calls[0][-1] == "openssh-client"


# --- rpm --------------------------------------------------------------------------------
def test_rpm_clean_file_verifies_intact(anchor):
    anchor("rpm", R(stdout="", returncode=0))
    assert adj.pkg_modified("/usr/bin/passwd", "shadow-utils-4.17.4-1.fc42.x86_64") is False


def test_rpm_checksum_flag_on_this_path_is_modified(anchor):
    anchor("rpm", R(stdout="S.5....T.    /usr/bin/ssh\n", returncode=1))
    assert adj.pkg_modified("/usr/bin/ssh", "openssh-clients") is True


def test_rpm_verifies_the_whole_package_so_a_sibling_change_is_not_this_file(anchor):
    anchor("rpm", R(stdout="S.5....T.    /usr/bin/scp\n", returncode=1))
    assert adj.pkg_modified("/usr/bin/ssh", "openssh-clients") is False


def test_rpm_non_checksum_flags_are_not_tampering(anchor):
    # Mode or mtime drift without a content change: '5' is the checksum flag.
    anchor("rpm", R(stdout=".M......T.    /usr/bin/ssh\n", returncode=1))
    assert adj.pkg_modified("/usr/bin/ssh", "openssh-clients") is False


def test_rpm_unowned_file_cannot_verify(anchor):
    anchor("rpm", R(stdout="file /tmp/x is not owned by any package\n", returncode=1))
    assert adj.pkg_modified("/tmp/x", "bogus") is None


# --- apk --------------------------------------------------------------------------------
def test_apk_audit_lists_changed_files_relative(anchor):
    anchor("apk", R(stdout="U  usr/bin/ssh\n", returncode=0))
    assert adj.pkg_modified("/usr/bin/ssh", "openssh-client-default") is True


def test_apk_audit_clean_verifies_intact(anchor):
    anchor("apk", R(stdout="", returncode=0))
    assert adj.pkg_modified("/usr/bin/ssh", "openssh-client-default") is False


def test_apk_audit_failure_cannot_verify(anchor):
    # An empty set from a failed audit would read as "every file is intact" -- the same
    # mistake as the debsums case, in the opposite direction.
    anchor("apk", R(stderr="ERROR: unable to read database\n", returncode=1))
    assert adj.pkg_modified("/usr/bin/ssh", "openssh-client-default") is None


# --- pacman -----------------------------------------------------------------------------
def test_pacman_reports_the_altered_path(anchor):
    anchor("pacman", R(stdout="openssh: /usr/bin/ssh (Modification time mismatch)\n"
                              "openssh: 200 total files, 1 altered files\n", returncode=1))
    assert adj.pkg_modified("/usr/bin/ssh", "openssh 10.0p1-1") is True


def test_pacman_clean_verifies_intact(anchor):
    anchor("pacman", R(stdout="openssh: 200 total files, 0 altered files\n", returncode=0))
    assert adj.pkg_modified("/usr/bin/ssh", "openssh 10.0p1-1") is False


def test_pacman_is_asked_for_the_package_without_its_version(anchor):
    calls = anchor("pacman", R(stdout="openssh: 200 total files, 0 altered files\n"))
    adj.pkg_modified("/usr/bin/ssh", "openssh 10.0p1-1")
    assert calls[0][-1] == "openssh"


def test_pacman_silence_cannot_verify(anchor):
    anchor("pacman", R(stdout="", returncode=1))
    assert adj.pkg_modified("/usr/bin/ssh", "openssh 10.0p1-1") is None


# --- contract ---------------------------------------------------------------------------
def test_no_owner_is_unverifiable_not_intact(anchor):
    anchor("debsums", R(stdout="", returncode=0))
    assert adj.pkg_modified("/usr/bin/ssh", None) is None


def test_no_package_manager_is_unverifiable(monkeypatch):
    monkeypatch.setattr(adj.shutil, "which", lambda c: None)
    assert adj.pkg_modified("/usr/bin/ssh", "openssh-client") is None
