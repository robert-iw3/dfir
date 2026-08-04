#!/usr/bin/env bash
# ==============================================================================
# IR Playbook 00 - Linux Forensics Collection
# Captures a full system snapshot before any eradication action disturbs state.
# Must run FIRST in every engagement. Output: compressed archive in /var/ir/.
# ==============================================================================
set -uo pipefail

INCIDENT_ID="${IR_INCIDENT_ID:-UNKNOWN}"
ARCHIVE_DIR="/var/ir/forensics"
WORK_DIR="${ARCHIVE_DIR}/incident-${INCIDENT_ID}"
ARCHIVE="${ARCHIVE_DIR}/ir-forensics-${INCIDENT_ID}.tar.gz"

mkdir -p "${WORK_DIR}"
logger -t ir-playbook "FORENSICS: Collection started for incident ${INCIDENT_ID}"

# -- Process state -------------------------------------------------------------
ps auxf                                      > "${WORK_DIR}/process_tree.txt"        2>/dev/null || true
ps -eo pid,ppid,user,stat,comm,args          > "${WORK_DIR}/process_full.txt"        2>/dev/null || true

# Hash every running process binary - fast indicator cross-reference
while IFS= read -r pid; do
    exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null) || continue
    [[ -f "${exe}" ]] || continue
    printf '%s  %s\n' "$(sha256sum "${exe}" 2>/dev/null | cut -d' ' -f1)" "${exe}"
done < <(find /proc -maxdepth 1 -name '[0-9]*' -printf '%f\n' 2>/dev/null) \
    > "${WORK_DIR}/running_binary_hashes.txt" 2>/dev/null || true

# Command-lines and open file descriptors for all processes
for pid in $(find /proc -maxdepth 1 -name '[0-9]*' -printf '%f\n' 2>/dev/null); do
    {
        printf '\n=== PID %s ===\n' "${pid}"
        tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null; echo
        printf 'CWD: '; readlink -f "/proc/${pid}/cwd" 2>/dev/null; echo
        ls -la "/proc/${pid}/fd/" 2>/dev/null | head -30
        tr '\0' '\n' < "/proc/${pid}/environ" 2>/dev/null | grep -E 'PATH|HOME|USER|LD_' || true
    }
done > "${WORK_DIR}/proc_details.txt" 2>/dev/null || true

# -- Network state -------------------------------------------------------------
ss -tulpanm                                  > "${WORK_DIR}/sockets.txt"             2>/dev/null || \
    netstat -tulpan                          > "${WORK_DIR}/sockets.txt"             2>/dev/null || true
ss -anp  --tcp                               > "${WORK_DIR}/tcp_connections.txt"     2>/dev/null || true
ip route show                                > "${WORK_DIR}/routing_table.txt"       2>/dev/null || true
ip neigh show                                > "${WORK_DIR}/arp_table.txt"           2>/dev/null || true
iptables-save                                > "${WORK_DIR}/iptables_pre.rules"      2>/dev/null || true
nft list ruleset                             > "${WORK_DIR}/nftables_pre.rules"      2>/dev/null || true

# DNS client config
cat /etc/resolv.conf                         > "${WORK_DIR}/resolv_conf.txt"         2>/dev/null || true
cat /etc/hosts                               > "${WORK_DIR}/etc_hosts.txt"           2>/dev/null || true

# -- Persistence mechanisms ----------------------------------------------------
# Crontabs
crontab -l                                   > "${WORK_DIR}/cron_root.txt"           2>/dev/null || true
for user_home in /home/*/; do
    username=$(basename "${user_home}")
    crontab -l -u "${username}"              >> "${WORK_DIR}/cron_users.txt"         2>/dev/null || true
done
find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /var/spool/cron \
     -type f 2>/dev/null | xargs ls -la      > "${WORK_DIR}/cron_files.txt"          2>/dev/null || true
cat /etc/crontab                             >> "${WORK_DIR}/cron_files.txt"         2>/dev/null || true

# Systemd units - all states, highlight non-standard paths
systemctl list-units --all --no-pager        > "${WORK_DIR}/systemd_units.txt"       2>/dev/null || true
systemctl list-unit-files --no-pager         > "${WORK_DIR}/systemd_unit_files.txt"  2>/dev/null || true
find /etc/systemd /usr/local/lib/systemd /home -name '*.service' -o -name '*.timer'  2>/dev/null \
                                             > "${WORK_DIR}/custom_systemd_files.txt"             || true

# Init / rc scripts
ls -la /etc/init.d/                          > "${WORK_DIR}/initd.txt"               2>/dev/null || true
cat /etc/rc.local                            > "${WORK_DIR}/rc_local.txt"            2>/dev/null || true

# OpenRC services - the enumeration on a host with no systemd (Alpine, Gentoo, Devuan).
# `rc-update show` reads the /etc/runlevels symlinks; `rc-status` is deliberately not used
# because it writes a dependency cache to the endpoint under collection.
rc-update show -v                            > "${WORK_DIR}/openrc_services.txt"     2>/dev/null || true
ls -la /etc/runlevels/*/                     > "${WORK_DIR}/openrc_runlevels.txt"    2>/dev/null || true
ls -la /run/openrc/started/                  > "${WORK_DIR}/openrc_started.txt"      2>/dev/null || true

# Init script bodies and their conf.d overrides. Both run as root at boot and both carry
# payload: conf.d is sourced, so a line there executes with the service's privileges.
find /etc/init.d /etc/conf.d -maxdepth 1 -type f 2>/dev/null | while IFS= read -r f; do
    printf '\n=== %s ===\n' "${f}"; cat "${f}"
done > "${WORK_DIR}/init_scripts.txt" 2>/dev/null || true

# SSH authorized_keys for every user
find /root /home -name 'authorized_keys' 2>/dev/null | while IFS= read -r keyfile; do
    printf '\n=== %s ===\n' "${keyfile}"
    cat "${keyfile}"
done > "${WORK_DIR}/authorized_keys.txt" 2>/dev/null || true

# Shell init files (backdoor injection common here)
find /root /home -maxdepth 2 \
     \( -name '.bashrc' -o -name '.bash_profile' -o -name '.profile' \
        -o -name '.zshrc' -o -name '.bash_logout' \) 2>/dev/null | \
while IFS= read -r f; do
    printf '\n=== %s ===\n' "${f}"; cat "${f}"
done > "${WORK_DIR}/shell_init_files.txt" 2>/dev/null || true

# LD_PRELOAD / shared library hijacking
cat /etc/ld.so.preload                       > "${WORK_DIR}/ld_so_preload.txt"        2>/dev/null || true
ldconfig -p                                  > "${WORK_DIR}/ldconfig_cache.txt"       2>/dev/null || true

# SUID/SGID binaries (quick check - compare with baseline in full investigation)
find / -perm /6000 -type f 2>/dev/null       > "${WORK_DIR}/suid_sgid_files.txt"                || true

# -- File system artifacts -----------------------------------------------------
# Recently modified files in volatile/writable locations, over an explicit window.
# Not `-newer /proc/1`: procfs gives /proc/1 a moving mtime, so it matches nothing.
# IR_RECENT_MINS widens it when the intrusion predates the 24h default.
find /tmp /var/tmp /dev/shm /run /var/run \
     -type f -mmin "-${IR_RECENT_MINS:-1440}" 2>/dev/null \
                                             > "${WORK_DIR}/recently_modified.txt"               || true
# Hidden files in home directories
find /root /home -maxdepth 3 -name '.*' -type f 2>/dev/null \
                                             > "${WORK_DIR}/hidden_files.txt"                     || true
# World-writable executables (common implant locations)
find /usr /opt /var -perm -o+w -type f 2>/dev/null \
                                             > "${WORK_DIR}/world_writable_exec.txt"              || true

# -- Authentication and logs ---------------------------------------------------
tail -500 /var/log/auth.log                  > "${WORK_DIR}/auth_log.txt"            2>/dev/null || \
    journalctl -u sshd -n 500 --no-pager     >> "${WORK_DIR}/auth_log.txt"           2>/dev/null || true
# Structured journal export (consumed by journal_analysis.py for offline re-analysis).
# Bounded by time + line cap so a multi-GB journal can't stall collection.
journalctl -o json --no-pager --since "14 days ago" -n 300000 \
                                             > "${WORK_DIR}/journal.json"            2>/dev/null || true
last -500 -F                                 > "${WORK_DIR}/last_logins.txt"         2>/dev/null || true
lastb -100                                   > "${WORK_DIR}/failed_logins.txt"       2>/dev/null || true
who                                          > "${WORK_DIR}/current_sessions.txt"    2>/dev/null || true

# The RAW login databases, not only the output of the tools that read them. `last`/`lastb`
# are the host's account of itself; a truncated wtmp or a replaced `last` reports clean.
# These parse offline, where the machine under investigation cannot edit the answer.
for _rec in /var/log/wtmp /var/log/btmp /var/log/lastlog /run/utmp /var/run/utmp; do
    [[ -f "${_rec}" ]] && cp -p "${_rec}" "${WORK_DIR}/$(basename "${_rec}")" 2>/dev/null
done
# Sizes recorded separately: a zero-length wtmp IS the finding, and it is easy to miss in a
# listing of an archive nobody unpacks.
ls -l /var/log/wtmp /var/log/btmp /var/log/lastlog /run/utmp /var/run/utmp 2>/dev/null \
                                             > "${WORK_DIR}/login_record_sizes.txt"  || true

# At jobs
atq                                          > "${WORK_DIR}/at_jobs.txt"             2>/dev/null || true
find /var/spool/at -type f 2>/dev/null | \
    xargs -r cat                             >> "${WORK_DIR}/at_jobs.txt"            2>/dev/null || true

# Kernel modules (rootkit check)
lsmod                                        > "${WORK_DIR}/kernel_modules.txt"      2>/dev/null || true
# Flag modules without a corresponding file in the standard kernel module tree (in-memory rootkit indicator)
{
    echo "=== Kernel modules with no file on disk (rootkit LKM indicator) ==="
    lsmod 2>/dev/null | awk 'NR>1 {print $1}' | while IFS= read -r _mod; do
        _path=$(modinfo -n "${_mod}" 2>/dev/null || true)
        if [[ -z "${_path}" ]]; then
            printf 'NO_FILE: %s\n' "${_mod}"
        elif [[ "${_path}" != "/lib/modules/$(uname -r)"* ]]; then
            printf 'OUTSIDE_TREE: %s  PATH: %s\n' "${_mod}" "${_path}"
        fi
    done
} >> "${WORK_DIR}/kernel_modules.txt" 2>/dev/null || true

# -- ELF entropy scan (high-entropy = packed/encrypted implants) ---------------
# Shannon entropy > 7.2 on an ELF binary strongly suggests packing or encryption
{
    printf 'entropy\tsize_bytes\tpath\n'
    for _scan_dir in /tmp /var/tmp /dev/shm /run /home /root /opt /var/www; do
        [[ -d "${_scan_dir}" ]] || continue
        find "${_scan_dir}" -maxdepth 4 -type f -executable 2>/dev/null | while IFS= read -r _f; do
            file "${_f}" 2>/dev/null | grep -q 'ELF' || continue
            _size=$(stat -c%s "${_f}" 2>/dev/null) || continue
            [[ "${_size}" -lt 64 || "${_size}" -gt 52428800 ]] && continue
            _entropy=$(python3 -c "
import sys, math, collections
try:
    d = open(sys.argv[1], 'rb').read(65536)
    if d:
        c = collections.Counter(d); t = len(d)
        print(f'{-sum((v/t)*math.log2(v/t) for v in c.values() if v):.2f}')
except: pass
" "${_f}" 2>/dev/null) || continue
            [[ -z "${_entropy}" ]] && continue
            awk "BEGIN{exit(\"${_entropy}\"+0>7.2?0:1)}" 2>/dev/null && \
                printf '%s\t%s\t%s\n' "${_entropy}" "${_size}" "${_f}"
        done
    done
} > "${WORK_DIR}/high_entropy_elf.txt" 2>/dev/null || true

# -- Hidden PID detection (rootkit indicator) ----------------------------------
# Rootkits hook getdents64() to hide entries from readdir but /proc/[pid]/maps still exists
{
    echo "=== PIDs readable via /proc/[pid]/maps but hidden from directory listing ==="
    for _pid_maps in /proc/[0-9]*/maps; do
        _pid=$(basename "$(dirname "${_pid_maps}")")
        [[ "${_pid}" =~ ^[0-9]+$ ]] || continue
        if ! ls "/proc/${_pid}" &>/dev/null 2>&1; then
            _comm=$(tr '\0' ' ' < "/proc/${_pid}/cmdline" 2>/dev/null | head -c 100 || true)
            printf 'HIDDEN PID: %s  CMDLINE: %s\n' "${_pid}" "${_comm}"
        fi
    done
} > "${WORK_DIR}/hidden_pids.txt" 2>/dev/null || true

# -- Anonymous executable memory mappings (shellcode/injection indicators) ------
# r-xp mappings with device 00:00 and inode 0 = no backing file = injected shellcode
{
    echo "=== Processes with anonymous executable memory regions ==="
    for _pid in $(find /proc -maxdepth 1 -name '[0-9]*' -printf '%f\n' 2>/dev/null); do
        _maps="/proc/${_pid}/maps"
        [[ -r "${_maps}" ]] || continue
        if grep -qP '^[0-9a-f]+-[0-9a-f]+ r.xp 00000000 00:00 0\s+$' "${_maps}" 2>/dev/null; then
            _comm=$(cat "/proc/${_pid}/comm" 2>/dev/null || echo "unknown")
            _exe=$(readlink "/proc/${_pid}/exe" 2>/dev/null || echo "unknown")
            printf 'PID: %s  COMM: %s  EXE: %s\n' "${_pid}" "${_comm}" "${_exe}"
            grep -P '^[0-9a-f]+-[0-9a-f]+ r.xp 00000000 00:00 0\s+$' "${_maps}" 2>/dev/null | head -5
        fi
    done
} > "${WORK_DIR}/anon_exec_maps.txt" 2>/dev/null || true

# -- Immutable file attributes (chattr +i blocks cleanup) ---------------------
lsattr /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/rc.local \
       /etc/ld.so.preload /etc/nsswitch.conf /etc/hosts 2>/dev/null \
    > "${WORK_DIR}/lsattr_critical.txt" 2>/dev/null || true

# -- nsswitch.conf and sudoers (privilege escalation / credential intercept) ---
cat /etc/nsswitch.conf                       > "${WORK_DIR}/nsswitch_conf.txt"       2>/dev/null || true
{
    printf '=== /etc/sudoers ===\n'; cat /etc/sudoers 2>/dev/null
    # Each drop-in under its own name. Concatenating them bare lost which file a rule came
    # from, and the filename is evidence: a rule in a package's drop-in and the same rule in
    # one an intruder created are the same text and not the same finding.
    find /etc/sudoers.d -type f 2>/dev/null | sort | while IFS= read -r _sd; do
        printf '\n=== %s ===\n' "${_sd}"; cat "${_sd}" 2>/dev/null
    done
} > "${WORK_DIR}/sudoers.txt" 2>/dev/null || true

# -- Filesystem timeline (MACB) -----------------------------------------------------------
# Individual artifacts say what is on the host. A timeline says what happened, in what order,
# and that ordering is what turns a pile of findings into an account of an intrusion. Nothing
# else collected here can answer "what else changed in the ninety seconds around this".
#
# Emitted in The Sleuth Kit's BODY FILE format, so it feeds `mactime` and every tool that
# already reads it, rather than inventing a layout an analyst would have to be taught:
#
#   MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
#
# The MD5 column is 0: hashing every file on a production endpoint is not affordable, and
# running_binary_hashes.txt already covers the executables that matter.
#
# Scope is bounded on purpose. A timeline of `/` on a real host is tens of millions of rows,
# most of them noise; these are the directories persistence, implants and staging live in.
# -xdev is not optional — without it a network mount drags the collection across the wire.
IR_TIMELINE_MAX="${IR_TIMELINE_MAX:-400000}"
_tl_dirs=()
for _d in /etc /usr/bin /usr/sbin /usr/local /usr/lib/systemd /lib/systemd /opt /srv \
          /root /home /var/www /var/spool /var/log /boot /tmp /var/tmp /dev/shm /run; do
    [[ -e "${_d}" ]] && _tl_dirs+=("${_d}")
done
{
    # %A@/%T@/%C@ carry a fractional part and %B@ is 0 where the filesystem or findutils has
    # no birth time; awk truncates to whole seconds, which is what the body format expects.
    find "${_tl_dirs[@]}" -xdev \( -type f -o -type d -o -type l \) \
         -printf '0|%p|%i|%M|%U|%G|%s|%A@|%T@|%C@|%B@\n' 2>/dev/null \
    | awk -F'|' 'BEGIN{OFS="|"}
                 {for(i=8;i<=11;i++){split($i,a,".");$i=a[1]}
                  # find reports -1 for a birth time the filesystem cannot supply (overlayfs,
                  # older ext4). The body format reads that as a real 1969 timestamp and
                  # mactime would sort every such file to the top of the timeline; 0 is the
                  # format is own "unknown".
                  if($11+0<0)$11=0
                  print}' \
    | head -n "${IR_TIMELINE_MAX}"
} > "${WORK_DIR}/filesystem_timeline.body" 2>/dev/null || true
# Whether the cap was hit, because a truncated timeline that does not say so is a timeline an
# analyst will read as complete.
{
    printf 'rows: %s\n' "$(wc -l < "${WORK_DIR}/filesystem_timeline.body" 2>/dev/null || echo 0)"
    printf 'cap: %s\n' "${IR_TIMELINE_MAX}"
    printf 'scope: %s\n' "${_tl_dirs[*]}"
    printf 'format: TSK body file (mactime -b) — MD5 column is 0 by design\n'
} > "${WORK_DIR}/filesystem_timeline.meta.txt" 2>/dev/null || true

# -- eBPF state (where a modern rootkit lives) --------------------------------------------
# edr_hunt.py already REASONS about eBPF — pinned objects, implant-held prog/map fds — but
# nothing preserved the state it reasoned over. A finding says "verify each is from an expected
# agent" and the evidence to do that verification was gone by the time anyone read it.
#
# `bpftool` is frequently absent on a production host. Its absence is recorded rather than
# passed over: "no eBPF programs were loaded" and "we could not ask" are different answers, and
# only one of them is evidence.
{
    printf '=== unprivileged_bpf_disabled ===\n'
    cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || printf 'unavailable\n'
    printf '\n=== bpf_jit_enable / bpf_jit_harden ===\n'
    cat /proc/sys/net/core/bpf_jit_enable  2>/dev/null || printf 'unavailable\n'
    cat /proc/sys/net/core/bpf_jit_harden  2>/dev/null || printf 'unavailable\n'
    printf '\n=== pinned objects under /sys/fs/bpf ===\n'
    if [[ -d /sys/fs/bpf ]]; then
        find /sys/fs/bpf -mindepth 1 2>/dev/null | head -500
    else
        printf 'bpffs not mounted\n'
    fi
    printf '\n=== bpftool prog list ===\n'
    if command -v bpftool >/dev/null 2>&1; then
        bpftool prog list 2>&1 | head -500
        printf '\n=== bpftool map list ===\n'
        bpftool map list  2>&1 | head -500
        printf '\n=== bpftool link list ===\n'
        bpftool link list 2>&1 | head -200
    else
        printf 'bpftool NOT PRESENT on this host - loaded programs could not be enumerated\n'
    fi
} > "${WORK_DIR}/bpf_objects.txt" 2>/dev/null || true

# -- Kernel taint (a loaded module is sticky in the mask, even after it unlinks) -----------
# The numeric mask plus the decoded letters. A rootkit that unloads itself still leaves the
# taint set, which is why this is worth capturing separately from the module list.
{
    printf 'tainted: '; cat /proc/sys/kernel/tainted 2>/dev/null || printf 'unavailable\n'
    printf '\n=== /proc/version ===\n';    cat /proc/version    2>/dev/null
    printf '\n=== /proc/cmdline ===\n';    cat /proc/cmdline    2>/dev/null
    printf '\n=== lockdown ===\n'
    cat /sys/kernel/security/lockdown 2>/dev/null || printf 'unavailable\n'
    printf '\n=== kptr_restrict / dmesg_restrict / ptrace_scope ===\n'
    for _s in /proc/sys/kernel/kptr_restrict /proc/sys/kernel/dmesg_restrict \
              /proc/sys/kernel/yama/ptrace_scope; do
        printf '%s: ' "${_s}"; cat "${_s}" 2>/dev/null || printf 'unavailable\n'
    done
} > "${WORK_DIR}/kernel_taint.txt" 2>/dev/null || true

# -- File capabilities (SUID-equivalent privilege that `find -perm /6000` misses) ----------
# A binary with cap_setuid+ep escalates exactly like a SUID binary and carries no SUID bit, so
# the SUID sweep above reports nothing. Bounded to the directories executables live in rather
# than walking the whole filesystem twice.
{
    for _cdir in /usr /opt /usr/local /srv; do
        [[ -d "${_cdir}" ]] && getcap -r "${_cdir}" 2>/dev/null
    done
} > "${WORK_DIR}/file_capabilities.txt" 2>/dev/null || true

# -- Shell history (what was actually typed) ----------------------------------------------
# The commands themselves, per user and per shell. `history -c` and a truncated file are both
# findings in their own right, which is why the sizes are recorded beside the contents.
{
    find /root /home -maxdepth 3 \
         \( -name '.bash_history' -o -name '.zsh_history' -o -name '.sh_history' \
            -o -name '.python_history' -o -name '.mysql_history' \) 2>/dev/null | sort | \
    while IFS= read -r _h; do
        printf '\n=== %s (%s bytes) ===\n' "${_h}" "$(stat -c%s "${_h}" 2>/dev/null || echo '?')"
        cat "${_h}" 2>/dev/null
    done
} > "${WORK_DIR}/bash_history.txt" 2>/dev/null || true

# -- SSH client state (where this host reached, and what it trusted) -----------------------
# known_hosts names the machines this host connected TO, which is the lateral-movement map
# from the source side; config and the client keys say how.
{
    find /root /home -maxdepth 3 -path '*/.ssh/*' \
         \( -name 'known_hosts*' -o -name 'config' \) 2>/dev/null | sort | \
    while IFS= read -r _k; do
        printf '\n=== %s ===\n' "${_k}"; cat "${_k}" 2>/dev/null
    done
} > "${WORK_DIR}/ssh_known_hosts.txt" 2>/dev/null || true

# -- Compress and clean up -----------------------------------------------------
tar czf "${ARCHIVE}" -C "${ARCHIVE_DIR}" "incident-${INCIDENT_ID}/" 2>/dev/null
rm -rf "${WORK_DIR}"
chmod 600 "${ARCHIVE}"

logger -t ir-playbook "FORENSICS: Archive saved → ${ARCHIVE}"

python3 -c "
import json
print(json.dumps({
    'phase': 'forensics',
    'status': 'success',
    'archive': '${ARCHIVE}',
    'incident_id': '${INCIDENT_ID}'
}))
"
