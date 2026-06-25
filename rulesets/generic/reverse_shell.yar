rule reverse_shell_indicators
{
    meta:
        description = "Detects common reverse-shell"
        severity = "critical"
        category = "generic"
        class = "reverse shell"

    strings:
        $rs1 = "bash -i >& /dev/tcp/" nocase
        $rs2 = "nc -e /bin/sh" nocase
        $rs3 = "socket.connect((" nocase
        $rs4 = "/bin/sh -i" nocase
        $rs5 = "python -c 'import socket" nocase
        $rs6 = "perl -e 'use Socket" nocase

    condition:
        any of them
}
