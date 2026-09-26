/*
 * Goodware v3.0 - YARA rules for reverse shell detection
 * Source: community contributions + Goodware team
 */
rule reverse_shell_nc {
    meta:
        description = "Detects netcat reverse shell attempts"
        author = "Goodware v3.0"
        severity = "critical"
        cve = "N/A"
        family = "shellcode"
    strings:
        $nc1 = "nc -e" ascii wide
        $nc2 = "ncat -e" ascii wide
        $nc3 = "/bin/sh -i" ascii wide
        $nc4 = "bash -i" ascii wide
    condition:
        any of them
}

rule python_reverse_shell {
    meta:
        description = "Detects Python-based reverse shells"
        severity = "critical"
    strings:
        $py1 = "import socket" ascii
        $py2 = "import subprocess" ascii
        $py3 = "os.dup2" ascii
        $py4 = "subprocess.call" ascii
        $py5 = "/bin/sh" ascii
    condition:
        all of them
}

rule perl_reverse_shell {
    meta:
        description = "Detects Perl-based reverse shells"
        severity = "critical"
    strings:
        $pl1 = "use Socket" ascii
        $pl2 = "/bin/sh" ascii
        $pl3 = "socket(SOCK" ascii
    condition:
        all of them
}

rule php_reverse_shell {
    meta:
        description = "Detects PHP web shell"
        severity = "critical"
    strings:
        $php1 = "<?php" ascii
        $php2 = "system(" ascii
        $php3 = "exec(" ascii
        $php4 = "passthru(" ascii
        $php5 = "shell_exec(" ascii
    condition:
        $php1 and any of ($php2, $php3, $php4, $php5)
}

rule powershell_download {
    meta:
        description = "Detects PowerShell download cradle"
        severity = "high"
    strings:
        $ps1 = "DownloadString" ascii wide
        $ps2 = "DownloadFile" ascii wide
        $ps3 = "IEX" ascii wide
        $ps4 = "Invoke-Expression" ascii wide
        $ps5 = "Net.WebClient" ascii wide
    condition:
        any of them
}

rule mimikatz_indicators {
    meta:
        description = "Detects mimikatz and similar credential dumpers"
        severity = "critical"
    strings:
        $mk1 = "sekurlsa::logonpasswords" ascii wide
        $mk2 = "lsadump::sam" ascii wide
        $mk3 = "kerberos::list" ascii wide
        $mk4 = "privilege::debug" ascii wide
        $mk5 = "token::elevate" ascii wide
    condition:
        any of them
}

rule ransomware_extension {
    meta:
        description = "Common ransomware file extensions"
        severity = "critical"
    strings:
        $e1 = ".locked" ascii wide
        $e2 = ".encrypted" ascii wide
        $e3 = ".crypto" ascii wide
        $e4 = ".cerber" ascii wide
        $e5 = ".zepto" ascii wide
    condition:
        any of them
}

rule xmrig_miner {
    meta:
        description = "Detects XMRig crypto miner"
        severity = "high"
    strings:
        $x1 = "xmrig" ascii wide
        $x2 = "cryptonight" ascii wide
        $x3 = "stratum+tcp" ascii wide
        $x4 = "randomx" ascii wide
    condition:
        any of them
}

rule meterpreter {
    meta:
        description = "Detects Meterpreter payload indicators"
        severity = "critical"
    strings:
        $m1 = "metsrv" ascii wide
        $m2 = "stdapi_sys_process_execute" ascii wide
        $m3 = "PAYLOAD_UUID" ascii wide
    condition:
        any of them
}

rule cobalt_strike {
    meta:
        description = "Detects Cobalt Strike beacon"
        severity = "critical"
    strings:
        $cs1 = "%s as %s\\%s: " ascii wide
        $cs2 = "beacon.dll" ascii wide
        $cs3 = "cobaltstrike" ascii nocase wide
    condition:
        any of them
}

rule suspicious_powershell_encoded {
    meta:
        description = "PowerShell with -EncodedCommand"
        severity = "high"
    strings:
        $ps1 = "-EncodedCommand" ascii wide
        $ps2 = "-enc " ascii wide
        $ps3 = "FromBase64String" ascii wide
    condition:
        any of them
}
