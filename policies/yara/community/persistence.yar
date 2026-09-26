/*
 * Goodware v3.0 - Persistence mechanism detection
 */

rule cron_persistence {
    meta:
        description = "Suspicious cron entries"
        severity = "high"
    strings:
        $c1 = "/etc/cron.d" ascii
        $c2 = "@reboot" ascii
        $c3 = "(crontab -l" ascii
    condition:
        any of them
}

rule systemd_persistence {
    meta:
        description = "Suspicious systemd services"
        severity = "high"
    strings:
        $s1 = "/etc/systemd/system/" ascii
        $s2 = "ExecStart=" ascii
        $s3 = "[Service]" ascii
        $s4 = "/tmp/" ascii
    condition:
        $s1 and $s2 and $s3 and $s4
}

rule bashrc_persistence {
    meta:
        description = "Suspicious bashrc modifications"
        severity = "medium"
    strings:
        $b1 = ".bashrc" ascii
        $b2 = "curl " ascii
        $b3 = "wget " ascii
        $b4 = "nc " ascii
    condition:
        $b1 and any of ($b2, $b3, $b4)
}

rule ld_preload {
    meta:
        description = "LD_PRELOAD hijacking"
        severity = "critical"
    strings:
        $l1 = "LD_PRELOAD" ascii
        $l2 = "/etc/ld.so.preload" ascii
    condition:
        any of them
}
