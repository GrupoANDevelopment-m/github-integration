rule goodware_crypto_miner : cryptocurrency miner
{
    meta:
        description = "Detects common crypto miner indicators"
        author = "goodware"
    strings:
        $a = "xmrig" ascii nocase
        $b = "kdevtmpfsi" ascii nocase
        $c = "stratum+tcp" ascii nocase
        $d = "cryptonight" ascii nocase
    condition:
        any of them
}

rule goodware_reverse_shell : backdoor
{
    meta:
        description = "Detects reverse shell patterns"
    strings:
        $a = "/dev/tcp/" ascii
        $b = "nc -e" ascii nocase
        $c = "bash -i" ascii
        $d = "0<&" ascii
    condition:
        any of them
}

rule goodware_ransom_note : ransomware
{
    meta:
        description = "Detects common ransomware note patterns"
    strings:
        $a = "your files have been encrypted" ascii nocase
        $b = "send the bitcoin" ascii nocase
        $c = ".locked" ascii nocase
        $d = "wanna" ascii nocase
    condition:
        any of them
}

rule goodware_persistence : persistence
{
    meta:
        description = "Detects persistence mechanisms"
    strings:
        $a = "/etc/ld.so.preload" ascii
        $b = "/etc/cron.d/" ascii
        $c = "crontab -e" ascii
    condition:
        any of them
}
