/*
 * Goodware v3.0 - Packer / crypter detection
 */

rule upx_packed {
    meta:
        description = "UPX-packed binary"
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "$Info: This file is packed with the UPX executable packer" ascii
    condition:
        any of them
}

rule vmprotect {
    meta:
        description = "VMProtect-packed binary"
    strings:
        $v1 = "VMProtect" ascii wide
        $v2 = ".vmp0" ascii
        $v3 = ".vmp1" ascii
    condition:
        any of them
}

rule themida {
    meta:
        description = "Themida-packed binary"
    strings:
        $t1 = "Themida" ascii wide
        $t2 = "WinLicense" ascii wide
    condition:
        any of them
}

rule mimikatz_strings {
    meta:
        description = "Mimikatz credential dumper"
    strings:
        $m1 = "sekurlsa::logonpasswords" ascii
        $m2 = "lsadump::sam" ascii
        $m3 = "logonPasswords" ascii
        $m4 = "wdigest" ascii
        $m5 = "kerberos" ascii
    condition:
        any of them
}
