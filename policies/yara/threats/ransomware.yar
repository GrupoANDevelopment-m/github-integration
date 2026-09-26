/*
 * Goodware v3.0 - Ransomware family detection
 */

rule wannacry_indicators {
    meta:
        description = "WannaCry ransomware indicators"
    strings:
        $w1 = "WannaCry" ascii wide
        $w2 = "WNcry" ascii wide
        $w3 = "@WanaDecryptor" ascii wide
        $w4 = ".wncry" ascii
        $mssec = "mssecsvc.exe" ascii nocase
    condition:
        any of them
}

rule locky_indicators {
    meta:
        description = "Locky ransomware indicators"
    strings:
        $l1 = "Locky" ascii wide
        $l2 = "_Locky_recover_instructions.txt" ascii
        $l3 = ".locky" ascii
    condition:
        any of them
}

rule ryuk_indicators {
    meta:
        description = "Ryuk ransomware indicators"
    strings:
        $r1 = "Ryuk" ascii wide
        $r2 = "RyukReadMe" ascii wide
        $r3 = "HERMES" ascii wide
    condition:
        any of them
}

rule conti_indicators {
    meta:
        description = "Conti ransomware indicators"
    strings:
        $c1 = "CONTI" ascii wide
        $c2 = ".conti" ascii
    condition:
        any of them
}

rule revil_indicators {
    meta:
        description = "REvil/Sodinokibi ransomware indicators"
    strings:
        $r1 = "REvil" ascii
        $r2 = "sodinokibi" ascii
        $r3 = ".sodinokibi" ascii
    condition:
        any of them
}
