/*
 * Goodware v3.0 - APT group indicators
 * Source: MITRE ATT&CK
 */

rule apt_lazarus {
    meta:
        description = "Lazarus Group indicators"
        apt = "Lazarus"
    strings:
        $l1 = "bhPL63doHIRBaMaH" ascii
        $l2 = "wbclient" ascii
        $l3 = "/bin/bash" ascii
    condition:
        any of them
}

rule apt_fancy_bear {
    meta:
        description = "Fancy Bear (APT28) indicators"
    strings:
        $f1 = "X-Agent" ascii wide
        $f2 = "Sofacy" ascii
        $f3 = "Winexe" ascii
    condition:
        any of them
}

rule apt_cozy_bear {
    meta:
        description = "Cozy Bear (APT29) indicators"
    strings:
        $c1 = "CobaltStrike" ascii nocase
        $c2 = "WellMess" ascii
        $c3 = "Sunburst" ascii
    condition:
        any of them
}

rule apt_equation_group {
    meta:
        description = "Equation Group (NSA) indicators"
    strings:
        $e1 = "Fanny" ascii
        $e2 = "DoubleFantasy" ascii
        $e3 = "GrayFish" ascii
    condition:
        any of them
}
