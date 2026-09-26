/*
 * Goodware v3.0 - Data exfiltration patterns
 */

rule dns_exfil {
    meta:
        description = "DNS-based data exfiltration"
        severity = "high"
    strings:
        $d1 = "TXT" ascii
        $d2 = "base32" ascii
        $d3 = "base64" ascii
        $d4 = "/etc/resolv.conf" ascii
    condition:
        $d4 and any of ($d1, $d2, $d3)
}

rule http_exfil {
    meta:
        description = "HTTP-based data exfiltration"
        severity = "high"
    strings:
        $h1 = "Content-Type: application/octet-stream" ascii
        $h2 = "POST" ascii
        $h3 = "Authorization:" ascii
        $h4 = "X-Exfil:" ascii
    condition:
        $h2 and any of ($h1, $h3, $h4)
}

rule archive_creation {
    meta:
        description = "Mass archive creation (possible staging)"
        severity = "medium"
    strings:
        $a1 = "tar -czf" ascii
        $a2 = "zip -r" ascii
        $a3 = "7z a" ascii
        $a4 = "rar a" ascii
    condition:
        any of them
}
