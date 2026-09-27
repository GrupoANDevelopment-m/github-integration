/*
 * Goodware v3.0 - C2 (Command & Control) detection patterns
 */

rule c2_http_beacon {
    meta:
        description = "HTTP-based C2 beacon"
    strings:
        $h1 = "X-C2:" ascii
        $h2 = "session=" ascii
        $h3 = "task=" ascii
        $h4 = "beacon_id=" ascii
        $h5 = "POST /update" ascii
    condition:
        2 of them
}

rule c2_dns_tunneling {
    meta:
        description = "DNS tunneling for C2"
    strings:
        $d1 = "TXT" ascii
        $d2 = "base32" ascii
        $d3 = "base64" ascii
        $d4 = "/etc/resolv.conf" ascii
    condition:
        $d4 and 2 of ($d1, $d2, $d3)
}

rule c2_https_selfsigned {
    meta:
        description = "HTTPS C2 with self-signed cert"
    strings:
        $s1 = "self-signed" ascii
        $s2 = "INVALID" ascii
        $s3 = "Connection: keep-alive" ascii
    condition:
        any of them
}

rule c2_slack_teams {
    meta:
        description = "C2 abusing Slack/Teams webhooks"
    strings:
        $s1 = "hooks.slack.com" ascii
        $s2 = "outlook.office.com/webhook" ascii
        $s3 = "discord.com/api/webhooks" ascii
    condition:
        any of them
}

rule c2_pastebin {
    meta:
        description = "C2 using Pastebin/raw text"
    strings:
        $p1 = "pastebin.com/raw" ascii
        $p2 = "gist.githubusercontent.com" ascii
        $p3 = "throwbin.io" ascii
    condition:
        any of them
}
