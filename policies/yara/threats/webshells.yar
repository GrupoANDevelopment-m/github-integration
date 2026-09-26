/*
 * Goodware v3.0 - Web shell detection
 */

rule php_webshell_generic {
    meta:
        description = "Generic PHP web shell"
    strings:
        $php1 = "<?php" ascii
        $eval = "eval(" ascii
        $exec = "exec(" ascii
        $system = "system(" ascii
        $passthru = "passthru(" ascii
        $shell_exec = "shell_exec(" ascii
        $base64 = "base64_decode" ascii
        $assert = "assert(" ascii
    condition:
        $php1 and any of ($eval, $exec, $system, $passthru, $shell_exec, $base64, $assert)
}

rule jsp_webshell {
    meta:
        description = "JSP web shell"
    strings:
        $j1 = "<%@ page" ascii wide
        $j2 = "Runtime.getRuntime()" ascii wide
        $j3 = "ProcessBuilder" ascii wide
        $j4 = "request.getParameter" ascii wide
    condition:
        $j1 and any of ($j2, $j3, $j4)
}

rule aspx_webshell {
    meta:
        description = "ASPX web shell"
    strings:
        $a1 = "<%@ Page" ascii wide
        $a2 = "Eval(" ascii wide
        $a3 = "ExecuteCmd" ascii wide
        $a4 = "Process.Start" ascii wide
    condition:
        any of them
}
