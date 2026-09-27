/*
 * Goodware v3.0 - Crypto miner detection
 */

rule xmrig_generic {
    meta:
        description = "XMRig miner"
    strings:
        $x1 = "xmrig" ascii nocase
        $x2 = "RandomX" ascii
        $x3 = "stratum+tcp://" ascii
        $x4 = "cryptonight" ascii nocase
        $x5 = "rx/0" ascii
    condition:
        any of them
}

rule ethminer_generic {
    meta:
        description = "Ethereum miner"
    strings:
        $e1 = "ethminer" ascii nocase
        $e2 = "stratum" ascii
        $e3 = "ethereum" ascii nocase
        $e4 = "ethash" ascii nocase
    condition:
        any of them
}

rule cgminer_generic {
    meta:
        description = "CGMiner or BFGMiner"
    strings:
        $c1 = "cgminer" ascii nocase
        $c2 = "bfgminer" ascii nocase
        $c3 = "asic" ascii
    condition:
        any of them
}

rule nicehash_generic {
    meta:
        description = "NiceHash miner"
    strings:
        $n1 = "nicehash" ascii nocase
        $n2 = "miner.exe" ascii
    condition:
        any of them
}
