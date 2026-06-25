rule cosmovisor_unauthorized_upgrade_binary
{
    meta:
        description = "Detects placement of a new binary inside cosmovisor's upgrade path - flag for manual verification"
        severity = "high"
        category = "validator"
        class = "binary tamper"

    strings:
        $p1 = "cosmovisor/upgrades" nocase
        $p2 = "current/bin" nocase
        $elf = { 7f 45 4c 46 } // ELF magic bytes

    condition:
        $elf at 0 and (1 of ($p1, $p2))
}
