rule slashing_db_tamper_indicator
{
    meta:
        description = "Detects patterns to edit slashing_protection"
        severity = "high"
        author = "Syam SV"
        category = "validator"
        class = "slashing protection"

    strings:
        $s1 = "slashing_protection" nocase
        $s2 = "priv_validator_state" nocase
        $s3 = "double_sign" nocase
        $s4 = "highest_block" nocase
        $s5 = "json.dump" nocase
        $s6 = "writeFileSync" nocase

    condition:
        (1 of ($s1,$s2,$s3,$s4)) and (1 of ($s5,$s6))
}
