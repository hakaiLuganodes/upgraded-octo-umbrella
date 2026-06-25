rule validator_key_exfil_strings {
    meta:
        description = "Detects if keys are moved out/located of the machine though network calls"
        severity = "critical"
        author = "Syam SV"
        category = "validator"
        class = "key exfiltration"

    strings:
        $key1 = "priv_validator_key.json" nocase
        $key2 = "voting-keystore.json" nocase
        $key3 = "slashing_protection.json" nocase
        $key4 = "validator-keypair.json" nocase
        $key5 = "validator_keys" nocase
        $exfil1 = "curl" fullword
        $exfil2 = "wget" fullword
        $exfil3 = "base64 -w0" nocase
        $exfil4 = "tar -czf" nocase
        $net1 = "POST" fullword
        $net2 = /https?:\/\/[a-zA-Z0-9\.\-]+\/[a-zA-Z0-9\/_\-]*/ nocase

    condition:
            (1 of ($key*)) and (1 of ($exfil*)) and (1 of ($net*))
    }

rule polkadot_validator_key_exfil{
        meta:
            description = "Detects tooling that locates and exfiltrates Polkadot/Kusama/Substrate validator session keys"
            severity = "critical"
            author = "Syam SV"
            category = "validator"

        strings:
            // substrate/polkadot keystore locations
            $path1 = "/chains/polkadot/keystore" nocase
            $path2 = "/chains/kusama/keystore" nocase
            $path3 = "/chains/westend/keystore" nocase
            $path4 = "/chains/rococo/keystore" nocase
            $path5 = "/keystore" nocase
            $exfil1 = "curl" fullword
            $exfil2 = "wget" fullword
            $exfil3 = "base64 -w0" nocase
            $exfil4 = "tar -czf" nocase
            $net1 = "POST" fullword
            $net2 = /https?:\/\/[a-zA-Z0-9\.\-]+\/[a-zA-Z0-9\/_\-]*/ nocase
            $hexfile = /\b[a-f0-9]{72,128}\b/ nocase

        condition:
            (
                (
                    1 of ($path*)
                    or
                    $hexfile
                )
                and
                1 of ($exfil*)
                and
                1 of ($net*)
            )
    }
