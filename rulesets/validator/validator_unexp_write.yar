rule validator_keystore_unexpected_write_tool
{
    meta:
        description = "Detects scripts/binaries for possible tamper tooling"
        severity = "critical"
        author = "Syam SV"
        category = "validator"
        class = "key tamper"

    strings:
        $path1  = "keystore-" nocase
        $path2  = "priv_validator" nocase
        $path3  = "priv_validator_key.json" nocase
        $path4  = "voting-keystore.json" nocase
        $path5  = "slashing_protection.json" nocase
        $path6  = "validator-keypair.json" nocase
        $path7  = "validator_keys" nocase
        $path8  = "/chains/polkadot/keystore" nocase
        $path9  = "/chains/kusama/keystore" nocase
        $path10 = "/chains/westend/keystore" nocase
        $path11 = "/chains/rococo/keystore" nocase
        $path12 = "/keystore" nocase
        $path13 = /\b[a-f0-9]{72,128}\b/ nocase

        // write/delete primitives
        $write1 = "os.remove" nocase
        $write2 = "shutil.rmtree" nocase
        $write3 = "unlink(" nocase
        $write4 = "open(" nocase
        $write5 = "fs.writeFileSync" nocase

    condition:
        (1 of ($path*)) and (2 of ($write*))
}
