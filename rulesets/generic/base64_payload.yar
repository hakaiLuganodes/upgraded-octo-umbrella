rule suspicious_base64_payload_in_script
{
    meta:
        description = "Detects shell or python scripts containing large base64 blobs"
        severity = "high"
        category = "generic"
        class = "malware base64"

    strings:
        $b64_pipe1 = "base64 -d" nocase
        $b64_pipe2 = "base64 --decode" nocase
        $b64_pipe3 = "b64decode" nocase
        $exec1 = "| bash" nocase
        $exec2 = "| sh" nocase
        $exec3 = "exec(" nocase
        $exec4 = "eval(" nocase

    condition:
        (1 of ($b64_pipe*)) and (1 of ($exec*))
}
