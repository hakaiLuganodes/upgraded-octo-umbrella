rule generic_ld_preload_hijack{
    meta:
        description = "Detects shared object code consistent with LD_PRELOAD hijacking"
        severity = "critical"
        category = "generic"
        class = "rootkit"

    strings:
        $sym1 = "LD_PRELOAD"
        $sym2 = "dlsym"
        $hook1 = "readdir"
        $hook2 = "getdents"
        $hook3 = "execve"
        $hook4 = "open64"

    condition:
        uint32(0) == 0x464c457f and  // ELF magic
        $sym1 and $sym2 and (2 of ($hook*))
}
