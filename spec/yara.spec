x64:
    pack $NOP "b" 0x90

    # TCG_d28603cb — kills all 16 API stub hits
    ised insert "sub rsp, 0x20" $NOP +after

    # TCG_78e3597a — r0_adler32sum
    ised insert "mov eax, 0x80078071" $NOP +before

    # TCG_78e3597a — r1_PicoLoad
    ised insert "mov rdx, qword ptr [rbp-0x58]" $NOP +before

    # TCG_78e3597a — r2_GetProcAddress
    ised insert "mov edx, 0x60E0CEEF" $NOP +before

    # TCG_78e3597a — r3_bypass_cfg
    ised insert "cmp dword ptr [rbp-4], 0xC00000F4" $NOP +before

    # TCG_78e3597a — r4_ProcessImport
    ised insert "mov rdx, qword ptr [rbp+0x20]" $NOP +before

    # TCG_78e3597a — r5_HeapFree
    ised insert "mov qword ptr [r8+rcx+8], rax" $NOP +before

    # TCG_78e3597a — r6_get_text_section_size
    ised insert "cmp dword ptr [rbp-0x24], 0xEBC2F9B4" $NOP +before

    # TCG_78e3597a — r7_dprintf
    ised insert "mov r9d, 4" "mov r8d, 0x3000" $NOP +first +before

    # TCG_78e3597a — r8_cleanup_memory
    ised insert "rep stosq" $NOP +after

    # TCG_78e3597a — r9_cleanup_memory
    ised insert "mov r8d, 0xE70" $NOP +before

    disassemble "yara_fix.txt"