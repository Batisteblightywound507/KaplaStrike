# Crystal-Palace UDRL

A Cobalt Strike Reflective Loader built with [Crystal Palace](https://tradecraftgarden.org).

Some components are based or taken from [Crystal-Kit](https://github.com/rasta-mouse/Crystal-Kit) by [@_RastaMouse](https://twitter.com/_RastaMouse). 
Credit to him for the sleep masking implementation and significant portions of the loader architecture. 
Go check out his work and his CRTL course.

For a full breakdown of every technique implemented here, read the accompanying blog post: [Bypassing EDR in a Crystal Clear Way](https://lorenzomeacci.com/bypassing-edr-in-a-crystal-clear-way)

---

## What this does

- Module overloading via `NtCreateSection` + `NtMapViewOfSection` (no `LoadLibrary`, no CFG)
- `.pdata` registration via `RtlAddFunctionTable` for clean beacon call stack frames
- `NtContinue` entry transfer with synthetic `BaseThreadInitThunk` / `RtlUserThreadStart` frames
- API call stack spoofing for loader setup via Draugr
- XOR-encrypted beacon DLL at build time
- Sleep masking via `addhook` IAT hooking and per-section XOR encryption
- Crystal Palace YARA signature removal via `ised`

## Setup

### 1. Malleable C2 profile
```
stage {
    set cleanup "true";
    set sleep_mask "false";
    set obfuscate "false";
}

post-ex {
    set cleanup "true";
}
```

Sleep masking is handled entirely by the loader. Do not enable it in the profile.

### 2. CNA script

Load `NOUDRL.cna` in your Cobalt Strike client before generating payloads. This strips the default reflective loader from the beacon DLL so only the raw DLL is passed to the RL pipeline:
```
set BEACON_RDLL_SIZE { 
    warn("Running 'BEACON_RDLL_SIZE' for DLL " .$1. " with architecture " .$2);    
    return "0"; 
}

set BEACON_RDLL_GENERATE {
    local('$arch $beacon $fileHandle $ldr $path $payload');
    $beacon = $2;
    $arch = $3;
    return $beacon;
}
```

> **Note:** Standard Cobalt Strike artifact kit will not work with this setup. Because the beacon DLL is stripped of its default UDRL, it cannot load itself. Use a separate shellcode runner to execute the output blob after linking the DLL with Crystal-palace.

### 3. Build
```bash
make x64
./link spec/loader.spec cobalt_strike_raw.dll output.bin
```

`output.bin` is the final PIC blob. Execute it with any shellcode loader.

---

## Credits

- [Daniel Duggan (@_RastaMouse)](https://x.com/_RastaMouse) — Crystal-Kit, CRTL course
- [Alex Reid (@Octoberfest7)](https://x.com/Octoberfest73) — NtContinue entry transfer method
- [Alessandro Magnosi (@KlezVirus)](https://x.com/KlezVirus) — research and answering my dumb questions
- [Codextf2](https://x.com/codex_tf2) - answering my dumb questions about CS
- Raphael Mudge — Crystal Palace

---

## Disclaimer

This tool is for authorised security testing and research purposes only.
