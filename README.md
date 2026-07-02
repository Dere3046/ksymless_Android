# ksymless_Android

ARM64 implementation of [ksymless](https://github.com/rota1001/ksymless) for Android GKI kernels.
discovers kallsyms data and sys_call_table without exported kernel symbols.

kallsyms internals are described in [xcellerator's post](https://xcellerator.github.io/posts/linux_rootkits_11/).

## how it works

adapted from the original x86_64 ksymless technique:

1. walks x29 frame pointer chain to find do_el0_svc return addresses
2. scans ADRP+ADD+B patterns to locate sys_call_table (ARM64 equivalent of GOT scan)
3. scans kernel .rodata for the kallsyms_token_index structural signature
4. locates kallsyms_offsets at the next 8-byte boundary after token_index + 512
5. verifies with sprint_symbol, confirms by longest sorted u32 run
6. computes all 8 kallsyms data structures from kernel source layout
7. implements kallsyms_name_to_addr and sym_name_at
8. verifies with kprobe when available

## requirements

- ARM64 device with GKI kernel
- sprint_symbol exported
- kprobe available for verification (optional, core logic works without it)

## credits

Thanks to [汐の月](https://www.coolapk.com/u/1550124) for providing
the device for GKI 6.6 testing.

Thanks to [阿尔托莉雅·潘德拉贡](https://www.coolapk.com/u/41654149) for providing
the device for GKI 6.1 testing.

## license

GPL-2.0
