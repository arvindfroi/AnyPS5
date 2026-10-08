# macos-native

Proof of concept: x86-64 guest code run natively on Apple silicon (arm64 macOS, no Rosetta) by FEXCore inside the host process, and calling a native arm64 function.

- FEXCore source: [willfaust/FEX](https://github.com/willfaust/FEX) at `ac555dd81fa84f86d1927476e152451005e78f49` (2026-08-25), the last commit before that fork's own changes became GPL-3.0-or-later; FEX-Emu code and this commit are MIT.
- `fex-macos.patch`: guards three iOS-only diagnostics so FEXCore builds for macOS.
- JIT memory: macOS refuses RWX mappings. The proofs of concept map one 1 GiB pool twice (RW and RX, `mach_vm_remap`), set `FEXCore::DualMap::WriteOffset` and hand the RX view to FEXCore through `FEXCore::Allocator::mmap`. `jit_memory_probe.c` shows which mappings macOS accepts.
- `poc_arith.cpp`: arithmetic and a loop; expects `RAX = 229`.
- `poc_native_call.cpp`: the guest calls a stub (`mov r10, rcx; mov eax, 0x1001; syscall; ret`) that reaches a native arm64 function with a string and two integers; expects `RAX = 1245`.

`./build.sh` clones the FEX commit, applies the patch, builds FEXCore and runs both.
