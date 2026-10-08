#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static const uint32_t ret42[] = {0x52800540, 0xd65f03c0};

int main(void) {
    void* rwx = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    printf("plain RWX mmap: %s\n", rwx == MAP_FAILED ? "refused" : "allowed");

    void* jit = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    printf("MAP_JIT RWX mmap: %s\n", jit == MAP_FAILED ? "refused" : "allowed");
    if (jit != MAP_FAILED) {
        pthread_jit_write_protect_np(0);
        memcpy(jit, ret42, sizeof ret42);
        pthread_jit_write_protect_np(1);
        sys_icache_invalidate(jit, sizeof ret42);
        printf("MAP_JIT + toggle -> %d\n", ((int (*)(void))jit)());
    }

    mach_vm_address_t src = 0, alias = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &src, 0x4000, VM_FLAGS_ANYWHERE);
    vm_prot_t cur, max;
    kr |= mach_vm_remap(mach_task_self(), &alias, 0x4000, 0, VM_FLAGS_ANYWHERE, mach_task_self(), src, FALSE, &cur, &max, VM_INHERIT_NONE);
    int rx = mprotect((void*)alias, 0x4000, PROT_READ | PROT_EXEC);
    printf("dual map (plain): remap=%d mprotect RX=%s\n", kr, rx == 0 ? "ok" : "refused");

    void* jit2 = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    mach_vm_address_t rw = 0;
    kr = mach_vm_remap(mach_task_self(), &rw, 0x4000, 0, VM_FLAGS_ANYWHERE, mach_task_self(), (mach_vm_address_t)jit2, FALSE, &cur, &max, VM_INHERIT_NONE);
    int p1 = mprotect((void*)rw, 0x4000, PROT_READ | PROT_WRITE);
    int p2 = mprotect(jit2, 0x4000, PROT_READ | PROT_EXEC);
    printf("dual map (MAP_JIT): remap=%d rw-alias=%s rx-orig=%s cur=%d max=%d\n", kr, p1 == 0 ? "ok" : "refused", p2 == 0 ? "ok" : "refused", cur, max);
    if (kr == 0 && p1 == 0 && p2 == 0) {
        memcpy((void*)rw, ret42, sizeof ret42);
        sys_icache_invalidate(jit2, sizeof ret42);
        printf("dual map (MAP_JIT) write via RW, run via RX -> %d\n", ((int (*)(void))jit2)());
    }
    return 0;
}
