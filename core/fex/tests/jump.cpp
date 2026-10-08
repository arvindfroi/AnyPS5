// setjmp and longjmp across a discarded frame: longjmp with 0 makes setjmp return 1, and the frame
// longjmp left is gone. Exits 43 when both jumps land.
extern "C" int setjmp(void* buffer) __attribute__((returns_twice));
extern "C" [[noreturn]] void longjmp(void* buffer, int value);
extern "C" [[noreturn]] void exit(int);

alignas(16) static unsigned char buffer[96];
static int jumps = 0;

__attribute__((noinline)) static void jump(int value) {
    ++jumps;
    longjmp(buffer, value);
}

// Called through a data pointer, so the executable also has a RELA import, which the relinker needs.
void (*volatile exitPointer)(int) = exit;

extern "C" [[noreturn]] void _start(void*) {
    volatile int landed = 0;
    const int result = setjmp(buffer);
    landed = landed + 1;
    if (result == 0) jump(0);
    if (result == 1 && landed == 2) jump(40);
    exitPointer(result == 40 && jumps == 2 ? result + landed : 100 + result);
    __builtin_unreachable();
}
