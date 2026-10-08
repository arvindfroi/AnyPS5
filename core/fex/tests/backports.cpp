// Instructions that FEXCore at the fork's commit gets wrong and FEX-Emu has since fixed; build-fexcore.sh
// applies those fixes. Exits 43 when every result is right, otherwise with 100 plus a bit per wrong
// check.
#include <immintrin.h>

extern "C" [[noreturn]] void exit(int);

// Called through a data pointer, so the executable also has a RELA import, which the relinker needs.
void (*volatile exitPointer)(int) = exit;

static int failures = 0;

static void Check(bool right, int bit) {
    if (!right) failures |= 1 << bit;
}

template <typename T>
static T Opaque(T value) {
    asm volatile("" : "+m"(value));
    return value;
}

// 655102fc7d: pdep whose destination is the mask register.
static void DepositIntoMask() {
    unsigned long long value = Opaque(0x1256ull), result = Opaque(0xFF00FF00ull);
    asm("pdepq %0, %1, %0" : "+r"(result) : "r"(value));
    Check(result == 0x12005600, 0);
    unsigned narrow = Opaque(0xFF00FF00u);
    asm("pdepl %0, %1, %0" : "+r"(narrow) : "r"(static_cast<unsigned>(value)));
    Check(narrow == 0x12005600, 0);
}

// 635befb4c8: the carry of 32-bit blsr and blsmsk looked at all 64 bits of the source register.
static void LowestBitsCarry() {
    unsigned long long source = Opaque(0x100000000ull);
    unsigned result;
    unsigned char carry;
    asm("blsrl %k2, %0\n setc %1" : "=r"(result), "=r"(carry) : "r"(source) : "cc");
    Check(result == 0 && carry == 1, 1);
    asm("blsmskl %k2, %0\n setc %1" : "=r"(result), "=r"(carry) : "r"(source) : "cc");
    Check(result == 0xFFFFFFFF && carry == 1, 1);
}

// 3d65c030a8: a 32-bit cmpxchg into eax, which always matches, stored the whole of the source
// register in rax.
static void ExchangeIntoAccumulator() {
    unsigned long long accumulator = Opaque(7ull), source = Opaque(0xAAAAAAAA00000005ull);
    asm("cmpxchgl %k1, %%eax" : "+a"(accumulator) : "r"(source) : "cc");
    Check(accumulator == 5, 2);
}

// 6646a5cc72: a 16-bit shld by 16 is defined: the source moves in whole, and the carry is bit 0.
static void ShiftDoubleBySixteen() {
    unsigned short destination = Opaque(static_cast<unsigned short>(0x1235)), source = Opaque(static_cast<unsigned short>(0xABCD));
    unsigned char carry;
    asm("shldw $16, %2, %0\n setc %1" : "+r"(destination), "=r"(carry) : "r"(source) : "cc");
    Check(destination == 0xABCD && carry == 1, 3);
}

// 7f0bdf8d63: fcomi clears OF, SF and AF.
static void CompareClearsFlags() {
    unsigned char overflow, sign;
    asm("movb $0x7f, %%al\n addb $1, %%al\n fld1\n fldz\n fcomi %%st(1), %%st\n seto %0\n sets %1\n fstp %%st(0)\n fstp %%st(0)"
        : "=r"(overflow), "=r"(sign) : : "rax", "cc", "st", "st(1)");
    Check(overflow == 0 && sign == 0, 4);
}

extern "C" [[noreturn]] void _start(void*) {
    DepositIntoMask();
    LowestBitsCarry();
    ExchangeIntoAccumulator();
    ShiftDoubleBySixteen();
    CompareClearsFlags();
    exitPointer(failures == 0 ? 43 : 100 + failures);
    __builtin_unreachable();
}
