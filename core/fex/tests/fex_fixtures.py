"""Small PS5-style x86-64 ELF programs, built byte by byte, for the arm64 guest runner."""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../relinker/relinker/tests/macos"))
from nid import nid  # noqa: E402

PT_LOAD = 1
PT_DYNAMIC = 2
PT_SCE_VERSION = 0x6FFFFF01
CODE = 0x4000
DATA = 0x5000


def program(code, imports, data=b"", slots=8):
    """An executable whose code at CODE calls imports through a GOT at DATA ([rip+got(i)]) and whose
    data starts at DATA + 0x100. code(got, data) returns the code bytes, given the GOT slot and data
    addresses as functions of the instruction end."""
    image = bytearray(0x6000)
    image[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, 3, 62, 1, CODE, 64, 0, 0, 64, 56, slots, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, PT_LOAD, 5, CODE, CODE, CODE, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 120, PT_LOAD, 6, DATA, DATA, DATA, 0x1000, 0x1000, 0x1000)
    body = code(lambda index, end: DATA + 8 * index - end, lambda offset, end: DATA + 0x100 + offset - end)
    image[CODE:CODE + len(body)] = body
    image[DATA + 0x100:DATA + 0x100 + len(data)] = data
    strings = b"\0libc.prx\0"
    offsets = []
    for name in imports:
        offsets.append(len(strings))
        strings += (nid(name) + "#A#B").encode() + b"\0"
    image[0x5A00:0x5A00 + len(strings)] = strings
    for index, offset in enumerate(offsets):
        struct.pack_into("<IBBHQQ", image, 0x5B00 + 24 * (index + 1), offset, 0x12, 0, 0, 0, 0)
        struct.pack_into("<QQq", image, 0x5C00 + 24 * index, DATA + 8 * index, ((index + 1) << 32) | 6, 0)
    tags = [(1, 1), (5, 0x5A00), (10, len(strings)), (6, 0x5B00), (11, 24), (0x6100003f, 24 * (len(imports) + 1)),
            (7, 0x5C00), (8, 24 * len(imports)), (9, 24), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x5800 + index * 16, *tag)
    struct.pack_into("<IIQQQQQQ", image, 176, PT_DYNAMIC, 6, 0x5800, 0x5800, 0x5800, len(tags) * 16, len(tags) * 16, 8)
    for index in range(3, slots):
        struct.pack_into("<IIQQQQQQ", image, 64 + index * 56, PT_SCE_VERSION, 0, 0, 0, 0, 0, 0, 1)
    return image


def hello(message=b"hello from x86-64 guest code on arm64\0", status=42):
    """puts(message); exit(status)"""
    def code(got, data):
        out = bytearray(b"\x48\x83\xec\x08")                                  # sub rsp, 8
        out += b"\x48\x8d\x3d" + struct.pack("<i", data(0, CODE + len(out) + 7))  # lea rdi, [rip+message]
        out += b"\xff\x15" + struct.pack("<i", got(0, CODE + len(out) + 6))       # call [rip+puts]
        out += b"\xbf" + struct.pack("<I", status)                            # mov edi, status
        out += b"\xff\x15" + struct.pack("<i", got(1, CODE + len(out) + 6))       # call [rip+exit]
        out += b"\x0f\x0b"                                                    # ud2
        return out
    return program(code, ["puts", "exit"], message)


def floating():
    """exit(2 * atof("20.5")): a double comes back in xmm0."""
    def code(got, data):
        out = bytearray(b"\x48\x83\xec\x08")                                  # sub rsp, 8
        out += b"\x48\x8d\x3d" + struct.pack("<i", data(0, CODE + len(out) + 7))  # lea rdi, [rip+text]
        out += b"\xff\x15" + struct.pack("<i", got(0, CODE + len(out) + 6))       # call [rip+atof]
        out += b"\xf2\x0f\x58\xc0"                                            # addsd xmm0, xmm0
        out += b"\xf2\x0f\x2c\xf8"                                            # cvttsd2si edi, xmm0
        out += b"\xff\x15" + struct.pack("<i", got(1, CODE + len(out) + 6))       # call [rip+exit]
        out += b"\x0f\x0b"                                                    # ud2
        return out
    return program(code, ["atof", "exit"], b"20.5\0")


def sorting():
    """qsort({5, 3, 9, 1, 7}) with a guest comparator, then exit(10 * a[0] + a[4]): the library calls
    back into guest code."""
    def code(got, data):
        out = bytearray(b"\x48\x83\xec\x08")                                  # sub rsp, 8
        out += b"\x48\x8d\x3d" + struct.pack("<i", data(0, CODE + len(out) + 7))  # lea rdi, [rip+array]
        out += b"\xbe\x05\x00\x00\x00"                                        # mov esi, 5
        out += b"\xba\x04\x00\x00\x00"                                        # mov edx, 4
        compare_at = len(out)
        out += b"\x48\x8d\x0d" + bytes(4)                                      # lea rcx, [rip+compare]
        out += b"\xff\x15" + struct.pack("<i", got(0, CODE + len(out) + 6))       # call [rip+qsort]
        out += b"\x8b\x3d" + struct.pack("<i", data(0, CODE + len(out) + 6))      # mov edi, [rip+array]
        out += b"\x6b\xff\x0a"                                                # imul edi, edi, 10
        out += b"\x03\x3d" + struct.pack("<i", data(16, CODE + len(out) + 6))     # add edi, [rip+array+16]
        out += b"\xff\x15" + struct.pack("<i", got(1, CODE + len(out) + 6))       # call [rip+exit]
        out += b"\x0f\x0b"                                                    # ud2
        struct.pack_into("<i", out, compare_at + 3, len(out) - (compare_at + 7))
        out += b"\x8b\x07\x2b\x06\xc3"                                        # compare: mov eax, [rdi]; sub eax, [rsi]; ret
        return out
    return program(code, ["qsort", "exit"], struct.pack("<5i", 5, 3, 9, 1, 7))


def variadic():
    """snprintf with integer, string, double and stack arguments, then puts, then printf."""
    data = bytearray(0xc0)
    data[0x00:0x15] = b"%d %s %.2f %d %d %d\0"
    data[0x40:0x42] = b"x\0"
    data[0x48:0x50] = struct.pack("<d", 2.5)
    data[0x50:0x57] = b"%s %d\n\0"
    data[0x60:0x68] = b"printed\0"

    def code(got, at):
        out = bytearray(b"\x48\x83\xec\x08")                                  # sub rsp, 8
        out += b"\x6a\x06\x6a\x05"                                            # push 6; push 5
        out += b"\x48\x8d\x3d" + struct.pack("<i", at(0x80, CODE + len(out) + 7))  # lea rdi, [rip+buffer]
        out += b"\xbe\x40\x00\x00\x00"                                        # mov esi, 64
        out += b"\x48\x8d\x15" + struct.pack("<i", at(0x00, CODE + len(out) + 7))  # lea rdx, [rip+format]
        out += b"\xb9\x2a\x00\x00\x00"                                        # mov ecx, 42
        out += b"\x4c\x8d\x05" + struct.pack("<i", at(0x40, CODE + len(out) + 7))  # lea r8, [rip+x]
        out += b"\x41\xb9\x04\x00\x00\x00"                                    # mov r9d, 4
        out += b"\xf2\x0f\x10\x05" + struct.pack("<i", at(0x48, CODE + len(out) + 8))  # movsd xmm0, [rip+2.5]
        out += b"\xb8\x01\x00\x00\x00"                                        # mov eax, 1
        out += b"\xff\x15" + struct.pack("<i", got(0, CODE + len(out) + 6))       # call [rip+snprintf]
        out += b"\x48\x83\xc4\x10"                                            # add rsp, 16
        out += b"\x48\x8d\x3d" + struct.pack("<i", at(0x80, CODE + len(out) + 7))  # lea rdi, [rip+buffer]
        out += b"\xff\x15" + struct.pack("<i", got(1, CODE + len(out) + 6))       # call [rip+puts]
        out += b"\x48\x8d\x3d" + struct.pack("<i", at(0x50, CODE + len(out) + 7))  # lea rdi, [rip+format2]
        out += b"\x48\x8d\x35" + struct.pack("<i", at(0x60, CODE + len(out) + 7))  # lea rsi, [rip+printed]
        out += b"\xba\x07\x00\x00\x00"                                        # mov edx, 7
        out += b"\x31\xc0"                                                    # xor eax, eax
        out += b"\xff\x15" + struct.pack("<i", got(2, CODE + len(out) + 6))       # call [rip+printf]
        out += b"\x31\xff"                                                    # xor edi, edi
        out += b"\xff\x15" + struct.pack("<i", got(3, CODE + len(out) + 6))       # call [rip+exit]
        out += b"\x0f\x0b"                                                    # ud2
        return out
    return program(code, ["snprintf", "puts", "printf", "exit"], bytes(data))


def opening():
    """_open("created.txt", O_WRONLY | O_CREAT | O_TRUNC, 0640), then exit(fd < 0): the mode is an
    integer variadic argument."""
    def code(got, at):
        out = bytearray(b"\x48\x83\xec\x08")                                  # sub rsp, 8
        out += b"\x48\x8d\x3d" + struct.pack("<i", at(0, CODE + len(out) + 7))   # lea rdi, [rip+path]
        out += b"\xbe\x01\x06\x00\x00"                                        # mov esi, 0x601
        out += b"\xba\xa0\x01\x00\x00"                                        # mov edx, 0640
        out += b"\x31\xc0"                                                    # xor eax, eax
        out += b"\xff\x15" + struct.pack("<i", got(0, CODE + len(out) + 6))       # call [rip+_open]
        out += b"\x89\xc7\xc1\xef\x1f"                                        # mov edi, eax; shr edi, 31
        out += b"\xff\x15" + struct.pack("<i", got(1, CODE + len(out) + 6))       # call [rip+exit]
        out += b"\x0f\x0b"                                                    # ud2
        return out
    return program(code, ["_open", "exit"], b"created.txt\0")


def threading():
    """pthread_create with a guest entry that checks its thread pointer and returns its argument plus
    22, then pthread_join and exit with what the thread returned."""
    def code(got, at):
        out = bytearray(b"\x48\x83\xec\x08")                                  # sub rsp, 8
        out += b"\x48\x8d\x3d" + struct.pack("<i", at(0, CODE + len(out) + 7))   # lea rdi, [rip+thread]
        out += b"\x31\xf6"                                                    # xor esi, esi
        entry_at = len(out)
        out += b"\x48\x8d\x15" + bytes(4)                                      # lea rdx, [rip+entry]
        out += b"\xb9\x14\x00\x00\x00"                                        # mov ecx, 20
        out += b"\xff\x15" + struct.pack("<i", got(0, CODE + len(out) + 6))       # call [rip+pthread_create]
        out += b"\x85\xc0"                                                    # test eax, eax
        failures = [len(out)]
        out += b"\x75\x00"                                                    # jnz fail
        out += b"\x48\x8b\x3d" + struct.pack("<i", at(0, CODE + len(out) + 7))   # mov rdi, [rip+thread]
        out += b"\x48\x8d\x35" + struct.pack("<i", at(8, CODE + len(out) + 7))   # lea rsi, [rip+result]
        out += b"\xff\x15" + struct.pack("<i", got(1, CODE + len(out) + 6))       # call [rip+pthread_join]
        out += b"\x85\xc0"                                                    # test eax, eax
        failures.append(len(out))
        out += b"\x75\x00"                                                    # jnz fail
        out += b"\x8b\x3d" + struct.pack("<i", at(8, CODE + len(out) + 6))        # mov edi, [rip+result]
        out += b"\xff\x15" + struct.pack("<i", got(2, CODE + len(out) + 6))       # call [rip+exit]
        for jump in failures:
            out[jump + 1] = len(out) - (jump + 2)
        out += b"\xbf\x01\x00\x00\x00"                                        # fail: mov edi, 1
        out += b"\xff\x15" + struct.pack("<i", got(2, CODE + len(out) + 6))       # call [rip+exit]
        out += b"\x0f\x0b"                                                    # ud2
        struct.pack_into("<i", out, entry_at + 3, len(out) - (entry_at + 7))
        out += b"\x64\x48\x8b\x04\x25\x00\x00\x00\x00"                      # entry: mov rax, fs:[0]
        out += b"\x48\x85\xc0"                                                # test rax, rax
        bad = [len(out)]
        out += b"\x74\x00"                                                    # jz bad
        out += b"\x48\x3b\x00"                                                # cmp rax, [rax]
        bad.append(len(out))
        out += b"\x75\x00"                                                    # jne bad
        out += b"\x48\x8d\x47\x16\xc3"                                        # lea rax, [rdi+22]; ret
        for jump in bad:
            out[jump + 1] = len(out) - (jump + 2)
        out += b"\x31\xc0\xc3"                                                # bad: xor eax, eax; ret
        return out
    return program(code, ["pthread_create", "pthread_join", "exit"], bytes(16))


def extended():
    """strtold("1.0000000000000000001"), stored from st(0), then exit(42) if it holds the x87 value
    1 + 2^-63: the long double result reaches the guest's x87 stack."""
    data = bytearray(0x30)
    data[0:22] = b"1.0000000000000000001\0"

    def code(got, at):
        out = bytearray(b"\x48\x83\xec\x08")                                  # sub rsp, 8
        out += b"\x48\x8d\x3d" + struct.pack("<i", at(0, CODE + len(out) + 7))   # lea rdi, [rip+text]
        out += b"\x31\xf6"                                                    # xor esi, esi
        out += b"\xff\x15" + struct.pack("<i", got(0, CODE + len(out) + 6))       # call [rip+strtold]
        out += b"\xdb\x3d" + struct.pack("<i", at(0x20, CODE + len(out) + 6))     # fstp tword [rip+value]
        out += b"\x48\x8b\x05" + struct.pack("<i", at(0x20, CODE + len(out) + 7))  # mov rax, [rip+value]
        out += b"\x48\xb9" + struct.pack("<Q", 0x8000000000000001)             # mov rcx, 0x8000000000000001
        out += b"\x48\x39\xc8"                                                # cmp rax, rcx
        failures = [len(out)]
        out += b"\x75\x00"                                                    # jne fail
        out += b"\x0f\xb7\x05" + struct.pack("<i", at(0x28, CODE + len(out) + 7))  # movzx eax, word [rip+value+8]
        out += b"\x3d\xff\x3f\x00\x00"                                        # cmp eax, 0x3fff
        failures.append(len(out))
        out += b"\x75\x00"                                                    # jne fail
        out += b"\xbf\x2a\x00\x00\x00"                                        # mov edi, 42
        out += b"\xff\x15" + struct.pack("<i", got(1, CODE + len(out) + 6))       # call [rip+exit]
        for jump in failures:
            out[jump + 1] = len(out) - (jump + 2)
        out += b"\xbf\x01\x00\x00\x00"                                        # fail: mov edi, 1
        out += b"\xff\x15" + struct.pack("<i", got(1, CODE + len(out) + 6))       # call [rip+exit]
        out += b"\x0f\x0b"                                                    # ud2
        return out
    return program(code, ["strtold", "exit"], bytes(data))


FIXTURES = {"hello": hello, "floating": floating, "sorting": sorting, "variadic": variadic, "opening": opening,
            "threading": threading, "extended": extended}

if __name__ == "__main__":
    open(sys.argv[2], "wb").write(FIXTURES[sys.argv[1]]())
