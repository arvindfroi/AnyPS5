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


FIXTURES = {"hello": hello, "floating": floating, "sorting": sorting}

if __name__ == "__main__":
    open(sys.argv[2], "wb").write(FIXTURES[sys.argv[1]]())
