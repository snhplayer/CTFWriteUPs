from pwnlib.util.crc import crc_64_we, generic_crc
import pwnlib.asm
import sys
import struct
import subprocess
from pwn import *

def crc_64_we_neutral(data):
    return generic_crc(data, 0x42f0e1eba9ea3693, 64, 0, False, False, 0)

def shift_left(n):
    carry = (n & 2**63) != 0
    value = (n << 1) & (2**64 - 1)
    return carry, value

def unstepn(value, steps):
    for _ in range(steps):
        if value & 1 != 0:
            value ^= 0x142f0e1eba9ea3693
        value = value >> 1
    return value

def stepn(value, steps):
    for _ in range(steps):
        carry, value = shift_left(value)
        if carry:
            value ^= 0x42f0e1eba9ea3693
    return value

# Finds an 8-byte suffix to message to make
def find_suffix(msg):
    # Just a constant
    C0 = crc_64_we(b'\x5c' * 8 + b'\xff' * 8)

    # Depends on message
    C1 = crc_64_we_neutral(b'\xc9' * 8 + msg + b'\x00' * 8 + b'\x00' * 16)

    return unstepn(C0 ^ C1, 24 * 8).to_bytes(8, byteorder='big')

def precompute_xor_value(msg_len):
    return stepn(2**63, 8*msg_len + 16*8)

def polyglot(out, values):
    out += b'\x04\x01\xe0\x36'

def asm_helper(out, arch, code):
    with context.local(arch = arch):
        path = asm(f'''
                .zero {len(out)}
        ''' + code, extract = False)
        subprocess.check_call([pwnlib.asm.which_binutils('objcopy'), '-j', '.shellcode', '-Obinary', path, '/tmp/mybinary'])
        out += read('/tmp/mybinary')[len(out):]

def riscv64_entry(out, values):
    asm_helper(out, 'riscv64', f'''
        li a4, 31
        mv a0, x1
        ld a2, {values['precomputed']}(a5)
        ld a3, {values['polynom']}(a5)
        j _start + {values['riscv64']}
    ''')

def padding0(out, values):
    while len(out) & 7:
        out += b'\x00'

def precomputed(out, values):
    out += p64(values['precomputed_value'])

def polynom(out, values):
    out += p64(0x42f0e1eba9ea3693)

def padding1(out, values):
    out += b'\x00' * (0x20 - len(out))

def arm64_entry(out, values):
    asm_helper(out, 'arm64', f'''
        ldp x10, x11, [x1, #{values['precomputed']}]
        mov x1, x0
        mov x0, x8
        b _start + {values['arm64']}
    ''')

def padding2(out, values):
    out += b'\x00' * (0x3a - len(out))

def amd64_1(out, values):
    pass

def amd64_2(out, values):
    pass

def amd64_3(out, values):
    asm_helper(out, 'amd64', f'''
        entry:
          sub al, 1 # polyglot increments al

          xchg rax, rdx
          add ecx, 33 # polyglot decrements ecx...

        iteration:
          xor esi, esi
          shl rdx, 1

          cmovc rsi, [rbx+{values['precomputed']}]
          xor rax, rsi

          xor esi, esi
          shl rax, 1

          cmovc rsi, [rbx+{values['polynom']}]
          xor rax, rsi

          xor esi, esi
          shl rdx, 1

          cmovc rsi, [rbx+{values['precomputed']}]
          xor rax, rsi

          xor esi, esi
          shl rax, 1

          cmovc rsi, [rbx+{values['polynom']}]
          xor rax, rsi

          loop iteration
        hlt
    ''')

def padding3(out, values):
    while len(out) & 1:
        out += b'\x00'

def riscv64(out, values):
    asm_helper(out, 'riscv64', f'''
        loop:
          srai a5,a0,0x3f
          and  a5,a5,a2
          xor  a1,a1,a5
          slli a0,a0,0x1

          slli a5,a1,0x1
          srai a1,a1,0x3f
          and  a1,a1,a3

          xor  a1,a1,a5

          srai a5,a0,0x3f
          and  a5,a5,a2
          xor  a1,a1,a5
          slli a0,a0,0x1

          slli a5,a1,0x1
          srai a1,a1,0x3f
          and  a1,a1,a3

          xor  a1,a1,a5

          addiw a4, a4, -1
          bgez a4, loop

          mv x1,a1
          wfi
    ''')

def padding4(out, values):
    while len(out) & 3:
        out += b'\x00'

def arm64(out, values):
    asm_helper(out, 'aarch64', f'''
        loop:
          and x12, x10, x1, asr #63
          lsl x1, x1, #1
          eor x0, x12, x0
          and x12, x11, x0, asr #63
          eor x0, x12, x0, lsl #1

          and x12, x10, x1, asr #63
          lsl x1, x1, #1
          eor x0, x12, x0
          and x12, x11, x0, asr #63
          eor x0, x12, x0, lsl #1

          add w9, w9, 1
          tbz w9, 5, loop

          WFI
    ''')

def suffix(out, values):
    out += find_suffix(out)

def find_generators_fixpoint():
    # default falues, does not have to be correct
    values = {
        'polyglot': 0,
        'riscv64_entry': 4,
        'padding0': 8,
        'precomputed': 0x10,
        'precomputed_value': 0x1234567812345678,
        'polynom': 0x18,
        'padding1': 0x18,
        'arm64_entry': 0x20,
        'padding1': 0x34,
        'amd64_1': 0x3a,
        'amd64_2': 0x3a,
        'amd64_3': 0x3a,
        'riscv64': 0x7c,
        'padding2': 0x8d,
        'arm64': 0x90,
        'suffix': 0xa0,
    }

    generators = [
        polyglot,
        riscv64_entry,
        padding0,
        precomputed,
        polynom,
        padding1,
        arm64_entry,
        padding2,
        amd64_1,
        amd64_2,
        amd64_3,
        padding3,
        riscv64,
        padding4,
        arm64,
        suffix,
    ]
    names = [g.__name__ for g in generators]

    prev_out = bytearray()
    while True:
        out = bytearray()
        next_values = {}

        for generator in generators:
            next_values[generator.__name__] = values[generator.__name__] = len(out)
            generator(out, values)

        next_values['precomputed_value'] = precompute_xor_value(len(out))
        values = next_values

        if out != prev_out:
            prev_out = out
            continue
        break

    offsets = [values[name] for name in names]
    assert sorted(offsets) == offsets

    for (name, offset, next_offset) in zip(names, offsets, offsets[1:] + [len(out)]):
        cur = out[offset:next_offset]
        print(name)
        if cur:
            if name.startswith('amd64'):
                print(disasm(cur, arch = 'amd64'))
            elif name.startswith('arm64'):
                print(disasm(cur, arch = 'aarch64'))
            elif name.startswith('riscv64'):
                print(disasm(cur, arch = 'riscv64'))
            else:
                print(hexdump(cur))
        print()

    print()
    print('Offsets:')
    for (name, offset, next_offset) in zip(names, offsets, offsets[1:] + [len(out)]):
        cur = out[offset:next_offset]
        key = (name + ':').ljust(15)
        print(f'{key} 0x{offset:02x}-0x{next_offset:02x}')

    return out

msg = find_generators_fixpoint()

open('out.bin', 'wb').write(msg)
open('out.bin.hex', 'w').write(msg.hex())