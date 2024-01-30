
from z3 import *

s = Solver()

v9 = [BitVec(f'v9{i}', 64) for i in range(21)]

v10 = [BitVecVal(0, 64) for _ in range(21)]

l = [0x34a, 0xffffffffffffff3a, 0x30a, 0xfffffffffffffefd, 0xffffffffffffffb7, 0xfffffffffffffc59, 0x2e3, 0x2bf, 0x253, 0x38a, 0xfffffffffffffc88, 0xfffffffffffffd63, 0xfffffffffffffd98, 0x3d7, 0x88, 0x235, 0x19d, 0xfffffffffffffce3, 0x322, 0x216, 0xffffffffffffff86, 0x264, 0xffffffffffffff4c, 0xfffffffffffffc79, 0x39, 0x2a0, 0xfffffffffffffe6a, 0x146, 0xfffffffffffffeb8, 0xfffffffffffffeb8, 0xa9, 0xfffffffffffffd8e, 0xffffffffffffff3c, 0x23b, 0x207, 0xffffffffffffff64, 0x289, 0x37a, 0x268, 0x296, 0xffffffffffffff11, 0x79, 0x32c, 0x111, 0xfffffffffffffd02, 0x232, 0x2b6, 0x3ec, 0xffffffffffffffa5, 0x368, 0xfffffffffffffff3, 0x8, 0xfffffffffffffe57, 0x25b, 0xffffffffffffffbf, 0xffffffffffffff72, 0xffffffffffffff02, 0xfffffffffffffd0b, 0x32c, 0xfffffffffffffd78, 0x145, 0x36d, 0x24b, 0xfffffffffffffea1, 0xed, 0xf2, 0xfffffffffffffd14, 0x16c, 0x1fc, 0xfffffffffffffc24, 0xfffffffffffffdb1, 0xfffffffffffffc99, 0xf2, 0xffffffffffffff24, 0x2f3, 0x175, 0xfffffffffffffeb7, 0xfffffffffffffe32, 0x38a, 0x27c, 0x84, 0xffffffffffffffbf, 0x14, 0x28f, 0xfffffffffffffeb4, 0xfffffffffffffeb1, 0xfffffffffffffec9, 0x251, 0xfffffffffffffd2c, 0x21c, 0xfffffffffffffed6, 0x3b7, 0x29f, 0x75, 0x1af, 0x9c, 0x114, 0xffffffffffffffcd, 0x1e2, 0x29b, 0x3db, 0xfffffffffffffd21, 0xfffffffffffffe5c, 0xfffffffffffffe3f, 0xfffffffffffffedc, 0xfffffffffffffd9f, 0xfffffffffffffefb, 0xfffffffffffffc60, 0xffffffffffffff69, 0xffffffffffffffbc, 0xfffffffffffffc55, 0xfffffffffffffdda, 0xfffffffffffffdb0, 0x39c, 0x5d, 0xfffffffffffffdef, 0xffffffffffffff4d, 0xffffffffffffffbc, 0xfffffffffffffebd, 0xfffffffffffffcb0, 0xfffffffffffffd0b, 0x2ff, 0x1f8, 0xffffffffffffffc6, 0xffffffffffffffd0, 0xfffffffffffffe82, 0x263, 0xffffffffffffff3c, 0xfffffffffffffc93, 0x124, 0xfffffffffffffcec, 0x208, 0x362, 0x27f, 0x247, 0x262, 0x37f, 0x1c8, 0xfffffffffffffd8f, 0xfffffffffffffc1f, 0x279, 0xfffffffffffffc54, 0x1f0, 0x3ae, 0x3b0, 0x3e7, 0x1a1, 0x17f, 0xfffffffffffffdad, 0x2c8, 0xffffffffffffff76, 0xfffffffffffffc92, 0x1e8, 0xfffffffffffffd1c, 0xffffffffffffff79, 0xfffffffffffffcaa, 0x91, 0xfffffffffffffe60, 0x118, 0x27e, 0xf9, 0x124, 0x23f, 0xffffffffffffff5a, 0x328, 0xfffffffffffffecb, 0xfffffffffffffde0, 0xfffffffffffffcff, 0x218, 0x17a, 0x8, 0xfffffffffffffe08, 0x2ad, 0xfffffffffffffc7d, 0x30a, 0x30, 0xfffffffffffffe2c, 0xfffffffffffffe62, 0xfffffffffffffe8f, 0x28, 0x2ac, 0xfffffffffffffcb0, 0xffffffffffffff55, 0xba, 0x138, 0xfffffffffffffcc1, 0xffffffffffffffde, 0xfffffffffffffdb1, 0xfffffffffffffc85, 0x0, 0xfffffffffffffec7, 0x116, 0xfffffffffffffe9a, 0x2a2, 0xfffffffffffffe11, 0xfffffffffffffc4e, 0x91, 0xfffffffffffffc0c, 0x93, 0x28b, 0xb2, 0xfffffffffffffc05, 0x1ea, 0x348, 0xfffffffffffffdd3, 0x8d, 0xfffffffffffffe68, 0xfffffffffffffc6b, 0xfffffffffffffe44, 0x339, 0xfffffffffffffc08, 0x2c9, 0xffffffffffffffdc, 0x29c, 0x3f5, 0xfffffffffffffd2c, 0xfffffffffffffc13, 0xfffffffffffffe75, 0x3a7, 0xfffffffffffffc5b, 0x271, 0xfffffffffffffeff, 0xfffffffffffffcac, 0x3eb, 0x89, 0x45, 0xfffffffffffffce6, 0xfffffffffffffd38, 0xffffffffffffffad, 0x391, 0x3fa, 0xfffffffffffffd44, 0xdd, 0x1fb, 0xfffffffffffffe82, 0xffffffffffffffd6, 0xfffffffffffffdf8, 0xfffffffffffffe72, 0x9c, 0x290, 0xfffffffffffffd83, 0xffffffffffffffbd, 0xfffffffffffffc4e, 0x332, 0x217, 0x3ed, 0x3bd, 0xfffffffffffffcdd, 0xfffffffffffffc57, 0x17, 0x306, 0x22, 0x31, 0xffffffffffffffb0, 0xffffffffffffff09, 0xfffffffffffffde1, 0x80, 0xfffffffffffffc26, 0xfffffffffffffec9, 0x2ce, 0x201, 0xfffffffffffffd80, 0xffffffffffffff84, 0x251, 0xfffffffffffffe88, 0xfffffffffffffe54, 0x86, 0xfffffffffffffd45, 0x3a1, 0xfffffffffffffd9d, 0xfffffffffffffc9e, 0xfffffffffffffff3, 0x3e0, 0xfffffffffffffeb1, 0x2a0, 0xfffffffffffffe32, 0xfffffffffffffe92, 0xfffffffffffffd69, 0x188, 0x3a0, 0xffffffffffffffec, 0xfffffffffffffdc4, 0xffffffffffffff13, 0xfffffffffffffd47, 0x356, 0x92, 0x39a, 0x2fc, 0x192, 0x3e1, 0xf3, 0xfffffffffffffca7, 0xfffffffffffffe96, 0x26c, 0xffffffffffffffb6, 0xfffffffffffffd0a, 0x217, 0xd2, 0x174, 0xfffffffffffffc88, 0x279, 0xffffffffffffff7a, 0x291, 0xffffffffffffff35, 0xffffffffffffff0b, 0xfffffffffffffcb4, 0xfffffffffffffdce, 0x207, 0x24d, 0xfffffffffffffc74, 0xffffffffffffff91, 0x357, 0x3da, 0x217, 0x30e, 0xfffffffffffffd82, 0xfffffffffffffd96, 0x5e, 0x21, 0xfffffffffffffd64, 0x66, 0xfffffffffffffc9b, 0x87, 0xffffffffffffff79, 0x10b, 0xfffffffffffffe49, 0x26c, 0xfffffffffffffe68, 0xfffffffffffffcc0, 0xfffffffffffffd50, 0x37d, 0x3a9, 0x276, 0x218, 0xffffffffffffff2b, 0xd6, 0xfffffffffffffe34, 0xfffffffffffffdac, 0xffffffffffffff73, 0x280, 0x223, 0x356, 0xfffffffffffffc28, 0xfffffffffffffcda, 0xfffffffffffffc07, 0x32c, 0xfffffffffffffe92, 0x48, 0x3e8, 0xfffffffffffffe2d, 0x243, 0xffffffffffffffac, 0x10d, 0xaf, 0xfffffffffffffcb2, 0xfffffffffffffc91, 0xfffffffffffffe9c, 0xfffffffffffffd1d, 0x211, 0xfffffffffffffddf, 0xfffffffffffffc0a, 0xfffffffffffffd36, 0xb5, 0x348, 0xfffffffffffffced, 0x39, 0xffffffffffffffaa, 0x158, 0x257, 0xfffffffffffffc1c, 0x2b6, 0xfffffffffffffd8d, 0x25e, 0x300, 0xfffffffffffffe14, 0xfffffffffffffea0, 0x163, 0x14d, 0xfffffffffffffd14, 0xfffffffffffffda2, 0xffffffffffffff50, 0x99, 0xfffffffffffffc62, 0x30a, 0xfffffffffffffd34, 0xaf, 0x3d2, 0x202, 0x29d, 0xfffffffffffffe90, 0xffffffffffffff3e, 0x2d3, 0xfffffffffffffc7f, 0xffffffffffffffb2, 0x172, 0xfffffffffffffef1, 0xfffffffffffffd98, 0x7b, 0xffffffffffffff48, 0xfffffffffffffeab, 0xfffffffffffffcce, 0xfffffffffffffe0a, 0x294, 0xfffffffffffffca8, 0xfffffffffffffd5d, 0x167, 0x357, 0x97, 0x252, 0xfffffffffffffdf7, 0xfffffffffffffd00, 0xfffffffffffffc9e, 0x2c, 0x27d, 0xfffffffffffffee6, 0xfffffffffffffc1a, 0x397, 0xfffffffffffffe8e, 0xfffffffffffffe55, 0x33d, 0xfffffffffffffc9f, 0xfffffffffffffd29, 0xffffffffffffff87, 0x1d0, 0x1b4, 0xfffffffffffffc14, 0x3af, 0xffffffffffffffc2, 0xffffffffffffff11, 0xfffffffffffffce4, 0xfffffffffffffcda, 0xfffffffffffffc5e, 0x32b, 0x12d, 0xffffffffffffff76, 0xfffffffffffffe8d, 0xaf, 0x2ac, 0xffffffffffffffe1, 0xfffffffffffffe42, 0x3cf]

for m in range(21):
    for n in range(21):
        v10[m] += l[m * 20 + n + m] * v9[n]


v11 = [ 0xffffff6f11b8034b, 0x000000673420daf2, 0x0000045eb817f02c, 0xfffffe3099503945, 0x0000018f8dce1227, 0x0000026050ea6875, 0x00000298599c4bf0, 0xfffff8a356ce9e58, 0xfffffed3c712cf36, 0xfffffe96846d630f, 0x0000058cb1ce3ff3, 0xfffffccf182c2a63, 0xfffffe57fdf3f1de, 0xfffffa603f35f962, 0xffffff7884570b57, 0x0000004897c4d9c1, 0xfffffeb9355e5cb4, 0x000000dcedf7d094, 0x000003602e9cac47, 0xfffffee3667219d6, 0xfffffdc326c9b063 ]

for i in range(21):
    s.add(v11[i] == v10[i])

print(s.check())

m = s.model()

hash = []

for i in range(21):
    hash.append(m[v9[i]].as_long())

s.reset()

a = [BitVec(f'a{i}', 8) for i in range(84)]

for i in range(84):
    a[i] = ZeroExt(56, a[i])
    s.add(Or(a[i] == ord('!'), a[i] == ord('_'), a[i] == ord('a'), a[i] == ord('c'), a[i] == ord('d'), a[i] == ord('e'), a[i] == ord('f'), a[i] == ord('g'), a[i] == ord('h'), a[i] == ord('i'), a[i] == ord('l'), a[i] == ord('m'), a[i] == ord('n'), a[i] == ord('o'), a[i] == ord('p'), a[i] == ord('r'), a[i] == ord('s'), a[i] == ord('t'), a[i] == ord('u'), a[i] == ord('w'), a[i] == ord('y')))

for i in range(21):
    v4 = BitVecVal(0xCBF29CE484222325, 64)
    v4 = 0x100000001B3 * (a[i * 4] ^ v4)
    v4 = 0x100000001B3 * (a[i * 4 + 1] ^ v4)
    v4 = 0x100000001B3 * (a[i * 4 + 2] ^ v4)
    v4 = 0x100000001B3 * (a[i * 4 + 3] ^ v4)
    is_signed = (v4 & 0x80000000) != 0
    v9[i] = If(is_signed, v4 | 0xffffffff00000000, v4 & 0xffffffff)

for i in range(21):
    s.add(hash[i] == v9[i])

print(s.check())

m = s.model()

w = ''

for i in range(84):
    w += chr(m.evaluate(a[i]).as_long())

print(w)

# may_the_lanterns_of_the_lunar_new_year_light_up_your_path_to_success_and_happiness!!

# TetCTF{may_the_lanterns_of_the_lunar_new_year_light_up_your_path_to_success_and_happiness!!}
