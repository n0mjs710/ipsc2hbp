#!/usr/bin/env python3
"""Generate golden DSP vectors from dmr_utils3 to validate the C port.

Emits a flat KEY=hex format consumed by the C test harness.
Run with the project venv:  ./venv/bin/python tests/gen_dsp_vectors.py
"""
import sys, os
from bitarray import bitarray
from dmr_utils3 import bptc, ambe_utils, hamming, crc, rs129
from dmr_utils3.ambe_utils import convert49BitTo72BitAMBE, convert72BitTo49BitAMBE
from dmr_utils3.const import EMB, SLOT_TYPE, BS_VOICE_SYNC, BS_DATA_SYNC, LC_OPT


def emit(key, b):
    if isinstance(b, bitarray):
        b = b.tobytes()
    print(f"{key}={bytes(b).hex()}")


def ba_from_bytes(bs):
    ba = bitarray(endian='big')
    ba.frombytes(bs)
    return ba


# Several representative LC words (FLCO+FID+opts + dst(3) + src(3))
LCS = [
    b'\x00\x10\x20\x00\x0c\x30\x2f\x9b\xe5',   # the canonical test vector
    LC_OPT + (91).to_bytes(3, 'big') + (3120000).to_bytes(3, 'big'),
    LC_OPT + (310).to_bytes(3, 'big') + (3112000).to_bytes(3, 'big'),
    b'\x00\x00\x00\x12\x34\x56\x78\x9a\xbc',
]

for i, lc in enumerate(LCS):
    emit(f"lc{i}.in", lc)
    emit(f"lc{i}.rs_header", rs129.lc_header_encode(lc))
    emit(f"lc{i}.rs_term", rs129.lc_terminator_encode(lc))
    emit(f"lc{i}.encode_header_lc", bptc.encode_header_lc(lc))
    emit(f"lc{i}.encode_terminator_lc", bptc.encode_terminator_lc(lc))
    # encode_19696 of (lc + rs_header) before interleave
    emit(f"lc{i}.encode_19696", bptc.encode_19696(lc + rs129.lc_header_encode(lc)))
    emit(f"lc{i}.csum5", crc.csum5(lc))
    elc = bptc.encode_emblc(lc)
    for k in (1, 2, 3, 4):
        emit(f"lc{i}.emblc{k}", elc[k])
    # decode_full_lc round-trips from the encoded header (196-bit interleaved)
    full = bptc.encode_header_lc(lc)
    emit(f"lc{i}.decode_full_lc", bptc.decode_full_lc(full))

# Hamming encoders — exercise with deterministic bit patterns
def bits(n, val):
    ba = bitarray(endian='big')
    for j in range(n):
        ba.append((val >> (n - 1 - j)) & 1)
    return ba

for val in (0x000, 0x7FF, 0x555, 0x2AA, 0x123, 0x400, 0x001):
    emit(f"ham15113.{val:03x}", hamming.enc_15113(bits(11, val)))
    emit(f"ham16114.{val:03x}", hamming.enc_16114(bits(11, val)))
for val in (0x000, 0x1FF, 0x155, 0x0AA, 0x123, 0x100, 0x001):
    emit(f"ham1393.{val:03x}", hamming.enc_1393(bits(9, val)))

# AMBE conversions. Use representative 49-bit and 72-bit inputs.
# 72-bit silence frame and a few others (9 bytes each).
AMBE72 = [
    bytes.fromhex('ACAA40200044408080'),
    bytes.fromhex('0102030405060708090a'[:18]),
    bytes.fromhex('ffffffffffffffffff'),
    bytes.fromhex('123456789abcdef012'),
]
for i, a in enumerate(AMBE72):
    a = a[:9]
    ba = ba_from_bytes(a)
    a49 = convert72BitTo49BitAMBE(ba)      # bitarray length 49
    emit(f"ambe72to49.{i}.in", a)
    emit(f"ambe72to49.{i}.out", a49)       # tobytes pads to 56 bits (7 bytes)
    # round trip back to 72
    a72 = convert49BitTo72BitAMBE(a49)
    emit(f"ambe49to72.{i}.out", bytes(a72))

# const tables
emit("BS_VOICE_SYNC", BS_VOICE_SYNC)
emit("BS_DATA_SYNC", BS_DATA_SYNC)
emit("LC_OPT", LC_OPT)
for name in ('BURST_B', 'BURST_C', 'BURST_D', 'BURST_E', 'BURST_F'):
    emit(f"EMB.{name}", EMB[name])
for name in ('VOICE_LC_HEAD', 'VOICE_LC_TERM'):
    emit(f"SLOT_TYPE.{name}", SLOT_TYPE[name])

print("# done", file=sys.stderr)
