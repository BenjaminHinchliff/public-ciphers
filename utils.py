#!/usr/bin/env python3

import math

def hex_bytes(bytes_: bytes) -> str:
    return "".join(f"{b:02x}" for b in bytes_)

# why did I have to make this wtf
def min_byte_length(number: int) -> int:
    return max(math.ceil(math.log(max(abs(number), 1), 256)), 1)
