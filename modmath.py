#!/usr/bin/env python3

def modinv(a: int, b: int) -> int:
    b0 = b
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a > 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    assert(b == 1)
    return x0 % b0

def gcd(a: int, b: int) -> int:
    last_r, r = a, b
    while r > 0:
        r, last_r = last_r % r, r
    return last_r

def lcm(a: int, b: int) -> int:
    return abs(a * b) // gcd(a, b)
