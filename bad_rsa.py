#!/usr/bin/env python3

from Crypto.Util import number

from utils import min_byte_length
from modmath import modinv, lcm

class RSA:
    def __init__(self) -> None:
        self.p = number.getPrime(number.getRandomRange(1024, 2048))
        self.q = number.getPrime(number.getRandomRange(1024, 2048))
        self.e = 65537
        self.n = self.p * self.q
        self.d = RSA.__compute_key(self.p, self.q, self.e)

    @staticmethod
    def __compute_key(p: int, q: int, e: int) -> int:
        carmichael_totient = lcm(p - 1, q - 1)
        return modinv(e, carmichael_totient)

    @staticmethod
    def encrypt_public(m_str: bytes, e: int, n: int) -> bytes:
        m = int.from_bytes(m_str)
        c = pow(m, e, n)
        return c.to_bytes(min_byte_length(c))

    def encrypt(self, m: bytes) -> bytes:
        return RSA.encrypt_public(m, self.e, self.n)

    def decrypt(self, c_b: bytes) -> bytes:
        c = int.from_bytes(c_b)
        m = pow(c, self.d, self.n)
        return m.to_bytes(min_byte_length(m))


