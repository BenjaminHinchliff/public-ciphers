#!/usr/bin/env python3

from bad_rsa import RSA

if __name__ == "__main__":
    rsa = RSA()
    c = rsa.encrypt(b"Hello world!")
    print(rsa.decrypt(c))
