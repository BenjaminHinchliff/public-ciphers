#!/usr/bin/env python3

import secrets

class DHKeyExchange:
    def __init__(self, p: int, g: int) -> None:
        self.p = p
        self.g = g
        self.x = secrets.randbelow(p)

    def public_key(self) -> int:
        return pow(self.g, self.x, self.p)

    def shared_key(self, public_key: int) -> int:
        return pow(public_key, self.x, self.p)
