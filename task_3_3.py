#!/usr/bin/env python3

import asyncio
import secrets

from bad_rsa import RSA
from channel import Channel
from modmath import modinv
from utils import min_byte_length


async def alice(incoming: Channel, outgoing: Channel) -> None:
    rsa = RSA()

    await outgoing.send(rsa.n.to_bytes(min_byte_length(rsa.n)), "n")
    await outgoing.send(rsa.e.to_bytes(min_byte_length(rsa.e)), "e")

    c_prime = await incoming.recv("c'")
    s_prime = rsa.decrypt(c_prime)

    # required for ciphertext attack
    await outgoing.send(s_prime, "s'")


async def bob(incoming: Channel, outgoing: Channel) -> None:
    n = int.from_bytes(await incoming.recv("n"))
    e = int.from_bytes(await incoming.recv("e"))

    s = secrets.randbits(1024)
    print(f"Bob made super secret key s: {s:x}")
    c = RSA.encrypt_public(s.to_bytes(min_byte_length(s)), e, n)
    await outgoing.send(c, "c")


async def mallory(
    alice_incoming: Channel,
    alice_outgoing: Channel,
    bob_incoming: Channel,
    bob_outgoing: Channel,
) -> None:
    n_b = await alice_incoming.recv("n")
    n = int.from_bytes(n_b)
    await bob_outgoing.send(n_b, "n")
    e_b = await alice_incoming.recv("e")
    e = int.from_bytes(e_b)
    await bob_outgoing.send(e_b, "e")

    c = int.from_bytes(await bob_incoming.recv("c"))

    x = secrets.randbits(1024)
    c_prime = (c * pow(x, e, n)) % n

    await alice_outgoing.send(c_prime.to_bytes(min_byte_length(c_prime)), "c'")
    
    s_prime = int.from_bytes(await alice_incoming.recv("s'"))
    s = (s_prime * modinv(x, n)) % n
    print(f"Mallory decrypted s: {s:x}")


async def main() -> None:
    alice_mallory = Channel("Alice", "Mallory")
    mallory_bob = Channel("Mallory", "Bob")
    bob_mallory = Channel("Bob", "Mallory")
    mallory_alice = Channel("Mallory", "Alice")

    await asyncio.gather(
        alice(mallory_alice, alice_mallory),
        bob(mallory_bob, bob_mallory),
        mallory(alice_mallory, mallory_alice, bob_mallory, mallory_bob),
    )


if __name__ == "__main__":
    asyncio.run(main())
