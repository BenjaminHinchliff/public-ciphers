#!/usr/bin/env python3

import asyncio
import secrets

from Crypto.Hash import SHA256

from bad_rsa import RSA
from channel import Channel
from utils import min_byte_length
from aes import encrypt_message, decrypt_message


async def alice(incoming: Channel, outgoing: Channel) -> None:
    rsa = RSA()

    await outgoing.send(rsa.n.to_bytes(min_byte_length(rsa.n)), "n")
    await outgoing.send(rsa.e.to_bytes(min_byte_length(rsa.e)), "e")

    c_prime = await incoming.recv("c'")
    s_prime = rsa.decrypt(c_prime)

    k = SHA256.new(s_prime).digest()
    c_0 = encrypt_message("Hi Bob!", k)

    await outgoing.send(c_0)


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
    _: Channel,
    bob_outgoing: Channel,
) -> None:
    n_b = await alice_incoming.recv("n")
    await bob_outgoing.send(n_b, "n")
    e_b = await alice_incoming.recv("e")
    await bob_outgoing.send(e_b, "e")

    await alice_outgoing.send((0).to_bytes(), "c'")

    print(f"Mallory knows s: {0:x}")

    c_0 = await alice_incoming.recv("c_0")
    k = SHA256.new((0).to_bytes()).digest()
    m_0 = decrypt_message(c_0, k)
    print(f"Mallory decrypted m_0: {m_0}")


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
