#!/usr/bin/env python3

import re
import asyncio

from Crypto.Hash import SHA256

from channel import Channel
from utils import min_byte_length
from dh import DHKeyExchange
from aes import encrypt_message, decrypt_message

async def alice(incoming: Channel, outgoing: Channel) -> None:
    # send p, g
    s_rgx = re.compile(r"\s+")
    p = int(
        s_rgx.sub(
            "",
            """
B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
DF1FB2BC 2E4A4371
""",
        ),
        16,
    )
    g = int(
        s_rgx.sub(
            "",
            """
A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
855E6EEB 22B3B2E5
""",
        ),
        16,
    )
    await outgoing.send(p.to_bytes(min_byte_length(p)), "p")
    await outgoing.send(g.to_bytes(min_byte_length(g)), "g")

    alice = DHKeyExchange(p, g)
    a = alice.public_key()
    await outgoing.send(a.to_bytes(min_byte_length(a)), "A")

    b = int.from_bytes(await incoming.recv("B"))
    s = alice.shared_key(b)
    k = SHA256.new(s.to_bytes(min_byte_length(s))).digest()
    m_0 = "Hi Bob!"
    c_0 = encrypt_message(m_0, k)
    await outgoing.send(c_0, "c_0")

    c_1 = await incoming.recv("c_1")
    m_1 = decrypt_message(c_1, k)
    print(f"Alice decrypted message: {m_1}")


async def bob(incoming: Channel, outgoing: Channel) -> None:
    p = int.from_bytes(await incoming.recv("p"))
    g = int.from_bytes(await incoming.recv("g"))

    bob = DHKeyExchange(p, g)
    b = bob.public_key()
    await outgoing.send(b.to_bytes(min_byte_length(b)), "B")

    a = int.from_bytes(await incoming.recv("A"))
    s = bob.shared_key(a)
    k = SHA256.new(s.to_bytes(min_byte_length(s))).digest()
    m_1 = "Hi Alice!"
    c_1 = encrypt_message(m_1, k)
    await outgoing.send(c_1, "c_1")

    c_0 = await incoming.recv("c_0")
    m_0 = decrypt_message(c_0, k)
    print(f"Bob decrypted message: {m_0}")


async def mallory(
    alice_incoming: Channel,
    alice_outgoing: Channel,
    bob_incoming: Channel,
    bob_outgoing: Channel,
) -> None:
    p = await alice_incoming.recv("p")
    await bob_outgoing.send(p, "p")
    await bob_outgoing.send(await alice_incoming.recv("g"), "g")

    # Malicious mallorying
    _ = await alice_incoming.recv("A")
    await bob_outgoing.send(p, "A")
    _ = await bob_incoming.recv("B")
    await alice_outgoing.send(p, "B")

    k = SHA256.new((0).to_bytes()).digest()
    c_0 = await alice_incoming.recv("c_0")
    m_0 = decrypt_message(c_0, k)
    print(f"Mallory decrypted message: {m_0}")
    m_0 += " I stole your fish!"
    c_0 = encrypt_message(m_0, k)
    await bob_outgoing.send(c_0, "c_0")

    c_1 = await bob_incoming.recv("c_1")
    m_1 = decrypt_message(c_1, k)
    print(f"Mallory decrypted message: {m_1}")
    m_1 += " I stole your fish!"
    c_1 = encrypt_message(m_1, k)
    await alice_outgoing.send(c_1, "c_1")


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
