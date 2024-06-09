#!/usr/bin/env python3

import asyncio

from utils import hex_bytes

class Channel:
    def __init__(self, sender: str, recviver: str) -> None:
        self.sender = sender
        self.recviver = recviver
        self.queue = asyncio.Queue()

    async def send(self, message: bytes, semantic: str = "") -> None:
        await self.queue.put(message)
        print(f"{self.sender} sent {semantic}: {hex_bytes(message)}")

    async def recv(self, semantic: str = "") -> bytes:
        message = bytes(await self.queue.get())
        print(f"{self.recviver} recieved {semantic}: {hex_bytes(message)}")
        return message
