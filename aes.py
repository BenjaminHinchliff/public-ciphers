#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt_message(message: str, key: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC)
    m_0 = pad(message.encode(), AES.block_size)
    c_0 = aes.encrypt(m_0)
    return bytes(aes.iv) + c_0


def decrypt_message(encrypted: bytes, key: bytes) -> str:
    aes = AES.new(key, AES.MODE_CBC)
    m_0 = aes.decrypt(encrypted)[AES.block_size :]
    return unpad(m_0, AES.block_size).decode()
