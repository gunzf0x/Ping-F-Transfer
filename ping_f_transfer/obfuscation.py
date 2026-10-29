import random


def xor_key(n=8):
    return [random.randint(1, 255) for _ in range(n)]


def xor_encode(plaintext, key):
    return ''.join(f'{b ^ key[i % len(key)]:02x}' for i, b in enumerate(plaintext.encode()))
