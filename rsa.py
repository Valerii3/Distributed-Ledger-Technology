from utils import generate_prime, extended_gcd, mod_inverse
import random

def generate_rsa_keys(bits=512):
    """
    Generates (e, d, n).
    NOTE: In real usage, consider 2048 bits or more, not 512.
    """
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1)*(q - 1)
    e = 65537

    # If gcd(e, phi) != 1, choose another e
    g, _, _ = extended_gcd(e, phi)
    if g != 1:
        e = 3
        from math import gcd
        while gcd(e, phi) != 1:
            e += 2

    d = mod_inverse(e, phi)
    return e, d, n


def rsa_encrypt(m, e, n):
    """
    Encrypt integer message 'm' with public key (e, n).
    Returns the ciphertext as an integer: c = m^e mod n.
    """
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    """
    Decrypt integer ciphertext 'c' with private key (d, n).
    Returns the original message as an integer: m = c^d mod n.
    """
    return pow(c, d, n)


def rsa_sign(message_int, d, n):
    """
    Sign an integer 'message_int' with the private key (d, n).
    Signature s = (message_int^d) mod n
    """
    return pow(message_int, d, n)

def rsa_verify(signature_int, message_int, e, n):
    """
    Verify an RSA signature: check if (signature_int^e) mod n == message_int
    """
    return pow(signature_int, e, n) == message_int