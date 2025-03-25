from utils import generate_prime, extended_gcd, mod_inverse
import random
from math import gcd


def generate_rsa_keys(bits: int = 512) -> tuple[int, int, int]:
    """
    Generates an RSA key pair (e, d, n).

    Args:
        bits: Bit length of each prime number (p and q)

    Returns:
        Tuple containing:
            e - Public exponent
            d - Private exponent
            n - Modulus (p * q)
    """
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537

    # Ensure e and phi are coprime
    g, _, _ = extended_gcd(e, phi)
    if g != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = mod_inverse(e, phi)
    return e, d, n


def rsa_encrypt(m: int, e: int, n: int) -> int:
    """
    Encrypts a message using the RSA public key.

    Args:
        m: Plaintext message as an integer
        e: Public exponent
        n: Modulus

    Returns:
        The ciphertext as an integer
    """
    return pow(m, e, n)


def rsa_decrypt(c: int, d: int, n: int) -> int:
    """
    Decrypts a ciphertext using the RSA private key.

    Args:
        c: Ciphertext as an integer
        d: Private exponent
        n: Modulus

    Returns:
        The decrypted message as an integer
    """
    return pow(c, d, n)


def rsa_sign(message_int: int, d: int, n: int) -> int:
    """
    Signs a message using the RSA private key.

    Args:
        message_int: Message represented as an integer
        d: Private exponent
        n: Modulus

    Returns:
        The RSA signature as an integer
    """
    return pow(message_int, d, n)


def rsa_verify(signature_int: int, message_int: int, e: int, n: int) -> bool:
    """
    Verifies an RSA signature using the public key.

    Args:
        signature_int: The RSA signature as an integer
        message_int: The original message as an integer
        e: Public exponent
        n: Modulus

    Returns:
        True if the signature is valid, False otherwise
    """
    return pow(signature_int, e, n) == message_int
