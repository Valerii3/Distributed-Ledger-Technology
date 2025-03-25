import random


# 1) Fast primality testing
def miller_rabin_test(d: int, n: int) -> bool:
    """
    Performs one round of the Miller-Rabin primality test.

    Args:
        d: Odd part of n - 1, such that n - 1 = d * 2^r
        n: The number to test for primality

    Returns:
        False if 'n' is definitely composite, True if 'n' is probably prime in this round.
    """
    a = random.randint(2, n - 2)
    x = pow(a, d, n)

    if x in (1, n - 1):
        return True

    while d != n - 1:
        x = pow(x, 2, n)
        d *= 2
        if x == 1:
            return False
        if x == n - 1:
            return True

    return False


def is_prime(n: int, k: int = 10) -> bool:
    """
    Determines whether a number is probably prime using the Miller-Rabin test.

    Args:
        n: Number to check
        k: Number of rounds to run the test (more rounds = higher accuracy)

    Returns:
        True if n is probably prime, False if composite
    """
    if n < 2:
        return False

    # Quickly check small known primes
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    # Find d such that n-1 = d * 2^r with d odd
    d = n - 1
    while d % 2 == 0:
        d //= 2

    # Run Miller-Rabin k times
    for _ in range(k):
        if not miller_rabin_test(d, n):
            return False

    return True


def generate_prime(bits: int = 512) -> int:
    """
    Generates a random prime number of specified bit length.

    Args:
        bits: The desired bit length of the prime

    Returns:
        A prime number with approximately 'bits' bits
    """
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1  # Ensure high bit and odd
        if is_prime(candidate):
            return candidate


# Extended Euclidean Algorithm & Inverse
def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Computes the Extended Euclidean Algorithm.

    Args:
        a: First integer
        b: Second integer

    Returns:
        A tuple (gcd, x, y) where a*x + b*y = gcd
    """
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def mod_inverse(e: int, phi: int) -> int:
    """
    Computes the modular inverse of e modulo phi.

    Args:
        e: The number to invert
        phi: The modulus

    Returns:
        The modular inverse of e modulo phi

    Raises:
        Exception if the modular inverse does not exist
    """
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise Exception('Modular inverse does not exist!')
    return x % phi
