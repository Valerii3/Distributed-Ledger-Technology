import random

# -------------------------
# 1) Fast primality testing
# -------------------------
def miller_rabin_test(d, n):
    """
    One round of the Miller-Rabin test.
    Checks if 'n' is definitely composite or probably prime.
    Returns False if 'n' is composite, True if 'n' is probably prime for this round.
    """
    a = 2 + random.randint(1, n - 4)
    x = pow(a, d, n)  # a^d mod n
    if x == 1 or x == n - 1:
        return True
    # Keep squaring x while d doesn't reach n-1
    while d != n - 1:
        x = (x * x) % n
        d *= 2
        if x == 1:
            return False
        if x == n - 1:
            return True
    return False

def is_prime(n, k=10):
    """
    Miller-Rabin primality test to check primality for 'n' with 'k' rounds.
    Returns True if 'n' is probably prime, False otherwise.
    """
    # Handle simple cases:
    if n < 2:
        return False
    # Check small primes directly:
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0 and n != sp:
            return False

    # Find d such that n-1 = d * 2^r
    d = n - 1
    while d % 2 == 0:
        d //= 2

    # k rounds of testing
    for _ in range(k):
        if not miller_rabin_test(d, n):
            return False
    return True

def generate_prime(bits=512):
    """
    Generate a prime of approximately 'bits' bits using the is_prime() test.
    """
    while True:
        candidate = random.getrandbits(bits)
        # Ensure it's odd and has the correct bit length
        candidate |= (1 << bits-1) | 1
        if is_prime(candidate):
            return candidate

# --------------------------------
# 2) Extended Euclidean (modular inverse)
# --------------------------------
def extended_gcd(a, b):
    """
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return (g, x, y)

def mod_inverse(e, phi):
    """
    Compute the modular inverse of e modulo phi using Extended Euclidean Algorithm.
    i.e. d such that (d*e) % phi = 1.
    """
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise Exception('Modular inverse does not exist!')
    else:
        return x % phi