import math
import random
from sympy import randprime, mod_inverse


def egcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def randomZnElement(N):
    """Get a random element in Z_n."""
    g = N
    while math.gcd(g, N) != 1:
        g = random.randint(2, N)
    return g


def GenModulus(w):
    """Generate primes and modulus used in RSA."""
    n = len(w) // 2
    p = randprime(2 ** n, 2 ** (n+1))
    q = randprime(2 ** n, 2 ** (n+1))
    while p == q:
        q = randprime(2 ** n, 2 ** (n+1))
    N = p * q
    return N, p, q


def GenRSA(w):
    """Generate values necessary for RSA encryption."""
    N, p, q = GenModulus(w)
    m = (p-1) * (q-1)
    e = 2 ** 16 + 1
    d = mod_inverse(e, m)
    return N, e, d, p, q


def enc(x, N, e):
    """Encrypt x using RSA scheme."""
    return fast_pow(x, N, e)


def dec(c, N, d):
    """Decrypt x using RSA scheme."""
    return fast_pow(c, N, d)


def fast_pow(c, N, d):
    """Fast exponentiation algorithm."""
    d_bin = "{0:b}".format(d)
    d_len = len(d_bin)
    reductions = 0
    h = 0
    x = c
    for j in range(1, d_len):
        x, r = mod_reduce(x ** 2, N)
        reductions = reductions + r
        if d_bin[j] == "1":
            x, r = mod_reduce(x * c, N)
            reductions = reductions + r
            h = h + 1
    return x, h, reductions


def mod_reduce(a, b):
    """Reduce a if a >=b and return whether a reduction was performed."""
    reductions = 0
    if a >= b:
        a = a % b
        reductions = 1
    return a, reductions


def dec_blinded(c, N, d, e):
    """Blinded decryption operation in RSA."""
    r = random.randint(2, N-1)
    re, _, _ = enc(r, N, e)
    # Intermediate decryption
    dec_1, _, _ = fast_pow((c * re) % N, N, d)
    r_inv = mod_inverse(r, N)
    return (dec_1 * r_inv) % N


def sign(m, N, d):
    """Sign the message."""
    sigma = pow(m, d, N)
    return sigma


def verify(m, s, N, e):
    """Check if signature is correct."""
    return m == (pow(s, e, N))


def blind_sign_one(m, e, N):
    """Blind the input for the signing."""
    r = randomZnElement(N)
    return m * pow(r, e, N) % N,  r


def blind_sign_two(s, e, N, r):
    """Reveal the signature from the blinded sign."""
    rinv = mod_inverse(r, N)
    return s * rinv % N


N, e, d, p, q = GenRSA("111111111111111111111")

message = random.randint(2, N-1)

y, _, _ = enc(message, N, e)

z = dec_blinded(y, N, d, e)

x, _, _ = dec(y, N, d)

print(f"message: {message} enc: {y} dec: {x} dec_b: {z}")

s1, r = blind_sign_one(message, e, N)
s2 = sign(s1, N, d)
s = blind_sign_two(s2, e, N, r)

v = verify(message, s, N, e)

if v is False or z != message:
    print("Signatures don't match")
else:
    print("Signatures match")
