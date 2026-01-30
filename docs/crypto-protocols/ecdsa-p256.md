# ECDSA P-256

Elliptic Curve Digital Signature Algorithm on the NIST P-256 curve.

## What Problem Does It Solve?

Imagine you receive a message claiming to be from Alice. How do you know Alice actually sent it? You can't just trust the message says "from Alice" - anyone could write that. You need proof.

ECDSA solves this. Alice can attach a digital signature to her message - a piece of data that only she could have created. You can verify this signature using Alice's public key, which proves the message genuinely came from her and wasn't modified in transit.

The beautiful part: verifying a signature doesn't let you create new ones. Only Alice, with her secret private key, can sign messages.

## The Elliptic Curve

P-256 uses the curve defined by:

```
y² = x³ + ax + b   (mod p)

where:
  a = -3
  b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
  p = 2²⁵⁶ - 2²²⁴ + 2¹⁹² + 2⁹⁶ - 1
```

All arithmetic happens modulo the prime p. The curve also defines a base point G (the generator) and n (the order of G, meaning G added to itself n times equals the point at infinity).

## The Key Pair

Alice generates her keys:

```
Private key:  d = random integer in [1, n-1]
Public key:   Q = d × G
```

Here × means elliptic curve point multiplication: adding G to itself d times using the curve's addition rules. Computing Q from d is fast (milliseconds). Recovering d from Q requires solving the discrete logarithm problem - infeasible with current technology.

## Point Addition

Adding two points P₁ and P₂ on the curve:

```
If P₁ ≠ P₂:
  λ = (y₂ - y₁) / (x₂ - x₁)  mod p

If P₁ = P₂ (point doubling):
  λ = (3x₁² + a) / (2y₁)  mod p

Result P₃ = P₁ + P₂:
  x₃ = λ² - x₁ - x₂  mod p
  y₃ = λ(x₁ - x₃) - y₁  mod p
```

Point multiplication d × G is computed efficiently using double-and-add algorithm, not by literally adding d times.

## Signing

To sign message m with private key d:

```
1. Compute hash:     e = SHA-256(m)

2. Pick random:      k ∈ [1, n-1]   (MUST be fresh each time!)

3. Compute point:    (x₁, y₁) = k × G

4. Compute r:        r = x₁ mod n
                     (if r = 0, pick new k)

5. Compute s:        s = k⁻¹ × (e + d × r) mod n
                     (if s = 0, pick new k)

6. Signature:        (r, s)
```

The signature ties together the message hash e, the private key d, and the random k. Without knowing d, you cannot produce valid (r, s) for a given message.

## Verification

To verify signature (r, s) on message m using public key Q:

```
1. Check bounds:     1 ≤ r < n  and  1 ≤ s < n

2. Compute hash:     e = SHA-256(m)

3. Compute:          w = s⁻¹ mod n

4. Compute:          u₁ = e × w mod n
                     u₂ = r × w mod n

5. Compute point:    (x₁, y₁) = u₁ × G + u₂ × Q

6. Valid if:         r ≡ x₁ (mod n)
```

Why does this work? Substituting the signing equations:

```
u₁ × G + u₂ × Q = u₁ × G + u₂ × (d × G)
                = (u₁ + u₂ × d) × G
                = (e × w + r × w × d) × G
                = w × (e + r × d) × G
                = s⁻¹ × (e + r × d) × G
                = s⁻¹ × (k × s) × G     [from signing step 5]
                = k × G
```

Which has x-coordinate equal to r, confirming the signature is valid.

## Why P-256?

P-256 provides 128-bit security - an attacker needs approximately 2¹²⁸ operations to break it. The prime p was chosen for efficient computation on 32-bit and 64-bit processors. It's standardized by NIST, used in TLS/HTTPS, secure boot, and passkeys. Signature size is 64 bytes (two 32-byte integers), much smaller than RSA's 256+ bytes for equivalent security.

## The One Rule You Must Never Break

Every signature requires a fresh random k. If Alice signs two different messages m₁ and m₂ using the same k:

```
s₁ = k⁻¹(e₁ + d × r) mod n
s₂ = k⁻¹(e₂ + d × r) mod n

Subtracting:
s₁ - s₂ = k⁻¹(e₁ - e₂) mod n

Therefore:
k = (e₁ - e₂) / (s₁ - s₂) mod n

And then:
d = (s₁ × k - e₁) / r mod n
```

The private key d is recovered with simple algebra. This is exactly how the PlayStation 3 was hacked - Sony reused k, and attackers extracted their signing key. Always use a cryptographically secure random number generator.
