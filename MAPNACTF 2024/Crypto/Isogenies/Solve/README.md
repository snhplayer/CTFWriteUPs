
# Mapna CTF 2024 - Isogenies

Writeup by. **EggRoll**

## Challenge Overview 

First of all, the flag is encrypted by AES with its hash as encryption key.

```python
h = sha256(flag).digest()
A = bytes_to_long(h)

iv = token_bytes(16)
key = sha256(h).digest()[:16]
enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(flag, 16))
```

So our goal is to retrieve $A$ and decrypt the ciphertext. This variable is used as a coefficient of an elliptic curve $E$ whose order is a multiple of $3$, and then a $3$-torsion point $P$ is generated.  

```python
p = getPrime(512)
E = EllipticCurve(GF(p), [0, A, 0, 1, 0])
if E.order() % 3 != 0:
	continue

for _ in range(50):
	P = E.random_point() * (E.order() // 3)
	if P != 0:
		break
else:
	continue
```

Next, an isogeny from $E$ to $E_a$ is computed according to 

```python
def to_montgomery(E):
	R = E.base_ring()
	j = E.j_invariant()
	x = polygen(R)
	eq = 256 * (x - 3)**3 - (x - 4) * j
	for A2 in eq.roots(multiplicities=False):
		for A in A2.nth_root(2, all=True):
			Ea = EllipticCurve(R, [0, A, 0, 1, 0])
			if Ea.is_isomorphic(E):
				return Ea
            
Ea = to_montgomery(E.isogeny_codomain(P))
	if Ea is None:
		continue
```

Finally, the higher bits of montgomery coefficients of $E, E_a$ and $p, P[0]$ are provided. 

## Problem Analysis

Because two elliptic curves are isogenies, the j-invariants form a root of modular polynomial. In other words, the following relationship holds. $$\phi_3\left(\frac{256(A^2-3)^3}{(A^2-4)}, \frac{256(B^2-3)^3}{(B^2-4)}\right) = 0$$ The explicit form of such polynomials are listed [here](https://math.mit.edu/~drew/ClassicalModPolys.html). In our case, $$\phi_3(x, y) = x^4-x^3y^3+2232(x^3y^2+x^2y^3)-1069956(x^3y+xy^3)+36864000(x^3+y^3)+2587918086x^2y^2+8900222976000(x^2y+xy^2)+452984832000000(x^2+y^2)-770845966336000000xy+1855425871872000000000(x+y)$$

On the other hand, since $P$ is a $3$-torsion point, the x-coordinate $P[0]$ must be a root of the third [division polynomial](https://en.wikipedia.org/wiki/Division_polynomials), say $$\psi_3(x) = 3x^4+6ax^2+12bx-a^2$$ if we write the equation of the elliptic curve in the form $y^2 = x^3+ax+b$. 

However, the equation of $E$ we have is $y^2=x^3+Ax^2+x$. We need to transform it into the standard form, and this could be done by shifting. Precisely, consider $(x, y) \to (x-\frac{A}{3}, y)$, $$y^2 = \left(x-\frac{A}{3}\right)^3+A\left(x-\frac{A}{3}\right)^2+\left(x-\frac{A}{3}\right)=x^3+\left(1-\frac{A^2}{3}\right)x+\frac{2A^3-9A}{27}$$

Plug $(a, b) = \left(1-\frac{A^2}{3}, \frac{2A^3-9A}{27}\right)$ into $\psi_3$, we get another equation about $A$, and these two are all we have. 

As $A, B$ are masked, let's say $A = A'+x, B = B'+y$ where $A', B'$ are known and $x, y$ are unknowns. Notice that the number of equations and unknowns are exactly the same, we should be able to find them in an **algebraic** way, i.e. [resultant](https://en.wikipedia.org/wiki/Resultant).

## Implementation

The polynomials are constructed as we analyzed.

```python
# 3rd modular poly 
# each entry contains degrees of x, y and the coefficient
phi3 = [
    [1, 0, 1855425871872000000000],
    [1, 1, -770845966336000000],
    [2, 0, 452984832000000],
    [2, 1, 8900222976000],
    [2, 2, 2587918086],
    [3, 0, 36864000],
    [3, 1, -1069956],
    [3, 2, 2232],
    [3, 3, -1],
    [4, 0, 1]
]

PR.<x, y> = PolynomialRing(GF(p), 2)
# The numberators and denominators of j-invariants of E, Ea 
jA_n = 256 * ((A + x)^2 - 3)^3
jA_d = ((A + x)^2 - 4)
jB_n = 256 * ((B + y)^2 - 3)^3
jB_d = ((B + y)^2 - 4)
# Compute the numerator of modular poly
f = 0
x_deg_max, y_deg_max = 4, 4
for _ in phi3:
    x_deg, y_deg, coef = _
    f += coef * jA_n^x_deg * jA_d^(x_deg_max - x_deg) * jB_n^y_deg * jB_d^(y_deg_max - y_deg)
    if x_deg != y_deg:
        f += coef * jA_n^y_deg * jA_d^(y_deg_max - y_deg) * jB_n^x_deg * jB_d^(x_deg_max - x_deg)
# Division poly
g = 3 * (hint + (A + x) / 3)^4 + 6 * (1 - (A + x)^2 / 3) * (hint + (A + x) / 3)^2 + 12 * (2 * (A + x)^3 / 27 - (A + x) / 3) * (hint + (A + x) / 3) - (1 - (A + x)^2 / 3)^2
```

However, we are not able to invoke resultant like 
```
f.resultant(g, y)
```

This will result in Signature Error because the modulus is too big. Instead, we follow the definition explained in wiki: 

```
h = f.sylvester_matrix(g, y).determinant()
h = h.polynomial(x)
```

It remains to compute the roots of $h$ and see whether it's in fact the unknown. Put all the pieces together, the flag is returned immediately!

:::success
MAPNA{S1mpl3_p0lYnOm!4L_r3lA7i0n_0F_l0w_degr3E!}
:::

## Reference

1. Modular Polynomials. https://math.mit.edu/~drew/ClassicalModPolys.html
2. Division Polynomial. https://en.wikipedia.org/wiki/Division_polynomials
3. Resultant. https://en.wikipedia.org/wiki/Resultant