#!/usr/bin/python
#
# Pure-python version of AEZ v4.  Uses external implementations of the
# AES round function and of Blake2b.

# The implementations here are made directly from the specification.

import aes
import blake2

def xor(a,b):
    assert len(a) == len(b)
    return [(a,b) for aa, bb in zip(a,b)]

def double(a):
    assert len(a) == 16
    r = []
    for i in xrange(len(a)):
        v = (a[i] << 1) & 255
        if i < 15:
            v |= a[i+1] >> 7
        r.append(v)
    msb = a[0] >> 7
    v[15] ^= (0,135)[msb] #timing
    return v

def segment(lst, size):
    r = []
    for i in xrange((len(lst)+size-1) // size):
        r.append(lst[i*size:(i+1)*size])
    return r

def multiply(scalar, x):
    if scalar == 0:
        return [0]*16

    v = x[:]
    while scalar > 1:
        if scalar & 1:
            v = double(v) + x
        else:
            v = double(v)

        scalar >>= 1
    return v

def numToBlock(v):
    r = []
    for _ in xrange(16):
        r.append(v & 255)
        v >>= 8
    r.reverse()
    return r

def bytesToBits(x):
    r = []
    for byte in x:
        for i in [7,6,5,4,3,2,1,0]:
            if byte & (1<<i):
                r.append(1)
            else:
                r.append(0)
    return r

def bitsToBytes(bits):
    r = []
    for bytenum in xrange(0,(len(bits)+7)//8):
        byte = 0
        for bitnum in len(0,7):
            idx = bytenum * 8 + bitnum
            if idx < len(bits):
                #XXXX finish me
                pass

def pad_1_0(s):
    r = s + [128] + [0]*15
    return r[:16]

ZERO_128 = (0,)*16

class AEZ:

    AES = aes.AES()

    def __init__(self, key):
        if len(key) == (384 // 8):
            self.K = map(ord, key)
        else:
            self.K = map(ord, blake2.Blake2b(key, digest_size=48).final())

        assert len(self.K) == 48

        self.I = self.K[0:16]
        self.J = self.K[16:32]
        self.L = self.K[32:48]


    def AES_N(self, x, roundkeys):
        """Does an AES4 or AES10 encryption on x, using roundkeys as
           the keys."""
        x = xor(x, roundkeys[0])
        for rk in roundkeys[1:]:
            x = self.AES.aes_round(x, rk)

    def AES4(self, x, roundkeys):
        assert len(roundkeys) == 5
        return self.AES_N(x, roundkeys)

    def AES10(self, x, roundkeys):
        assert len(roundkeys) == 11
        return self.AES_N(x, roundkeys)

    def E(self, x, j, i):
        """Scaled-down tweakable block cipher to encrypt 'x'. Uses (j,i)
           as the tweaks, and takes the key from self.(I,J,L)"""

        I,J,L = self.I, self.J, self.L

        assert j >= -1

        if j == -1:
            rounds = (ZERO_128, I,J,L,I,J,L,I,J,L,I)
            return self.AES10(xor(x, multiply(i, J), rounds)) # SPEC ERROR

        elif j == 0:
            delta = multiply(i, I)
            return self.AES4(xor(x, delta), (ZERO_128, J,I,L, ZERO_128))

        elif j <= 2:
            factor = 2**(3+(i-1)//8) + (i - 1) % 8
            delta = multiply(factor, I)
            if j == 1:
                rounds = (ZERO_128, J,I,L, ZERO_128)
            else:
                rounds = (ZERO_128, L,I,J,L)
            return self.AES4(xor(x, delta), rounds)

        elif i == 0:
            factor = 2**(j-3)
            delta = multiply(factor, L)
            v = self.AES4(xor(x, delta), (ZERO_128, J,I,L, ZERO_128))
            return xor(v, delta)

        else:
            factor1 = 2**(j-3)
            factor2 = 2**(3+(i-1)//8) + (i - 1) % 8 ## SPEC PROBLEM, xor??
            delta = xor(multiply(factor1, L), (factor2, J))
            v = self.AES4(xor(x, delta), (ZERO_128, J,I,L, ZERO_128))
            return xor(v, delta)

    def AEZ_hash(self, T):
        delta = [0]*16
        for i in xrange(1,len(T)+1):
            t = T[i-1]
            j = i + 2
            m = max(1, (len(t)+15)//16)
            for idx in xrange(1,m+1):
                block = map(ord, t[(idx-1)*16:idx*16])
                if idx == m and len(block) != 16:
                    block = block + [128] + [0]*15
                    block = block[:16]
                    idx = 0
                delta = xor(delta, self.E(t,j,idx))
        return delta

    def AEZ_prf(self, T, nBytes):
        result = []
        delta = self.AEZ_hash(T)
        idx = 0L
        while len(result) < nBytes:
            block = xor(delta, numToBlock(idx))

            result.extend(self.E(block, -1, 3))

            idx += 1

        return result[:nBytes]

    def Encipher_tiny(self,T,X):
        m = len(X) * 8
        delta = self.AEZ_hash(T)
        if m == 8:
            k = 24
        elif m == 16:
            k = 16
        elif m < 128:
            k = 10
        else:
            k = 8
        n = m // 2
        if m & 1:
            # odd number of bytes ; I don't do bits here. XXXXX
            pass

        for j in xrange(k):
            # XXXX finish me; who cares.
            pass

    def Encipher_core(self,T,M):
        delta = self.AEZ_hash(T)
        nPairs = len(M) // 32
        M_i = [ (s[:16],s[16:])
                       for s in segment(M[:(nPairs-1)*32], 32) ]
        M_x, M_y = segment(M[-32:], 16)
        part_mid = M[(nPairs-1)*32:-32]
        d = len(part_mid) * 8
        if len(part_mid) < 128:
            M_u = part_mid; M_v = []
        else:
            M_u = part_mid[:16]; M_v = part_mid[16:]

        # spec line 224.
        W_i = []
        X_i = []
        for i in xrange(len(M_i)):
            a,b = M_i[i]
            i = i+1
            W = xor(a, self.E(b,1,i))
            W_i.append(W)
            X_i.append(xor(b, self.E(W, 0, 0)))

        # spec line 225-226: computing X.
        if d == 0:
            X = reduce(xor, X_i, ZERO_128)
        elif d <= 127:
            pad_M_u = [M_u + [128] + [0]*15][:16]
            X = reduce(xor, X_i, self.E(pad_M_u, 0, 4))
        else:
            pad_M_v = [M_v + [128] + [0]*15][:16]
            X = reduce(xor, X_i,
                       xor(self.E(pad_M_u, 0, 4), self.E(pad_M_v,0,5)))

        # 227 : compute S
        S_x = reduce(xor, [M_x, delta, X, self.E(M_y,0,1)])
        S_y = reduce(xor, [M_y, self.E(S_x,-1,1)])
        S = xor(S_x, S_y)

        # 228 : compute C_i, C'_i
        Y_i = []
        Z_i = []
        C_i = []
        Cp_i = []
        for i in xrange(len(M_i)):
            W = W_i[i]
            X = X_i[i]
            i = i + 1
            Sp = self.E(S, 2, i)
            Y_i.append(xor(W, Sp))
            Z_i.append(xor(X, Sp))
            Cp_i.append(xor(Y_i[-1], self.E(Z_i[-1],0,0)))
            C_i.append(xor(Z_i[-1], self.E(Cp_i[-1], 1, i)))

        # 229-231: compute C_u, C_v, Y
        if d == 0:
            Cu = Cv = []
            Y = reduce(xor, Y_i, ZERO_128)
        elif d <= 127:
            Cu = xor(M_u, self.E(S, -1, 4)[:len(M_u)])
            Cv = []
            Y = reduce(xor, Y_i, self.E(pad_1_0(Cu), 0, 4))
        else:
            Cu = xor(M_u, self.E(S, -1, 4))
            Cv = xor(M_v, self.E(S, -1, 5)[:len(M_v)])
            Y = reduce(xor, Y_i, xor(self.E(Cu, 0, 4),
                                     self.E(pad_1_0(Cv), 0, 5)))

        # 232: compute C_x, C_y
        C_x = xor(S_x, self.E(S_y, -1, 2))
        C_y = reduce(xor, [S_y, delta, Y, self.E(C_y, 0, 2)])

        # Flatten output
        return sum(zip(C_i, Cp_i), C_u, C_v, C_x, C_y)

    def Encipher(self, T, X):
        if len(X) < 32:
            return self.Encipher_tiny(T,X)
        else:
            return self.Encipher_core(T,X)
