#!/usr/bin/python
#
# Pure-python version of AEZ v4.  Uses external implementations of the
# AES round function and of Blake2b.

# The implementations here are made directly from the specification.

import aes
import pyblake2

def xor(a,b):
    assert len(a) == len(b)
    return [(aa^bb) for aa, bb in zip(a,b)]

def double(a):
    assert len(a) == 16
    r = []
    for i in xrange(len(a)):
        v = (a[i] << 1) & 255
        if i < 15:
            v |= a[i+1] >> 7
        r.append(v)
    msb = a[0] >> 7
    r[15] ^= (0,135)[msb] #timing
    assert len(r) == 16
    return r

def segment(lst, size):
    r = []
    for i in xrange((len(lst)+size-1) // size):
        r.append(lst[i*size:(i+1)*size])
    return r

def multiply(scalar, x):
    assert len(x) == 16
    r = [0] * 16
    v = x[:]
    while scalar:
        if scalar & 1:
            r = xor(r, v)

        v = double(v)

        scalar >>= 1
    return r

def numToBlock(v):
    r = []
    for _ in xrange(16):
        r.append(v & 255)
        v >>= 8
    r.reverse()
    return r

def pad_1_0(s):
    r = s + [128] + [0]*15
    return r[:16]

def pad_0(s):
    r = s + [0]*16
    return r[:16]

def blockToWords(rk):
    r = []
    for i in xrange(0,16,4):
        n = (rk[i]<<24) | (rk[i+1]<<16) | (rk[i+2]<<8) | (rk[i+3]<<0)
        r.append(n)
    return r

def wordsToBlock(ws):
    r = []
    for w in ws:
        r.append((w>>24) & 0xff)
        r.append((w>>16) & 0xff)
        r.append((w>>8 ) & 0xff)
        r.append((w>>0 ) & 0xff)
    return r


ZERO_128 = (0,)*16


class AEZ:

    def __init__(self, key):
        if len(key) == (384 // 8):
            self.K = map(ord, key)
        else:
            self.K = map(ord, pyblake2.blake2b(data=key, digest_size=48).digest())

        assert len(self.K) == 48

        self.I = self.K[0:16]
        self.J = self.K[16:32]
        self.L = self.K[32:48]
        assert self.I+self.J+self.L == self.K


    def AES_N(self, x, roundkeys):
        """Does an AES4 or AES10 encryption on x, using roundkeys as
           the keys."""
        a = aes.AES("x"*16)
        a._Ke = [ blockToWords(r) for r in roundkeys ]
        out = a.encrypt(x[:])
        return wordsToBlock(out)

    def AES4(self, x, roundkeys):
        assert len(roundkeys) == 5
        return self.AES_N(x, roundkeys)

    def AES10(self, x, roundkeys):
        assert len(roundkeys) == 11
        return self.AES_N(x, roundkeys)

    def E(self, x, j, i):
        """Scaled-down tweakable block cipher to encrypt 'x'. Uses (j,i)
           as the tweaks, and takes the key from self.(I,J,L)

        TWEAKS:  (AES4 unless specified)
            (-1, 1)     is used to compute S_y from S_x. (AES10)
            (-1, 2)     is used to compute C_y from S_y. (AES10)
            (-1, 3)     is used to generate data in the PRF. (AES10)
            (-1, 4)     is used to compute C_u from S. (AES10)
            (-1, 5)     is used to compute C_v from S. (AES10)


            (0, 0)      is used in the first phase of AEZ-core to make X_i.
                        and again in the second phase to make C'_i
            (0, 1)      is used to extract part of M_y for S_x
            (0, 2)      is used to compute part of C_x from C_y
            (0, 3)      is used for the narrow output case of AEZ-tiny
            (0, 4)      is used to extract part of X from M_u
            (0, 5)      is used to extract part of X from M_v
            (0, 6)      is used in the core of the wide case of AEZ-tiny
            (0, 7)      is used in the core of the narrow case of AEZ-tiny

            (1, i)      is used to compute W_i from M_i and M'_i and
                       and again in the second phase to make C_i
            (2, i)      is used to compute S' from S for C_i and C'_i

            (3...., i)  is used for AEZ_hash.
        """

        assert len(x) == 16
        I,J,L = self.I, self.J, self.L

        assert j >= -1

        if j == -1:
            # assert 1 <= i <= 5
            rounds = (ZERO_128, I,J,L,I,J,L,I,J,L,I)
            return self.AES10(xor(x, multiply(i, J)), rounds) # spec error XXXX

        elif j == 0:
            # assert 0 <= i <= 7
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
            delta = xor(multiply(factor1, L), multiply(factor2, J))
            v = self.AES4(xor(x, delta), (ZERO_128, J,I,L, ZERO_128))
            return xor(v, delta)

    def AEZ_hash(self, T):
        delta = [0]*16
        for i in xrange(1,len(T)+1):
            t = T[i-1]
            j = i + 2
            m = max(1, (len(t)+15)//16)
            for idx in xrange(1,m+1):
                block = t[(idx-1)*16:idx*16]
                if idx == m and len(block) != 16:
                    block = pad_1_0(block)
                    idx = 0
                delta = xor(delta, self.E(block,j,idx))
        return delta

    def AEZ_prf(self, T, nBytes):
        delta = self.AEZ_hash(T)
        return self.AEZ_prf_inner(delta, nBytes)

    def AEZ_prf_inner(self, delta, nBytes):
        result = []
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

        # Split X into L and R.  We don't handle a odd number of bits.
        if len(X) & 1:
            L = X[:len(X)//2+1]
            L[-1] &= 0xf0
            R_tmp = X[len(X)//2:]
            # now shift R 4 bits upwards.
            R = [ (R_tmp[0]<<4)&255 ]
            for b in R_tmp[1:]:
                R[-1] |= b>>4
                R.append((b<<4)&255)
            def mask(x):
                r = x[:]
                r[-1] &= 0xf0
                return r
            def pad(x):
                r = x[:]
                r[-1] |= 0x08
                return pad_1_0(r)
        else:
            L = X[:len(X)//2]
            R = X[len(X)//2:]
            def mask(x):
                return x
            pad = pad_1_0

        if m >= 128:
            i = 6
        else:
            i = 7

        for j in xrange(k):
            rhs = reduce(xor, [delta, pad(R), numToBlock(j)])
            rhs = self.E(rhs, 0, i)
            Rp = mask(xor(L, rhs[:len(L)]))
            L = R
            R = Rp

        if len(X) & 1:
            # concatenate bitwise
            C = L[:]
            for b in R:
                C[-1] |= (b>>4)
                C.append( (b<<4) & 0xf0)
            assert C[-1] == 0
            del C[-1]
        else:
            C = L + R

        if m < 128:
            inp = pad_0(C)
            inp[0] |= 0x80
            inp = xor(inp, delta)
            inp = self.E(inp, 0, 3)
            bit = inp[0] & 0x80
            C[0] ^= bit

        return C

    def Encipher_core(self,T,M):
        delta = self.AEZ_hash(T)
        nPairs = len(M) // 32
        M_i = [ (s[:16],s[16:])
                       for s in segment(M[:(nPairs-1)*32], 32) ]
        M_x, M_y = segment(M[-32:], 16)
        part_mid = M[(nPairs-1)*32:-32]
        d = len(part_mid) * 8
        if len(part_mid) < 16:
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
            pad_M_u = pad_1_0(M_u)
            X = reduce(xor, X_i, self.E(pad_M_u, 0, 4))
        else:
            pad_M_v = pad_1_0(M_v)
            iv = xor(self.E(M_u, 0, 4), self.E(pad_M_v,0,5))
            X = reduce(xor, X_i, iv)

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
            C_u = C_v = []
            Y = reduce(xor, Y_i, ZERO_128)
        elif d <= 127:
            C_u = xor(M_u, self.E(S, -1, 4)[:len(M_u)])
            C_v = []
            Y = reduce(xor, Y_i, self.E(pad_1_0(C_u), 0, 4))
        else:
            C_u = xor(M_u, self.E(S, -1, 4))
            C_v = xor(M_v, self.E(S, -1, 5)[:len(M_v)])
            Y = reduce(xor, Y_i, xor(self.E(C_u, 0, 4),
                                     self.E(pad_1_0(C_v), 0, 5)))

        # 232: compute C_x, C_y
        C_y = xor(S_x, self.E(S_y, -1, 2))
        C_x = reduce(xor, [S_y, delta, Y, self.E(C_y, 0, 2)])

        # Flatten output
        r = [a+b for a,b in zip(C_i, Cp_i)]
        r.extend([C_u, C_v, C_x, C_y])
        return reduce(list.__add__, r)

    def Encipher(self, T,X):
        if len(X) < 32:
            return self.Encipher_tiny(T,X)
        else:
            return self.Encipher_core(T,X)

    def Encrypt(self, N, A, tau, M):
        X = map(ord, M) + [0] * (tau // 8)
        T = [ numToBlock(tau), map(ord,N) ]
        T += A
        if len(M) == 0:
            r = self.AEZ_prf(T, tau // 8)
        else:
            r = self.Encipher(T, X)
        return r

