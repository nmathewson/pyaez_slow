#!/usr/bin/python

from aez import AEZ
from test_vectors import *

import binascii
h = binascii.a2b_hex
b = lambda bytes: map(ord, bytes)
def b2h(bb):
    r = "".join("%02x"%b for b in bb)

def testExtract():
    inp = ""
    out = h("b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100")
    assert AEZ(inp).K == b(out)

    inp = h("48656c6c6f20776f726c64")
    out = h("29cecb04dd421f862f198ea2e860151ada653a38e9d0aacd0a201cb7a5644ec215dd6ef51b70aba7196903ae2be6fdd4")
    assert AEZ(inp).K == b(out)

    inp = h("5468697320737472696e6720697320666f7274756e61746520746f206861766520343820627974656163746572732121")
    out = inp
    assert AEZ(inp).K == b(out)

    for x,y in EXTRACT_VECTORS:
        inp = h(x)
        assert AEZ(inp).K == b(h(y))

    print "%d/%d Extract okay"%(len(EXTRACT_VECTORS), len(EXTRACT_VECTORS))

def testMult():
    expected = [
        "00000000000000000000000000000000",
        "74686973697361737469636b75702121",
        "e8d0d2e6d2e6c2e6e8d2c6d6eae04242",
        "9cb8bb95bb95a3959cbba5bd9f906363",
        "d1a1a5cda5cd85cdd1a58dadd5c08403",
        "a5c9ccbeccbee4bea5cceec6a0b0a522",
        "3971772b772b472b39774b7b3f20c641",
        "4d191e581e5826584d1e28104a50e760",
        "a3434b9b4b9b0b9ba34b1b5bab810881",
        "d72b22e822e86ae8d7227830def129a0",
        "4b93997d997dc97d4b99dd8d41614ac3",
        "3ffbf00ef00ea80e3ff0bee634116be2",
        "72e2ee56ee568e5672ee96f67e418c82",
        "068a87258725ef250687f59d0b31ada3",
        "9a323cb03cb04cb09a3c502094a1cec0",
        "ee5a55c355c32dc3ee55334be1d1efe1",
        "4686973697361737469636b757021185",
        "32eefe45fe45764432ff55dc227230a4",
        "ae5645d045d0d5d1ae44f061bde253c7",
        "da3e2ca32ca3b4a2da2d930ac89272e6",
        "972732fb32fb92fa9733bb1a82c29586",
        "e34f5b885b88f389e35ad871f7b2b4a7",
        "7ff7e01de01d501c7fe17dcc6822d7c4",
        "0b9f896e896e316f0b881ea71d52f6e5",
        "e5c5dcaddcad1cace5dd2decfc831904",
        "91adb5deb5de7ddf91b44e8789f33825",
        "0d150e4b0e4bde4a0d0feb3a16635b46",
        "797d67386738bf397966885163137a67",
        "34647960796099613478a04129439d07",
        "400c10131013f8124011c32a5c33bc26",
        "dcb4ab86ab865b87dcaa6697c3a3df45",
        "a8dcc2f5c2f53af4a8c305fcb6d3fe64"]
    msg = map(ord, "thisisastickup!!")
    from aez import multiply
    for i in xrange(0,32):
        r = "".join("%02x"%b for b in multiply(i, msg))
        assert r == expected[i]
    print "32/32 multiply okay"

def testE():
    key = h("5468697320737472696e6720697320666f7274756e61746520746f206861766520343820627974656163746572732121")
    out = AEZ(key).E([0]*16, 0, 0)
    assert out == b(h("8eb11d57f7aea44a297f110a57ede9ed"))

    key = h("5468697320737472696e6720697320666f7274756e61746520746f206861766520343820636861726163746572732121")
    out = AEZ(key).E([0]*16, 0, 0)
    assert out == b(h("1e516d27ae0f05b2b5e3ae29c645d07c"))

    key = h("5468697320737472696e6720697320666f7274756e61746520746f206861766520343820636861726163746572732121")
    out = AEZ(key).E([0]*16, 0, 1)
    assert out == b(h("d0b9f8104073fce8d5287d693c715e0d"))

    out = AEZ(key).E([0]*15 + [1], 0, 0)
    assert out == b(h("8edc3cbb3358e4a60277063d9a98c7bb"))

    for K,j,i,inp,out in E_VECTORS:
        result = AEZ(h(K)).E(b(h(inp)), j, i)
        assert result == b(h(out))

    print "%d/%d E okay"%(len(E_VECTORS), len(E_VECTORS))

def testHash():
    from aez import numToBlock
    for K, tau, T_rest, V in HASH_VECTORS:
        t0 = numToBlock(tau)
        T = [t0] + [b(h(t)) for t in  T_rest]
        out = AEZ(h(K)).AEZ_hash(T)
        assert out == b(h(V))
    print "%d/%d AEZ-hash okay"%((len(HASH_VECTORS),)*2)

def testPRF():
    for K, delta, taubytes, R in PRF_VECTORS:
        out = AEZ(h(K)).AEZ_prf_inner(b(h(delta)), taubytes)
        assert out == b(h(R))
    print "%d/%d AEZ-prf okay"%((len(PRF_VECTORS),)*2)

def testEncrypt(decrypt_too=False):
    ok = 0
    for K, N, A, taubytes, M, C in ENCRYPT_VECTORS:
        out = AEZ(h(K)).Encrypt(h(N), map(h, A), taubytes * 8, h(M))
        if out == h(C):
            ok += 1
        else:
            print "BAD (taubytes=%d,len(M)=%d)"%(taubytes, len(M)//2)
            continue

        if decrypt_too:
            D = AEZ(h(K)).Decrypt(h(N), map(h,A), taubytes*8, out)
            assert D == h(M)

    print "%d/%d encryptions okay"%(ok,len(ENCRYPT_VECTORS))
    assert ok == len(ENCRYPT_VECTORS)

def testVectors():
    testExtract()
    testMult()
    testE()
    testHash()
    testPRF()
    testEncrypt()
    print "OK"

if __name__ == '__main__':
    testVectors()
