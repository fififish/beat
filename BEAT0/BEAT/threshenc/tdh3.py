from charm.core.engine.protocol import *
from charm.toolbox.ecgroup import ECGroup,ZR,G
from charm.toolbox.eccurve import prime192v2
from base64 import encodestring, decodestring
import random
from Crypto.Hash import SHA256
import time
import functools
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair

# Author: Sisi Duan

# Securing Threshold Cryptosystems against Chosen Ciphertext Attack

# Victor Shoup and Rosario Gennaro
#https://link.springer.com/article/10.1007/s00145-001-0020-9


# Dependencies: Charm, http://jhuisi.github.io/charm/, dev branch
#         a wrapper for ECGroup (Elliptic curve based crypto)


group = ECGroup(prime192v2)


g = group.random(G)
g1 = group.random(G)

ZERO = group.random(ZR)*0
ONE = group.random(ZR)*0+1


def serialize(g):
    return decodestring(group.serialize(g)[2:])

def hashG(g): #H_1
    return SHA256.new(serialize(g)).digest()

def hashH(x, L, u, w, u1, w1): #H_2
    return group.hash(x+L+serialize(u)+serialize(w)+serialize(u1)+serialize(w1))

def hash4(u, u1, h1): #H_4
    return group.hash(serialize(u)+serialize(u1)+serialize(h1))



def xor(x,y):
    result = []
    for x_, y_ in zip(x, y):
        result.append(bytes([x_ ^ y_]))
    return b''.join(result)



def convert(num):
    output = ZERO
    if num>0:
        for i in range(num):
            output += ONE
    elif num<0:
        for i in range(0-num):
            output -= ONE
    return output


#k -- threshold
#VK -- verification key
#VKs -- verification keys
#SK -- private keys
class TDHPublicKey(object):
    def __init__(self, l, k, VK, VKs): #l: number of players, k: threshold
        self.l = l
        self.k = k
        self.VK = VK
        self.VKs = VKs

    def lagrange(self, S, j):
        # Assert S is a subset of range(0,self.l)
        assert len(S) == self.k
        assert type(S) is set
        assert S.issubset(range(0,self.l))
        S = sorted(S)

        assert j in S
        assert 0 <= j < self.l
        
        mul = lambda a,b: a*b

        num = functools.reduce(mul, [ZERO - jj*ONE -ONE for jj in S if jj != j], ONE)
        den = functools.reduce(mul, [j*ONE - jj*ONE for jj in S if jj != j], ONE)


        return num*(den**(-1))
    


    def encrypt(self, m, L):
        # Only encrypt 32 byte strings
        #assert len(m) == 32
        r = group.random(ZR)
        s = group.random(ZR)
        c  = xor(m, hashG(self.VK**r))
        u = g ** r
        w = g ** s
        u1 = g1 ** r
        w1 = g1 **s 
        e = hashH(c,L,u,w,u1,w1)
        f = s + r*e
        C = (c, L, u, u1, e, f)
        return C

    def verify_ciphertext(self, cipher): 
        (c, L, u, u1, e, f) = cipher
        # Check correctness of ciphertext
        w = (g ** f)/(u **e)
        w1 = (g1 **f)/(u1 ** e)
        H = hashH(c, L, u, w, u1, w1)
        assert e == H
        return True

    def verify_share(self, i, share, cipher):
        (u_i, e_i, f_i) = share
        (c, L, u, u1, e, f) = cipher
        assert 0 <= i < self.l
        h_i = self.VKs[i]
        u1_i = (u ** f_i)/(u_i ** e_i)
        h1_i = (g ** f_i)/(h_i ** e_i)
        H = hash4(u_i,u1_i,h1_i)
        assert e_i == H
        return True

    def combine_shares(self, cipher, shares):
        (c, L, u, u1, e, f) = cipher
        # sigs: a mapping from idx -> sig
        S = set(shares.keys())
        assert S.issubset(range(self.l))

        mul = lambda a,b: a*b

        res = g**ZERO
        for j,share in shares.items():
            res = res*(share[0] ** self.lagrange(S, j))

        return xor(hashG(res), c)


class TDHPrivateKey(TDHPublicKey):
    def __init__(self, l, k, VK, VKs, SK, i):
        super(TDHPrivateKey,self).__init__(l, k, VK, VKs)
        assert 0 <= i < self.l
        self.i = i
        self.SK = SK

    def decrypt_share(self, cipher):
        (c, L, u, u1, e, f) = cipher
        u_i = u ** self.SK
        si = group.random(ZR)
        u1_i = u ** si
        h1_i = g ** si
        e_i = hash4(u_i, u1_i, h1_i)
        f_i = si + self.SK * e_i
        S = (u_i, e_i, f_i)
        return S
    

def dealer(players=10, k=5):
    # Random polynomial coefficients
    secret = group.random(ZR)
    a = [secret]
    for i in range(1,k):
        a.append(group.random(ZR))
    assert len(a) == k

    # Polynomial evaluation
    def f(x):
        y = ZERO
        xx = ONE
        for coeff in a:
            y += coeff * xx
            xx *= x
        return y

    # Shares of master secret key
    SKs = [f(i) for i in range(1,players+1)]
    assert f(0) == secret

    # Verification keys
    VK = g ** secret #equal to public key h=h_0 = g^F(0)
    VKs = [g ** xx for xx in SKs] # (h_1...h_n) where h_i = g^F(x_i)

    public_key = TDHPublicKey(players, k, VK, VKs)
    private_keys = [TDHPrivateKey(players, k, VK, VKs, SK, i)
                    for i, SK in enumerate(SKs)]

    # Check reconstruction of 0
    S = set(range(0,k))
    lhs = f(0)
    rhs = sum(public_key.lagrange(S,j) * f(j+1) for j in S)
    assert lhs == rhs
    
    return public_key, private_keys


def test():
    global PK, SKs
    PK, SKs = dealer(players=2,k=2)
    
    msg = 'message'
    label = 'label'
    m = SHA256.new(msg.encode('utf-8')).digest()
    L = SHA256.new(label.encode('utf-8')).digest()
    C = PK.encrypt(m, L)

    uu = C[2]

    t1 = time.time()
    assert PK.verify_ciphertext(C)

    shares = [sk.decrypt_share(C) for sk in SKs]
    for i,share in enumerate(shares):
        assert PK.verify_share(i, share, C)


    SS = list(range(PK.l))
    for i in range(1):
        random.shuffle(SS)
        S = set(SS[:PK.k])
        m_ = PK.combine_shares(C, dict((s,shares[s]) for s in S))
        assert m_ == m

    t2 = time.time()
    print ("time: %f"%(t2-t1))
    print ("done.")


def main():
    test()

if __name__ == '__main__':
    main()