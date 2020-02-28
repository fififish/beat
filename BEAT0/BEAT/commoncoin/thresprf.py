from charm.toolbox.ecgroup import ECGroup,ZR,G
from charm.toolbox.eccurve import prime256v1
from base64 import encodestring, decodestring
import random
import time


group = ECGroup(prime256v1)


g = group.random(G)
g1 = group.random(G)

ZERO = group.init(ZR,0)
ONE = group.init(ZR,1)

def serialize(g):
    # Only work in G1 here
    return decodestring(group.serialize(g)[2:])

def serialize1(g):
    return group.serialize(g)

def deserialize(g):
    return group.deserialize(g)

def deserialize2(g):
    # Only work in G1 here
    return group.deserialize('2:'+encodestring(g))

def hashH(gg, g_i,h,g_1,g_1_b,h_1): 
    return group.hash(serialize(gg)+serialize(g_i)+serialize(h)+serialize(g_1)+serialize(g_1_b)+serialize(h_1))


class TPRFPublicKey(object):
    def __init__(self, l, k, VK, VKs):
        self.l = l
        self.k = k
        self.VK = VK
        self.VKs = VKs

    def __getstate__(self):
        d = dict(self.__dict__)
        d['VK'] = serialize1(self.VK)
        d['VKs'] = map(serialize1,self.VKs)
        return d

    def __setstate__(self, d):
        self.__dict__ = d
        self.VK = deserialize(self.VK)
        self.VKs = map(deserialize,self.VKs)
        print "I'm being depickled"

    def lagrange(self, S, j):
        # Assert S is a subset of range(0,self.l)
        assert len(S) == self.k
        assert type(S) is set
        assert S.issubset(range(0,self.l))
        S = sorted(S)

        assert j in S
        assert 0 <= j < self.l
        
        mul = lambda a,b: a*b
        num = reduce(mul, [ZERO - jj*ONE - ONE   for jj in S if jj != j])
        den = reduce(mul, [j*ONE - jj*ONE   for jj in S if jj != j])

        return num*(den ** (-1))

    def hash_message(self, m):
        return group.hash(m,G)

    def verify_share(self, gg, sig, g_1, i, c, z):
        assert 0 <= i < self.l
        h = ( gg ** z )/(self.VKs[i] ** c)
        h_1 = ( g_1 ** z)/(sig ** c)
        c_1 = hashH(gg, self.VKs[i],h,g_1,sig,h_1)
        return c_1 == c

    def verify_signature(self, sig, g_1):
        return True

    def combine_shares(self, sigs):
        # sigs: a mapping from idx -> sig
        S = set(sigs.keys())
        assert S.issubset(range(self.l))

        mul = lambda a,b: a*b
        res = reduce(mul, 
                     [sig ** self.lagrange(S, j) 
                      for j,sig in sigs.iteritems()])
        return res


class TPRFPrivateKey(TPRFPublicKey):
    def __init__(self, l, k, VK, VKs, SK, i):
        super(TPRFPrivateKey,self).__init__(l, k, VK, VKs)
        assert 0 <= i < self.l
        self.i = i
        self.SK = SK

    def sign(self, g_1, gg):
        g_i_1 = g_1 ** self.SK
        s = group.random()
        h = gg ** s
        h_1 = g_1 ** s
        c = hashH(gg, self.VKs[self.i],h,g_1,g_i_1,h_1)
        z = s + self.SK * c

        return  (g_i_1,c,z)

def dealer(players=10, k=5):
    # Random polynomial coefficients
    secret = group.random()
    a = [secret]
    for i in range(1,k):
        a.append(group.random())
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
    SKs = [f(i) for i in range(1, players+1)]
    assert f(0) == secret

    # Verification keys
    VK = g ** secret
    VKs = [g ** xx for xx in SKs]

    public_key = TPRFPublicKey(players, k, VK, VKs)
    private_keys = [TPRFPrivateKey(players, k, VK, VKs, SK, i)
                    for i, SK in enumerate(SKs)]

    # Check reconstruction of 0
    S = set(range(0,k))
    lhs = f(0)
    rhs = sum(public_key.lagrange(S,j) * f(j+1) for j in S)
    assert lhs == rhs

    return public_key, private_keys, g #, secret


def test():
    global PK, SKs, gg
    PK, SKs, gg = dealer(players=4,k=2)
    #PK, SKs, a = dealer(players=4,k=2)

    global sigs,g_1
    sigs = {}
    proof_c = {}
    proof_z = {}
    g_1 = PK.hash_message('hi')

    

    t1 = time.time()
    for i,SK in enumerate(SKs):
        sigs[SK.i],proof_c[SK.i],proof_z[SK.i] = SK.sign(g_1,gg)
        assert PK.verify_share(gg,sigs[SK.i],g_1,i,proof_c[SK.i],proof_z[SK.i])

    SS = range(PK.l)
    for i in range(64*4):
        random.shuffle(SS)
        S = set(SS[:PK.k])
        sig = PK.combine_shares(dict((s,sigs[s]) for s in S))
        assert PK.verify_signature(sig,g_1)


    t2 = time.time()
    print ("time: %f"%(t2-t1))
    print "done"

def main():
    test()

if __name__ == '__main__':
    main()