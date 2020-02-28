from charm.toolbox.ecgroup import ECGroup,ZR,G
from charm.toolbox.eccurve import prime256v1
from thresprf import dealer, serialize, serialize1, deserialize
import gevent
import gipc
import time
import random

if '_procs' in globals():
    for p,pipe in _procs: 
        p.terminate()
        p.join()
    del _procs
_procs = []

def _worker(PK,pipe):
    while True:
        #(h, sigs) = pipe.get()
        (h, sigs, proof_c, proof_z,gg) = pipe.get()
        sigs = dict(sigs)
        proof_c = dict(proof_c)
        proof_z = dict(proof_z)
        
        for s in sigs: 
            sigs[s] = deserialize(sigs[s])
            proof_c[s] = deserialize(proof_c[s])
            proof_z[s] = deserialize(proof_z[s])
        
        h = deserialize(h)
        gg = deserialize(gg)

        for s in sigs:
            assert PK.verify_share(gg,sigs[s],h,s,proof_c[s],proof_z[s])
        sig = PK.combine_shares(sigs)
        res = PK.verify_signature(sig, h)
        pipe.put(res)

myPK = None

def initialize(PK, size=1):
    global _procs, myPK
    myPK = PK
    _procs = []
    for s in range(size):
        (r,w) = gipc.pipe(duplex=True)
        p = gipc.start_process(_worker, args=(PK, r,))
        _procs.append((p,w))

def combine_and_verify(h, sigs,proof_c,proof_z,gg):
#def combine_and_verify(h, sigs):
    # return True  # we are skipping the verification
    assert len(sigs) == myPK.k
    assert len(proof_c) == myPK.k
    assert len(proof_z) == myPK.k
    sigs = dict((s,serialize1(v)) for s,v in sigs.iteritems())
    proof_c = dict((s,serialize1(v)) for s,v in proof_c.iteritems())
    proof_z = dict((s,serialize1(v)) for s,v in proof_z.iteritems())

    h = serialize1(h)
    gg = serialize1(gg)
    # Pick a random process
    _,pipe = _procs[random.choice(range(len(_procs)))] #random.choice(_procs)
    pipe.put((h,sigs,proof_c,proof_z,gg))
    assert pipe.get() == True

def pool_test():
    global PK, SKs,gg
    PK, SKs,gg = dealer(players=4,k=2)

    global sigs,h
    sigs = {}
    proof_c = {}
    proof_z = {}
    h = PK.hash_message('hi')
    for SK in SKs:
        sigs[SK.i],proof_c[SK.i],proof_z[SK.i] = SK.sign(h,gg)

    initialize(PK)

    sigs = dict(list(sigs.iteritems())[:PK.k])
    proof_c = dict(list(proof_c.iteritems())[:PK.k])
    proof_z = dict(list(proof_z.iteritems())[:PK.k])

    # Combine 100 times
    if 1:
        #promises = [pool.apply_async(_combine_and_verify, 
        #                             (_h, sigs2))
        #            for i in range(100)]
        threads = []
        for i in range(100):
            threads.append(gevent.spawn(combine_and_verify, h, sigs, proof_c, proof_z,gg))
        print 'launched', time.time()
        gevent.joinall(threads)
        #for p in promises: assert p.get() == True
        print 'done', time.time()

    # Combine 100 times
    if 0:
        print 'launched', time.time()
        for i in range(10):
            _combine_and_verify(_h, sigs2)
        print 'done', time.time()

    print 'work done'

def main():
    pool_test()

if __name__ == '__main__':
    main()