# BEAT0
BEAT: Asynchronous BFT Made Practical


### Installation && How to run the code

Working directory is the **current directory**. All the bold vars are experiment parameters:

+ **N** means the total number of parties;
+ **t** means the tolerance, usually N/4 in our experiments;
+ **B** means the maximum number of transactions committed in a block (by default N log N). And therefore each party proposes B/N transactions.

#### Dependencies 
pbc

    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
    tar -xvf pbc-0.5.14.tar.gz
    cd pbc-0.5.14
    ./configure ; make ; sudo make install
    export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

charm

    sudo apt-get install python3-dev
    git clone https://github.com/JHUISI/charm.git
    cd charm
    git checkout 2.7-dev
    ./configure.sh
    sudo python setup.py install


Python dependencies (2.7)

    gevent
    greenlet
    pycrypto


Generate the keys
+ Threshold PRF Keys

    python -m BEAT.commoncoin.prf_generate_keys N (t+1) > thsigN_t.keys

+ ECDSA Keys

    python -m BEAT.ecdsa.generate_keys_ecdsa N > ecdsa.keys

+ Threshold Encryption Keys

    python -m BEAT.threshenc.generate_keys N (N-2t) > thencN_t.keys


Usually, we run ecdsa key generation with large N just once because it can be re-used for different N/t.
And we can store threshold signature keys and threshold encryption keys into different files for convenience.

##### Launch the code locally
    python -m BEAT.test.honest_party_test -k thsigN_t.keys -e ecdsa.keys -b B -n N -t t -c thencN_t.keys s

    If 'Consensus Finished' is printed, the experiment is successful. Errors will be printed in the end which could be ignored.

### How to deploy the Amazon EC2 experiment

Please refer to the README under EC2 folder for more details.