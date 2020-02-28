# -*- Mode: Python -*-
# Python Version >= 2

# OpenSSL wrapper, part of this is from
# https://github.com/joric/brutus/blob/master/ecdsa_ssl.py

# Combining the solution from https://pastebin.com/H1XikJFd to solve the segmentation error on mac

import ctypes
import ctypes.util
import codecs

class _OpenSSL:
    """
   Wrapper for OpenSSL using ctypes
   """
    def __init__(self, library):
        """
       Build the wrapper
       """
        self._lib = ctypes.CDLL(library)
 
        self.pointer = ctypes.pointer
        self.c_int = ctypes.c_int
        self.byref = ctypes.byref
        self.create_string_buffer = ctypes.create_string_buffer
 
        self.BN_new = self._lib.BN_new
        self.BN_new.restype = ctypes.c_void_p
        self.BN_new.argtypes = []
 
        self.BN_free = self._lib.BN_free
        self.BN_free.restype = None
        self.BN_free.argtypes = [ctypes.c_void_p]
 
        self.BN_copy = self._lib.BN_copy
        self.BN_copy.restype = ctypes.c_void_p
        self.BN_copy.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
 
        self.BN_mul_word = self._lib.BN_mul_word
        self.BN_mul_word.restype = ctypes.c_int
        self.BN_mul_word.argtypes = [ctypes.c_void_p, ctypes.c_int]
 
        self.BN_set_word = self._lib.BN_set_word
        self.BN_set_word.restype = ctypes.c_int
        self.BN_set_word.argtypes = [ctypes.c_void_p, ctypes.c_int]
 
        self.BN_add = self._lib.BN_add
        self.BN_add.restype = ctypes.c_void_p
        self.BN_add.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_void_p]
 
        self.BN_mod_sub = self._lib.BN_mod_sub
        self.BN_mod_sub.restype = ctypes.c_int
        self.BN_mod_sub.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p,
                                    ctypes.c_void_p,
                                    ctypes.c_void_p]
 
        self.BN_mod_mul = self._lib.BN_mod_mul
        self.BN_mod_mul.restype = ctypes.c_int
        self.BN_mod_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p,
                                    ctypes.c_void_p,
                                    ctypes.c_void_p]
 
        self.BN_mod_inverse = self._lib.BN_mod_inverse
        self.BN_mod_inverse.restype = ctypes.c_void_p
        self.BN_mod_inverse.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_void_p,
                                        ctypes.c_void_p]
 
        self.BN_cmp = self._lib.BN_cmp
        self.BN_cmp.restype = ctypes.c_int
        self.BN_cmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
 
        self.BN_num_bits = self._lib.BN_num_bits
        self.BN_num_bits.restype = ctypes.c_int
        self.BN_num_bits.argtypes = [ctypes.c_void_p]
 
        self.BN_bn2bin = self._lib.BN_bn2bin
        self.BN_bn2bin.restype = ctypes.c_int
        self.BN_bn2bin.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
 
        self.BN_bin2bn = self._lib.BN_bin2bn
        self.BN_bin2bn.restype = ctypes.c_void_p
        self.BN_bin2bn.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                   ctypes.c_void_p]
 
        self.EC_KEY_free = self._lib.EC_KEY_free
        self.EC_KEY_free.restype = None
        self.EC_KEY_free.argtypes = [ctypes.c_void_p]
 
        self.EC_KEY_new_by_curve_name = self._lib.EC_KEY_new_by_curve_name
        self.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
        self.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]
 
        self.EC_KEY_generate_key = self._lib.EC_KEY_generate_key
        self.EC_KEY_generate_key.restype = ctypes.c_int
        self.EC_KEY_generate_key.argtypes = [ctypes.c_void_p]
 
        self.EC_KEY_check_key = self._lib.EC_KEY_check_key
        self.EC_KEY_check_key.restype = ctypes.c_int
        self.EC_KEY_check_key.argtypes = [ctypes.c_void_p]
 
        self.EC_KEY_get0_private_key = self._lib.EC_KEY_get0_private_key
        self.EC_KEY_get0_private_key.restype = ctypes.c_void_p
        self.EC_KEY_get0_private_key.argtypes = [ctypes.c_void_p]
 
        self.EC_KEY_get0_public_key = self._lib.EC_KEY_get0_public_key
        self.EC_KEY_get0_public_key.restype = ctypes.c_void_p
        self.EC_KEY_get0_public_key.argtypes = [ctypes.c_void_p]
 
        self.EC_KEY_get0_group = self._lib.EC_KEY_get0_group
        self.EC_KEY_get0_group.restype = ctypes.c_void_p
        self.EC_KEY_get0_group.argtypes = [ctypes.c_void_p]
 
        self.EC_POINT_get_affine_coordinates_GFp = self._lib.EC_POINT_get_affine_coordinates_GFp
        self.EC_POINT_get_affine_coordinates_GFp.restype = ctypes.c_int
        self.EC_POINT_get_affine_coordinates_GFp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
 
        self.EC_KEY_set_private_key = self._lib.EC_KEY_set_private_key
        self.EC_KEY_set_private_key.restype = ctypes.c_int
        self.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p,
                                                ctypes.c_void_p]
 
        self.EC_KEY_set_public_key = self._lib.EC_KEY_set_public_key
        self.EC_KEY_set_public_key.restype = ctypes.c_int
        self.EC_KEY_set_public_key.argtypes = [ctypes.c_void_p,
                                               ctypes.c_void_p]
 
        self.EC_KEY_set_group = self._lib.EC_KEY_set_group
        self.EC_KEY_set_group.restype = ctypes.c_int
        self.EC_KEY_set_group.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
 
        self.EC_POINT_set_affine_coordinates_GFp = self._lib.EC_POINT_set_affine_coordinates_GFp
        self.EC_POINT_set_affine_coordinates_GFp.restype = ctypes.c_int
        self.EC_POINT_set_affine_coordinates_GFp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
 
        self.EC_POINT_set_compressed_coordinates_GFp = self._lib.EC_POINT_set_compressed_coordinates_GFp
        self.EC_POINT_set_compressed_coordinates_GFp.restype = ctypes.c_int
        self.EC_POINT_set_compressed_coordinates_GFp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
 
        self.EC_POINT_new = self._lib.EC_POINT_new
        self.EC_POINT_new.restype = ctypes.c_void_p
        self.EC_POINT_new.argtypes = [ctypes.c_void_p]
 
        self.EC_POINT_free = self._lib.EC_POINT_free
        self.EC_POINT_free.restype = None
        self.EC_POINT_free.argtypes = [ctypes.c_void_p]
 
        self.BN_CTX_free = self._lib.BN_CTX_free
        self.BN_CTX_free.restype = None
        self.BN_CTX_free.argtypes = [ctypes.c_void_p]
 
        self.EC_GROUP_get_order = self._lib.EC_GROUP_get_order
        self.EC_GROUP_get_order.restype = ctypes.c_void_p
        self.EC_GROUP_get_order.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
 
        self.EC_GROUP_get_degree = self._lib.EC_GROUP_get_degree
        self.EC_GROUP_get_degree.restype = ctypes.c_void_p
        self.EC_GROUP_get_degree.argtypes = [ctypes.c_void_p]
 
        self.EC_GROUP_get_curve_GFp = self._lib.EC_GROUP_get_curve_GFp
        self.EC_GROUP_get_curve_GFp.restype = ctypes.c_void_p
        self.EC_GROUP_get_curve_GFp.argtypes = [ctypes.c_void_p,
                                                ctypes.c_void_p,
                                                ctypes.c_void_p,
                                                ctypes.c_void_p,
                                                ctypes.c_void_p]
 
        self.EC_POINT_mul = self._lib.EC_POINT_mul
        self.EC_POINT_mul.restype = ctypes.c_int
        self.EC_POINT_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_void_p]
 
        self.i2d_ECPrivateKey = self._lib.i2d_ECPrivateKey
        
        self.EC_KEY_set_private_key = self._lib.EC_KEY_set_private_key
        self.EC_KEY_set_private_key.restype = ctypes.c_int
        self.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p,
                                                ctypes.c_void_p]
 
        self.EC_KEY_set_conv_form = self._lib.EC_KEY_set_conv_form
        self.EC_KEY_set_conv_form.restype = None
        self.EC_KEY_set_conv_form.argtypes = [ctypes.c_void_p,
                                              ctypes.c_int]
 
        self.ECDH_OpenSSL = self._lib.ECDH_OpenSSL
        self._lib.ECDH_OpenSSL.restype = ctypes.c_void_p
        self._lib.ECDH_OpenSSL.argtypes = []
 
        self.BN_CTX_new = self._lib.BN_CTX_new
        self._lib.BN_CTX_new.restype = ctypes.c_void_p
        self._lib.BN_CTX_new.argtypes = []
 
        self.BN_CTX_start = self._lib.BN_CTX_start
        self._lib.BN_CTX_start.restype = ctypes.c_void_p
        self._lib.BN_CTX_start.argtypes = [ctypes.c_void_p]
 
        self.BN_CTX_get = self._lib.BN_CTX_get
        self._lib.BN_CTX_get.restype = ctypes.c_void_p
        self._lib.BN_CTX_get.argtypes = [ctypes.c_void_p]
 
        self.ECDH_set_method = self._lib.ECDH_set_method
        self._lib.ECDH_set_method.restype = ctypes.c_int
        self._lib.ECDH_set_method.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
 
        self.ECDH_compute_key = self._lib.ECDH_compute_key
        self.ECDH_compute_key.restype = ctypes.c_int
        self.ECDH_compute_key.argtypes = [ctypes.c_void_p,
                                          ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
 
        self.EVP_CipherInit_ex = self._lib.EVP_CipherInit_ex
        self.EVP_CipherInit_ex.restype = ctypes.c_int
        self.EVP_CipherInit_ex.argtypes = [ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_void_p]
 
        self.EVP_CIPHER_CTX_new = self._lib.EVP_CIPHER_CTX_new
        self.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        self.EVP_CIPHER_CTX_new.argtypes = []
 
        # Cipher
        self.EVP_aes_128_cfb128 = self._lib.EVP_aes_128_cfb128
        self.EVP_aes_128_cfb128.restype = ctypes.c_void_p
        self.EVP_aes_128_cfb128.argtypes = []
 
        self.EVP_aes_256_cfb128 = self._lib.EVP_aes_256_cfb128
        self.EVP_aes_256_cfb128.restype = ctypes.c_void_p
        self.EVP_aes_256_cfb128.argtypes = []
 
        self.EVP_aes_128_cbc = self._lib.EVP_aes_128_cbc
        self.EVP_aes_128_cbc.restype = ctypes.c_void_p
        self.EVP_aes_128_cbc.argtypes = []
 
        self.EVP_aes_256_cbc = self._lib.EVP_aes_256_cbc
        self.EVP_aes_256_cbc.restype = ctypes.c_void_p
        self.EVP_aes_256_cbc.argtypes = []
 
        #self.EVP_aes_128_ctr = self._lib.EVP_aes_128_ctr
        #self.EVP_aes_128_ctr.restype = ctypes.c_void_p
        #self.EVP_aes_128_ctr.argtypes = []
 
        #self.EVP_aes_256_ctr = self._lib.EVP_aes_256_ctr
        #self.EVP_aes_256_ctr.restype = ctypes.c_void_p
        #self.EVP_aes_256_ctr.argtypes = []
 
        self.EVP_aes_128_ofb = self._lib.EVP_aes_128_ofb
        self.EVP_aes_128_ofb.restype = ctypes.c_void_p
        self.EVP_aes_128_ofb.argtypes = []
 
        self.EVP_aes_256_ofb = self._lib.EVP_aes_256_ofb
        self.EVP_aes_256_ofb.restype = ctypes.c_void_p
        self.EVP_aes_256_ofb.argtypes = []
 
        self.EVP_bf_cbc = self._lib.EVP_bf_cbc
        self.EVP_bf_cbc.restype = ctypes.c_void_p
        self.EVP_bf_cbc.argtypes = []
 
        self.EVP_bf_cfb64 = self._lib.EVP_bf_cfb64
        self.EVP_bf_cfb64.restype = ctypes.c_void_p
        self.EVP_bf_cfb64.argtypes = []
 
        self.EVP_rc4 = self._lib.EVP_rc4
        self.EVP_rc4.restype = ctypes.c_void_p
        self.EVP_rc4.argtypes = []
 
        self.EVP_CIPHER_CTX_cleanup = self._lib.EVP_CIPHER_CTX_cleanup
        self.EVP_CIPHER_CTX_cleanup.restype = ctypes.c_int
        self.EVP_CIPHER_CTX_cleanup.argtypes = [ctypes.c_void_p]
 
        self.EVP_CIPHER_CTX_free = self._lib.EVP_CIPHER_CTX_free
        self.EVP_CIPHER_CTX_free.restype = None
        self.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
 
        self.EVP_CipherUpdate = self._lib.EVP_CipherUpdate
        self.EVP_CipherUpdate.restype = ctypes.c_int
        self.EVP_CipherUpdate.argtypes = [ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
 
        self.EVP_CipherFinal_ex = self._lib.EVP_CipherFinal_ex
        self.EVP_CipherFinal_ex.restype = ctypes.c_int
        self.EVP_CipherFinal_ex.argtypes = [ctypes.c_void_p,
                                            ctypes.c_void_p, ctypes.c_void_p]
 
        self.EVP_DigestInit = self._lib.EVP_DigestInit
        self.EVP_DigestInit.restype = ctypes.c_int
        self._lib.EVP_DigestInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
 
        self.EVP_DigestUpdate = self._lib.EVP_DigestUpdate
        self.EVP_DigestUpdate.restype = ctypes.c_int
        self.EVP_DigestUpdate.argtypes = [ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_int]
 
        self.EVP_DigestFinal = self._lib.EVP_DigestFinal
        self.EVP_DigestFinal.restype = ctypes.c_int
        self.EVP_DigestFinal.argtypes = [ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_void_p]
 
        self.EVP_ecdsa = self._lib.EVP_ecdsa
        self._lib.EVP_ecdsa.restype = ctypes.c_void_p
        self._lib.EVP_ecdsa.argtypes = []
 
        self.ECDSA_size = self._lib.ECDSA_size

        self.ECDSA_sign = self._lib.ECDSA_sign
        self.ECDSA_sign.restype = ctypes.c_int
        self.ECDSA_sign.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
 
        self.ECDSA_verify = self._lib.ECDSA_verify
        self.ECDSA_verify.restype = ctypes.c_int
        self.ECDSA_verify.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                      ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
 
        self.EVP_MD_CTX_create = self._lib.EVP_MD_CTX_create
        self.EVP_MD_CTX_create.restype = ctypes.c_void_p
        self.EVP_MD_CTX_create.argtypes = []
 
        self.EVP_MD_CTX_init = self._lib.EVP_MD_CTX_init
        self.EVP_MD_CTX_init.restype = None
        self.EVP_MD_CTX_init.argtypes = [ctypes.c_void_p]
 
        self.EVP_MD_CTX_destroy = self._lib.EVP_MD_CTX_destroy
        self.EVP_MD_CTX_destroy.restype = None
        self.EVP_MD_CTX_destroy.argtypes = [ctypes.c_void_p]
 
        self.RAND_bytes = self._lib.RAND_bytes
        self.RAND_bytes.restype = None
        self.RAND_bytes.argtypes = [ctypes.c_void_p, ctypes.c_int]
 
 
        self.EVP_sha256 = self._lib.EVP_sha256
        self.EVP_sha256.restype = ctypes.c_void_p
        self.EVP_sha256.argtypes = []
 
        self.i2o_ECPublicKey = self._lib.i2o_ECPublicKey
        self.i2o_ECPublicKey.restype = ctypes.c_void_p
        self.i2o_ECPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
 
        self.EVP_sha512 = self._lib.EVP_sha512
        self.EVP_sha512.restype = ctypes.c_void_p
        self.EVP_sha512.argtypes = []
 
        self.HMAC = self._lib.HMAC
        self.HMAC.restype = ctypes.c_void_p
        self.HMAC.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
                              ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
 
        self.PKCS5_PBKDF2_HMAC = self._lib.PKCS5_PBKDF2_HMAC
        self.PKCS5_PBKDF2_HMAC.restype = ctypes.c_int
        self.PKCS5_PBKDF2_HMAC.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                           ctypes.c_void_p, ctypes.c_int,
                                           ctypes.c_int, ctypes.c_void_p,
                                           ctypes.c_int, ctypes.c_void_p]
 
ssl = _OpenSSL(ctypes.util.find_library('ssl') or 'libeay32')

#ssl = ctypes.cdll.LoadLibrary (ctypes.util.find_library ('ssl') or 'libeay32')

# this specifies the curve used with ECDSA.
NID_secp256k1 = 714 # from openssl/obj_mac.h

# Thx to Sam Devlin for the ctypes magic 64-bit fix.
def check_result (val, func, args):
    if val == 0:
        raise ValueError
    else:
        return ctypes.c_void_p (val)

ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
ssl.EC_KEY_new_by_curve_name.errcheck = check_result

class KEY:

    def __init__(self):

        self.POINT_CONVERSION_COMPRESSED = 2
        self.POINT_CONVERSION_UNCOMPRESSED = 4
        self.k = ssl.EC_KEY_new_by_curve_name(NID_secp256k1)

    def __del__(self):
        if ssl:
            ssl.EC_KEY_free(self.k)
        self.k = None

    def generate(self, secret=None):
        if secret:
            self.prikey = secret
            priv_key = ssl.BN_bin2bn(secret, 32, ssl.BN_new())
            group = ssl.EC_KEY_get0_group(self.k)
            pub_key = ssl.EC_POINT_new(group)
            ctx = ssl.BN_CTX_new()
            ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
            ssl.EC_KEY_set_private_key(self.k, priv_key)
            ssl.EC_KEY_set_public_key(self.k, pub_key)
            ssl.EC_POINT_free(pub_key)
            ssl.BN_CTX_free(ctx)
            return self.k
        else:
            return ssl.EC_KEY_generate_key(self.k)

    def set_privkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        ssl.d2i_ECPrivateKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def set_pubkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        ssl.o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def get_privkey(self):
        size = ssl.i2d_ECPrivateKey(self.k, 0)
        mb_pri = ctypes.create_string_buffer(size)
        ssl.i2d_ECPrivateKey(self.k, ctypes.byref(ctypes.pointer(mb_pri)))
        return mb_pri.raw

    def get_pubkey(self):
        size = ssl.i2o_ECPublicKey(self.k, 0)
        mb = ctypes.create_string_buffer(size)
        ssl.i2o_ECPublicKey(self.k, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw

    def sign(self, hash):
        sig_size = ssl.ECDSA_size(self.k)
        mb_sig = ctypes.create_string_buffer(sig_size)
        sig_size0 = ctypes.c_uint32()
        assert 1 == ssl.ECDSA_sign(0, hash, len(hash), mb_sig, ctypes.byref(sig_size0), self.k)
        return mb_sig.raw[:sig_size0.value]

    def verify(self, hash, sig):
        return ssl.ECDSA_verify(0, hash, len(hash), sig, len(sig), self.k)

    def set_compressed(self, compressed):
        if compressed:
            form = self.POINT_CONVERSION_COMPRESSED
        else:
            form = self.POINT_CONVERSION_UNCOMPRESSED
        ssl.EC_KEY_set_conv_form(self.k, form)

    def get_secret(self):
        bn = ssl.EC_KEY_get0_private_key(self.k)
        mb = ctypes.create_string_buffer(32)
        ssl.BN_bn2bin(bn, mb)
        return mb.raw

if __name__ == '__main__':
    # ethalone keys
    ec_secret = '' + \
        'a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e'
    ec_private = '308201130201010420' + \
        'a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e' + \
        'a081a53081a2020101302c06072a8648ce3d0101022100' + \
        'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f' + \
        '300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2d' + \
        'ce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a6' + \
        '8554199c47d08ffb10d4b8022100' + \
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141' + \
        '020101a14403420004' + \
        '0791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a' + \
        'a762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90'

    k = KEY()

