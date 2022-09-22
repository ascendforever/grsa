



cimport cython
from cpython cimport int as PyInt

cdef cython.ushort DEFAULT_EXPONENT = 65537

cdef bytes generate_random_bits(const cython.ushort nbits)
cdef PyInt generate_random_int(const cython.ushort nbits)
cdef PyInt generate_random_odd_int(const cython.ushort nbits)

cdef cython.uchar get_primality_testing_rounds(const cython.ushort bitsize) nogil
cdef PyInt randint(PyInt maxvalue, cython.ushort bit_size)
cdef cython.bint miller_rabin_primality_testing(PyInt n, PyInt k)
cdef cython.bint is_prime(PyInt number)
cdef PyInt get_prime(cython.ushort nbits)

cdef tuple find_p_q(cython.ushort nbits)
cdef tuple extended_gcd(PyInt a, PyInt b)
cdef object inverse(PyInt x, PyInt n)
cdef tuple calculate_keys_custom_exponent(PyInt p, PyInt q, cython.uint exponent)

cpdef tuple generate_keys(const cython.ushort nbits, cython.uint exponent=*)




cdef cython.uint gcd(PyInt p, PyInt q)

cdef cython.bint relatively_prime(PyInt p, PyInt q)

cdef PyInt encrypt_int(PyInt message, PyInt ekey, PyInt n)


cdef PyInt decrypt_int(PyInt cyphertext, PyInt dkey, PyInt n)



cdef bytes _pad_for_encryption(bytes message, const cython.uint target_length)
cdef bytes _pad_for_signing(bytes message, const cython.uint target_length)
cdef str _find_method_hash(bytes clearsig)
cpdef bytes compute_hash(object message, str method_name)






cdef cython.uint DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS = 1_000_000_000

cdef class AbstractKey:
    cdef readonly PyInt n
    cdef readonly PyInt e
    cdef readonly cython.uint n_size
    cdef readonly PyInt blindfac
    cdef readonly PyInt blindfac_inverse
    cdef readonly object mutex
    cpdef tuple blind(self, PyInt message, const cython.uint blind_factor_generation_attempts)
    cpdef PyInt unblind(self, PyInt blinded, PyInt blindfac_inverse)
    cpdef PyInt _initial_blinding_factor(self, const cython.uint blind_factor_generation_attempts)
    cpdef tuple _update_blinding_factor(self, const cython.uint blind_factor_generation_attempts)

cdef class PublicKey(AbstractKey):
    cpdef PyInt encrypt_int(self, bytes message)
    cpdef bytes encrypt(self, bytes message)
    cpdef object verify_optimized(self, bytes signature, bytes cleartext)
    cpdef object verify(self, bytes message, bytes signature, str hash_method=*)
    cpdef str verify_unknown_method(self, bytes message, bytes signature)

cdef class PrivateKey(AbstractKey):
    cdef readonly PyInt d
    cdef readonly PyInt p
    cdef readonly PyInt q
    cdef readonly PyInt exp1
    cdef readonly PyInt exp2
    cdef readonly PyInt coef
    cpdef PyInt blinded_decrypt(self, PyInt encrypted, cython.uint blind_factor_generation_attempts=*)
    cpdef PyInt blinded_encrypt(self, PyInt message, cython.uint blind_factor_generation_attempts=*)
    cpdef bytes decrypt(self, bytes crypto, cython.uint blind_factor_generation_attempts=*)
    cpdef bytes sign_hash_optimized(self, bytes cleartext, cython.uint blind_factor_generation_attempts=*)
    cpdef bytes sign_hash(self, bytes hash_value, str hash_method=*, cython.uint blind_factor_generation_attempts=*)
    cpdef bytes sign(self, bytes message, str hash_method=*, cython.uint blind_factor_generation_attempts=*)


cpdef tuple generate(const cython.ushort nbits, cython.uint exponent=*)



