
# // no // # cython: linetrace=True
# // no // # distutils: define_macros=CYTHON_TRACE_NOGIL=1

__all__ = [
    'NotRelativePrimeError',
    # 'DEFAULT_EXPONENT',
    # 'generate_random_bits',
    # 'generate_random_int',
    # 'generate_random_odd_int',
    # 'get_primality_testing_rounds',
    # 'randint',
    # 'miller_rabin_primality_testing',
    # 'is_prime',
    # 'get_prime',
    # 'find_p_q',
    # 'extended_gcd',
    # 'inverse',
    # 'calculate_keys_custom_exponent',
    'generate_keys',
    # 'gcd',
    # 'relatively_prime',
    # 'encrypt_int',
    # 'decrypt_int',

    'CryptoError',
    'DecryptionError',
    'VerificationError',
    # '_pad_for_encryption',
    # '_pad_for_signing',
    'HASH_ASN1',
    'HASH_METHODS',
    # '_find_method_hash',
    'yield_fixedblocks',
    'compute_hash',

    'AbstractKey',
    'PublicKey',
    'PrivateKey',
    'generate'
]

from grsa.__common import *
from cpython cimport int as PyInt

# cimport cython
# from cpython cimport int as PyInt

# from cpython cimport function

# cpdef test():
#     print(PyInt)
#     print(PyInt is builtins.int)
# test()

class NotRelativePrimeError(ValueError):
    def __init__(self, PyInt a, PyInt b, PyInt d, str msg='') -> None:
        super().__init__(msg or f"{a} and {b} are not relatively prime, divider={d}")
        self.a = a
        self.b = b
        self.d = d

cdef cython.uint DEFAULT_EXPONENT = 65537
cdef object ALGORITHM = os.urandom # secrets.token_bytes # os.urandom

cdef inline bytes generate_random_bits(const cython.ushort nbits):
    cdef cython.ushort nbytes
    cdef cython.uchar rbits
    nbytes, rbits = divmod(nbits, 8)
    cdef bytes randomdata = ALGORITHM(nbytes)
    # add remaining random bits
    cdef cython.uchar randomvalue # cython.uchar
    if rbits > 0:
        randomvalue = ALGORITHM(1)[0] >> (8-rbits) # ORD IS SLOWER # ord(ALGORITHM(1))
        randomdata = struct.pack("B", randomvalue) + randomdata # yes struct.pack is better than using bytes((randomvalue,))
    return randomdata
cdef inline PyInt generate_random_int(const cython.ushort nbits):
    cdef bytes randomdata = generate_random_bits(nbits)
    cdef PyInt value = PyInt.from_bytes(randomdata, 'big', signed=False)
    # This PyInt conversion is necessary - yes it is disgusting
    value |= PyInt(1) << (nbits - 1) # make sure that the number is large enough
    return value
cdef inline PyInt generate_random_odd_int(const cython.ushort nbits):
    cdef PyInt value = generate_random_int(nbits)
    # assert value | 1 == value | PyInt(1) # test works
    return value | 1 # Make sure it's odd

cdef inline cython.uchar get_primality_testing_rounds(const cython.ushort bitsize) nogil:
    if bitsize >= 1536: return 3
    if bitsize >= 1024: return 4
    if bitsize >= 512: return 7
    # default for very low bit sizes
    return 10
cdef inline PyInt randint(PyInt maxvalue, cython.ushort bit_size): # cython.uint
    cdef cython.ushort tries = 0
    cdef PyInt value
    cdef object __generate_random_int = generate_random_int
    while True:
        for _ in range(10):
            value = __generate_random_int(bit_size)
            if value <= maxvalue:
                break
            tries += 1
        else:
            if tries!=0:
                bit_size -= 1
            continue
        break
    return value
cdef inline cython.bint miller_rabin_primality_testing(PyInt n, PyInt k):
    # prevent potential infinite loop
    if n < 2: return False
    # decompose (n - 1) to write it as (2 ** r) * d
    # while d is even divide it by 2 and raise the exponent.
    cdef PyInt d = n - 1 # 204 byte integer
    cdef cython.uchar r = 0
    while not (d & 1):
        r += 1
        d >>= 1
    cdef cython.uchar r_minus_1 = r - 1
    cdef PyInt n_minus_1 = n - 1
    cdef PyInt n_minus_3 = n - 3
    cdef cython.ushort n_minus_3_bit_size = n_minus_3.bit_length()
    # test k witnesses
    cdef PyInt a, x
    for _ in range(k):
        # generate random integer a in [2, n-2]
        a = randint(n_minus_3, n_minus_3_bit_size) + 1 # 180 / 240 byte integers
        x = pow(a, d, n) # 180 / 240 byte integers
        if x == 1 or x == n_minus_1:
            continue
        for _ in range(r_minus_1):
            x = pow(x, 2, n)
            if x == 1: # n is composite.
                return False
            if x == n_minus_1:
                break
        else: # n is composite.
            return False
    return True
cdef inline cython.bint is_prime(PyInt number):
    if number < 10: # small number optimization
        return number==2 or number==3 or number==5 or number==7
    # assert number & 1 == number & PyInt(1) # test works
    if not (number & 1): # even check
        return False
    cdef cython.uchar k = get_primality_testing_rounds(number.bit_length())
    return miller_rabin_primality_testing(number, k + 1) # k is minimum so + 1
cdef inline cython.bint is_prime_fast(PyInt n): # unpredictable speed boost/loss - likely dont use it
    if n < 10: # small number optimization
        return n==2 or n==3 or n==5 or n==7
    if not (n & 1): # check for even numbers.
        return False
    if n < 2:
        return False
    cdef cython.ushort bitsize = n.bit_length()
    cdef cython.uchar k
    if bitsize >= 1536: k = 4
    if bitsize >= 1024: k = 5
    if bitsize >= 512: k = 8
    k = 11
    cdef PyInt d = n - 1 # 204 byte integer
    cdef cython.uchar r = 0
    while not (d & 1):
        r += 1
        d >>= 1
    cdef cython.uchar r_minus_1 = r - 1
    cdef PyInt n_minus_1 = n - 1
    cdef PyInt n_minus_3 = n - 3
    cdef cython.ushort n_minus_3_bit_size = n_minus_3.bit_length()
    cdef PyInt a, x
    for _ in range(k):
        a = randint(n_minus_3, n_minus_3_bit_size) + 1 # 180 / 240 byte integers
        x = pow(a, d, n) # 180 / 240 byte integers
        if x == 1 or x == n_minus_1:
            continue
        for _ in range(r_minus_1):
            x = pow(x, 2, n)
            if x == 1:
                return False
            if x == n_minus_1:
                break
        else:
            return False
    return True

cdef inline PyInt get_prime(cython.ushort nbits):
    # assert nbits > 3 # this is checked in find_p_q
    cdef PyInt integer
    while True:
        integer = generate_random_odd_int(nbits)
        if is_prime(integer):
            return integer

cdef inline tuple find_p_q(cython.ushort nbits):
    # """[Created 12/10/21]"""
    cdef cython.ushort total_bits = nbits * 2
    # make sure that p and q aren't too close or the factoring programs can factor n.
    cdef cython.ushort shift = nbits // 16
    cdef cython.ushort pbits = nbits + shift
    cdef cython.ushort qbits = nbits - shift
    # choose the two initial primes
    assert pbits > 3 and qbits > 3
    cdef PyInt p = get_prime(pbits)
    cdef PyInt q = get_prime(qbits)
    __bit_length = int.bit_length
    while True:
        if p!=q and __bit_length(p * q)==total_bits:
            break
        q = get_prime(qbits)
        if p!=q and __bit_length(p * q)==total_bits:
            break
        p = get_prime(pbits)
    # http://www.di-mgt.com.au/rsa_alg.html#crt
    return (p,q) if p > q else (q,p)
cdef inline tuple extended_gcd(PyInt a, PyInt b): # (cython.uint,cython.uint,cython.uint)
    # """[Created 12/10/21]"""
    cdef PyInt x = 0
    cdef PyInt y = 1
    cdef PyInt lx = 1
    cdef PyInt ly = 0
    cdef PyInt oa = a  # save original a/b
    cdef PyInt ob = b
    cdef PyInt q
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0: lx += ob
    if ly < 0: ly += oa
    return a, lx, ly # only positive values
cdef inline object inverse(PyInt x, PyInt n):
    # """[Created 12/10/21]"""
    cdef PyInt divider, inv
    divider, inv, _ = extended_gcd(x, n)
    if divider != 1:
        raise NotRelativePrimeError(x, n, divider)
    return inv
# needs to return a pyobject because this raises errors (?)
cdef inline tuple calculate_keys_custom_exponent(PyInt p, PyInt q, cython.uint exponent):
    # """[Created 12/10/21]"""
    cdef PyInt phi_n = (p - 1) * (q - 1)
    cdef PyInt d
    try:
        d = inverse(exponent, phi_n)
    except NotRelativePrimeError as ex:
        raise NotRelativePrimeError(exponent, phi_n, ex.d)
    if (exponent * d) % phi_n != 1:
        raise ValueError # no message b/c we will always except the error
    return exponent, d

cpdef tuple generate_keys(const cython.ushort nbits, cython.uint exponent=DEFAULT_EXPONENT):
    # """[Created 12/10/21]"""
    cdef cython.uint nbits_floordiv2 = nbits // 2
    cdef PyInt p,q,e,d
    while True:
        p,q = find_p_q(nbits_floordiv2)
        try:
            e,d = calculate_keys_custom_exponent(p, q, exponent=exponent)
        except ValueError:
            pass
        else:
            break
    return p, q, e, d




cdef inline cython.uint gcd(PyInt p, PyInt q):
    while q != 0:
        p, q = q, p % q
    return p

cdef inline cython.bint relatively_prime(PyInt p, PyInt q):
    # return gcd(a, b) == 1
    while q != 0:
        p, q = q, p % q
    return p == 1

cdef inline PyInt encrypt_int(PyInt message, PyInt ekey, PyInt n):
    if message < 0: raise ValueError('Only non-negative numbers are supported')
    if message > n: raise OverflowError(f"The message {message} is too long for n={n}")
    return pow(message, ekey, n)


cdef inline PyInt decrypt_int(PyInt cyphertext, PyInt dkey, PyInt n):
    return pow(cyphertext, dkey, n)




class CryptoError(Exception): pass
class DecryptionError(CryptoError): pass
class VerificationError(CryptoError): pass

cdef inline bytes _pad_for_encryption(bytes message, const cython.uint target_length):
    cdef cython.uint max_msglength = target_length - 11
    cdef cython.uint msglength = len(message)
    if msglength > max_msglength:
        raise OverflowError(f'{msglength} bytes needed for message, but there is only space for {max_msglength}')
    cdef bytes padding = b''
    cdef cython.uint padding_length = target_length - msglength - 3
    # not enough padding, we keep adding data until we have enough
    cdef cython.uint needed_bytes
    cdef bytes new_padding
    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)
        # read more bytes than needed, to increase chances of getting enough
        new_padding = os.urandom(needed_bytes+5).replace(b'\x00', b'')
        padding = padding + new_padding[:needed_bytes]
    assert len(padding) == padding_length # may want to keep this
    return b''.join([b'\x00\x02', padding, b'\x00', message])
cdef inline bytes _pad_for_signing(bytes message, const cython.uint target_length):
    cdef cython.uint max_msglength = target_length - 11
    cdef cython.uint msglength = len(message)
    if msglength > max_msglength:
        raise OverflowError(f'{msglength} bytes needed for message, but there is only space for {max_msglength}')
    cdef cython.uint padding_length = target_length - msglength - 3
    return b''.join([b'\x00\x01', padding_length * b'\xff', b'\x00', message])

HASH_ASN1 = {
    'MD5': b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
    'SHA-1': b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
    'SHA-224': b'\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c',
    'SHA-256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    'SHA-384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    'SHA-512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}
HASH_METHODS = {
    'MD5': hashlib.md5,
    'SHA-1': hashlib.sha1,
    'SHA-224': hashlib.sha224,
    'SHA-256': hashlib.sha256,
    'SHA-384': hashlib.sha384,
    'SHA-512': hashlib.sha512,
}

cdef inline str _find_method_hash(bytes clearsig):
    for hashname, asn1code in HASH_ASN1.items():
        if asn1code in clearsig:
            return hashname
    raise VerificationError('Verification failed')

#                     file:t.BinaryIO
def yield_fixedblocks(object file, const cython.ushort blocksize):
    cdef object __read = file.read
    cdef bytes block
    cdef cython.ushort l
    while True:
        block = __read(blocksize)
        l = len(block)
        if l == 0:
            break
        yield block
        if l < blocksize:
            break

#                                message:t.Union[bytes, t.BinaryIO]
cpdef bytes compute_hash(object message, str method_name):
    cdef object hsh = HASH_METHODS[method_name]()
    cdef object __hsh_update = hsh.update
    cdef bytes block
    if isinstance(message, bytes):
        __hsh_update(message)
    else:
        assert hasattr(message, 'read') and hasattr(message.read, '__call__')
        for block in yield_fixedblocks(message, 1024):
            __hsh_update(block)
    return hsh.digest()










cdef cython.uint DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS = 1_000_000_000

cdef class AbstractKey:
    def __init__(self, PyInt n, PyInt e):
        self.n = n
        self.n_size = upy_size(n)
        self.e = e
        # placeholder values; will be set in blind()
        self.blindfac = self.blindfac_inverse = -1
        self.mutex = threading.Lock()
    def __ne__(self, object other) -> bool:
        return not (self==other)
    cpdef tuple blind(self, PyInt message, const cython.uint blind_factor_generation_attempts):
        cdef PyInt blindfac, blindfac_inverse
        blindfac, blindfac_inverse = self._update_blinding_factor(blind_factor_generation_attempts)
        cdef PyInt blinded = (message * pow(blindfac, self.e, self.n)) % self.n
        return blinded, blindfac_inverse
    cpdef PyInt unblind(self, PyInt blinded, PyInt blindfac_inverse):
        return (blindfac_inverse * blinded) % self.n
    cpdef PyInt _initial_blinding_factor(self, const cython.uint blind_factor_generation_attempts):
        cdef PyInt blind_r
        cdef PyInt n = self.n
        cdef PyInt n_minus_1 = n - 1
        cdef cython.ushort n_minus_1_bit_size = n_minus_1.bit_length()
        for _ in range(blind_factor_generation_attempts): # used to be `range(1000):` # This may be a bad idea to not hard code it
            blind_r = randint(n_minus_1, n_minus_1_bit_size)
            if relatively_prime(n, blind_r):
                return blind_r
        raise RuntimeError(f'Unable to initialize blinding factor; Try increasing `blind_factor_generation_attempts` past {blind_factor_generation_attempts:,}')
    cpdef tuple _update_blinding_factor(self, const cython.uint blind_factor_generation_attempts):
        with self.mutex:
            if self.blindfac < 0:
                # initialize blinding factor
                self.blindfac = self._initial_blinding_factor(blind_factor_generation_attempts)
                self.blindfac_inverse = inverse(self.blindfac, self.n)
            else:
                # reuse blinding factor
                self.blindfac = pow(self.blindfac, 2, self.n)
                self.blindfac_inverse = pow(self.blindfac_inverse, 2, self.n)
            return self.blindfac, self.blindfac_inverse


cdef class PublicKey(AbstractKey):
    """Represents a public RSA key"""
    def __repr__(self) -> str:
        return f'PublicKey({self.n}, {self.e})'
    def __getstate__(self) -> tuple[PyInt, PyInt]:
        return self.n, self.e
    def __setstate__(self, tuple state) -> None:
        self.n, self.e = state
        super().__init__(self, self.n, self.e)
    def __eq__(self, object other) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.n == other.n and self.e == other.e
    def __hash__(self) -> int:
        return hash((self.n, self.e))
    cpdef PyInt encrypt_int(self, bytes message):
        cdef bytes padded = _pad_for_encryption(message, self.n_size)
        cdef PyInt payload = PyInt.from_bytes(padded, 'big', signed=False) # pyint
        cdef PyInt encrypted_int = encrypt_int(payload, self.e, self.n) # pyint
        return encrypted_int
    cpdef bytes encrypt(self, bytes message):
        cdef object encrypted_int = self.encrypt_int(message) # pyint
        return upy_to_bytes(encrypted_int)
    cpdef object verify_optimized(self, bytes signature, bytes cleartext): # return None
        cdef cython.uint keylength = self.n_size
        cdef PyInt encrypted = int.from_bytes(signature, 'big', signed=False) # pyint
        cdef PyInt decrypted = decrypt_int(encrypted, self.e, self.n) # pyint
        cdef bytes clearsig = PyInt.to_bytes(decrypted, keylength, 'big', signed=False)
        # ---------------------------
        # ---------------------------
        cdef bytes expected = _pad_for_signing(cleartext, keylength)
        if len(signature) != keylength:
            raise VerificationError('Verification failed')
        if expected != clearsig:
            raise VerificationError('Verification failed')
        return None
    cpdef object verify(self, bytes message, bytes signature, str hash_method='SHA-512'): # return None
        cdef bytes message_hash = compute_hash(message, hash_method)
        cdef bytes cleartext = HASH_ASN1[hash_method] + message_hash
        return self.verify_optimized(signature, cleartext)
    cpdef str verify_unknown_method(self, bytes message, bytes signature):
        cdef cython.uint keylength = self.n_size
        cdef PyInt encrypted = PyInt.from_bytes(signature, 'big', signed=False) # pyint
        cdef PyInt decrypted = decrypt_int(encrypted, self.e, self.n) # pyint
        cdef bytes clearsig = PyInt.to_bytes(decrypted, keylength, 'big', signed=False)
        # ---------------------------
        hash_method = _find_method_hash(clearsig)
        cdef bytes message_hash = compute_hash(message, hash_method)
        cdef bytes cleartext = HASH_ASN1[hash_method] + message_hash
        # ---------------------------
        cdef bytes expected = _pad_for_signing(cleartext, keylength)
        if len(signature) != keylength:
            raise VerificationError('Verification failed')
        if expected != clearsig:
            raise VerificationError('Verification failed')
        return None



cdef class PrivateKey(AbstractKey):
    """Represents a private RSA key"""
    def __init__(self, PyInt n, PyInt e, PyInt d, PyInt p, PyInt q) -> None:
        super().__init__(n, e)
        self.d = d
        self.p = p
        self.q = q
        # Calculate exponents and coefficient.
        self.exp1 = d % (p - 1)
        self.exp2 = d % (q - 1)
        self.coef = inverse(q, p)
    def __getitem__(self, str key) -> int:
        return getattr(self, key)
    def __repr__(self) -> str:
        return f'PrivateKey({self.n}, {self.e}, {self.d}, {self.p}, {self.q})'
    def __getstate__(self) -> tuple[int, int, int, int, int, int, int, int]:
        return self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef
    def __setstate__(self, state:tuple[int, int, int, int, int, int, int, int]) -> None:
        self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef = state
        super().__init__(self, self.n, self.e)
    def __eq__(self, object other) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self.n==other.n and self.e==other.e and self.d==other.d and self.p==other.p and self.q==other.q and
                self.exp1==other.exp1 and self.exp2==other.exp2 and self.coef==other.coef)
    def __hash__(self) -> int:
        return hash((self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef))
    cpdef PyInt blinded_decrypt(self, PyInt encrypted, cython.uint blind_factor_generation_attempts=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS): # uint
        # should used the same factor
        cdef PyInt blinded, blindfac_inverse
        blinded, blindfac_inverse = self.blind(encrypted, blind_factor_generation_attempts=blind_factor_generation_attempts)
        cdef PyInt decrypted = decrypt_int(blinded, self.d, self.n)
        return self.unblind(decrypted, blindfac_inverse)
    cpdef PyInt blinded_encrypt(self, PyInt message, cython.uint blind_factor_generation_attempts=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS): # uint
        cdef PyInt blinded, blindfac_inverse
        blinded, blindfac_inverse = self.blind(message, blind_factor_generation_attempts=blind_factor_generation_attempts)
        cdef PyInt encrypted = encrypt_int(blinded, self.d, self.n)
        return self.unblind(encrypted, blindfac_inverse)
    cpdef bytes decrypt(self, bytes crypto, cython.uint blind_factor_generation_attempts=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS):
        """Decrypts the given message using PKCS#1 v1.5
        raises `DecryptionError` on failure (never show the traceback!"""
        cdef PyInt encrypted = int.from_bytes(crypto, 'big', signed=False)
        cdef cython.uint blocksize = self.n_size
        cdef object decrypted = self.blinded_decrypt(encrypted, blind_factor_generation_attempts=blind_factor_generation_attempts) # pyint
        cdef bytes cleartext = int.to_bytes(decrypted, blocksize, 'big', signed=False)
        # Fix CVE-2020-13757 by detecting leading zeros, which are invisible when converted to in
        if len(crypto) > blocksize:
            raise DecryptionError('Decryption failed')
        if not hmac.compare_digest(cleartext[:2], b'\x00\x02'): # if we can't find cleartext marker we failed
            raise DecryptionError('Decryption failed')
        # Separator between padding and message
        cdef cython.uint sep_idx = cleartext.find(b'\x00', 2)
        # sep_idx is the index of \x00 which separates padding and message
        # padding should be >=8bytes, so the separator should be at the earliest index 10 (\x00\x02 precedes it)
        if sep_idx < 10: # sep_idx bad
            raise DecryptionError('Decryption failed')
        return cleartext[sep_idx + 1:]
    cpdef bytes sign_hash_optimized(self, bytes cleartext, cython.uint blind_factor_generation_attempts=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS):
        cdef cython.uint keylength = self.n_size
        cdef bytes padded = _pad_for_signing(cleartext, keylength)
        cdef object payload = int.from_bytes(padded, 'big', signed=False) # pyint
        cdef object encrypted = self.blinded_encrypt(payload, blind_factor_generation_attempts=blind_factor_generation_attempts) # pyint
        cdef bytes block = int.to_bytes(encrypted, keylength, 'big', signed=False)
        return block
    cpdef bytes sign_hash(self, bytes hash_value, str hash_method='SHA-512', cython.uint blind_factor_generation_attempts=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS):
        cdef bytes cleartext = HASH_ASN1[hash_method] + hash_value
        return self.sign_hash_optimized(cleartext, blind_factor_generation_attempts=blind_factor_generation_attempts)
    cpdef bytes sign(self, bytes message, str hash_method='SHA-512', cython.uint blind_factor_generation_attempts=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS):
        cdef bytes cleartext = HASH_ASN1[hash_method] + compute_hash(data, HASH_METHODS[hash_method])
        return self.sign_hash_optimized(cleartext, blind_factor_generation_attempts=blind_factor_generation_attempts)


cpdef tuple generate(const cython.ushort nbits, cython.uint exponent=DEFAULT_EXPONENT):
    # """[Created 12/10/21]"""
    if nbits < 16:
        raise ValueError('Key too small')
    cdef PyInt p,q,e,d
    p, q, e, d = generate_keys(nbits, exponent=exponent)
    cdef PyInt n = p * q
    return (
        PublicKey(n, e),
        PrivateKey(n, e, d, p, q)
    )
