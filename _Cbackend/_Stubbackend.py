from __future__ import annotations

__all__ = [
    'NotRelativePrimeError',
    'DEFAULT_EXPONENT',
    # 'read_random_bits',
    # 'read_random_int',
    # 'read_random_odd_int',
    # 'get_primality_testing_rounds',
    # 'randint',
    # 'miller_rabin_primality_testing',
    # 'is_prime',
    # 'getprime',
    # 'find_p_q',
    # 'extended_gcd',
    # 'inverse',
    # 'calculate_keys_custom_exponent',
    'gen_keys',
    # 'gcd',
    # 'are_relatively_prime',
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


class NotRelativePrimeError(ValueError):
    def __init__(self, a: int, b: int, d: int, msg: str = '') -> None: ...
DEFAULT_EXPONENT = 65537

# # noinspection PyUnusedLocal
# def read_random_bits(nbits:int) -> bytes:
#     """[Created 12/10/21]"""
# # noinspection PyUnusedLocal
# def read_random_int(nbits:int) -> int:
#     """[Created 12/10/21]"""
# # noinspection PyUnusedLocal
# def read_random_odd_int(nbits:int) -> int:
#     """[Created 12/10/21]"""

# # noinspection PyUnusedLocal
# def get_primality_testing_rounds(number:int) -> int:
#     """[Created 12/10/21]"""
# # noinspection PyUnusedLocal
# def randint(maxvalue:int) -> int:
#     """[Created 12/10/21]"""
# # noinspection PyUnusedLocal
# def miller_rabin_primality_testing(n:int, k:int) -> bool:
#     """[Created 12/10/21]"""
# # noinspection PyUnusedLocal
# def is_prime(number:int) -> bool:
#     """[Created 12/10/21]"""
# # noinspection PyUnusedLocal
# def getprime(nbits:int) -> int:
#     """[Created 12/10/21]"""
# # noinspection PyUnusedLocal

# # noinspection PyUnusedLocal
# def find_p_q(nbits:int) -> tuple[int, int]:
#     """[Created 12/10/21]"""
# # noinspection PyUnusedLocal
# def extended_gcd(a:int, b:int) -> tuple[int, int, int]:
#     """[Created 12/10/21]"""
# # noinspection PyUnusedLocal
# def inverse(x:int, n:int) -> int:
#     """[Created 12/10/21]"""
# # noinspection PyUnusedLocal
# def calculate_keys_custom_exponent(p:int, q:int, exponent:int) -> tuple[int, int]:
#     """[Created 12/10/21]"""
# # noinspection PyUnusedLocal
def gen_keys(nbits:int, exponent:int=DEFAULT_EXPONENT) -> tuple[int, int, int, int]:
    """[Created 12/10/21]"""
# noinspection PyUnusedLocal

# # noinspection PyUnusedLocal
# def gcd(p:int, q:int) -> int:
#     ...
# # noinspection PyUnusedLocal
# def are_relatively_prime(a:int, b:int) -> int:
#     ...

# # noinspection PyUnusedLocal
# def encrypt_int(message:int, ekey:int, n:int) -> int:
#     """Encrypts a message using encryption key 'ekey', working modulo n"""
# # noinspection PyUnusedLocal
# def decrypt_int(cyphertext:int, dkey:int, n:int) -> int:
#     """Decrypts a cypher text using the decryption key 'dkey', working modulo n"""



class CryptoError(Exception): pass
class DecryptionError(CryptoError): pass
class VerificationError(CryptoError): pass

# def _pad_for_encryption(message:bytes, target_length:int) -> bytes:
#     """Pads the message for encryption, returning the padded message"""
# def _pad_for_signing(message:bytes, target_length:int) -> bytes:
#     """Pads the message for signing, returning the padded message
#     The padding is always a repetition of FF bytes"""

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

# def _find_method_hash(clearsig:bytes) -> str:
#     """Finds the hash method.
#     :param clearsig: full padded ASN1 and hash.
#     :return: the used hash method.
#     :raise VerificationFailed: when the hash method cannot be found
#     """

def yield_fixedblocks(infile:t.BinaryIO, blocksize:int) -> abcs.Iterator[bytes]:
    """Yields each block of `blocksize` bytes in the input file."""

def compute_hash(message:bytes|t.BinaryIO, method_name:str) -> bytes:
    """Returns the message digest"""












DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS = 1_000_000_000


class AbstractKey:
    __slots__ = ('n', 'n_size', 'e', 'blindfac', 'blindfac_inverse', 'mutex')
    def __init__(self, n: int, e: int) -> None:
        self.n:int = n
        self.n_size:int = ...
        self.e:int = e
        self.blindfac:int = -1
        self.blindfac_inverse:int = self.blindfac
        self.mutex:threading.Lock = threading.Lock()
    @t.final
    def __ne__(self, other) -> bool:
        return not (self == other)
    @t.final
    def blind(self, message:int, blind_factor_generation_attempts:int) -> tuple[int,int]:
        """Blinds the message
        message = unblind(decrypt(blind(encrypt(message))).
        https://en.wikipedia.org/wiki/Blinding_%28cryptography%29
        :return tuple(blinded_message, inverse_used_blinding_factor)
        """
    @t.final
    def unblind(self, blinded:int, blindfac_inverse:int) -> int:
        return (blindfac_inverse * blinded) % self.n
    # noinspection PyTypeChecker
    @t.final
    def _initial_blinding_factor(self, blind_factor_generation_attempts:int) -> int:
        ...
    def _update_blinding_factor(self, blind_factor_generation_attempts:int) -> tuple[int, int]:
        """Blinding factor computation is expensive so the blinding factor is generated once and updated according to section 9 of 'A Timing Attack against RSA with the Chinese Remainder Theorem': https://tls.mbed.org/public/WSchindler-RSA_Timing_Attack.pdf
        :return: new blinding factor and its inverse.
        """


class PublicKey(AbstractKey):
    """Represents a public RSA key"""
    __slots__ = ()
    def __getitem__(self, key: str) -> int:
        return getattr(self, key)
    def __repr__(self) -> str:
        return f'PublicKey({self.n}, {self.e})'
    def __getstate__(self) -> tuple[int, int]:
        return self.n, self.e
    def __setstate__(self, state:tuple[int, int]) -> None:
        self.n, self.e = state
        AbstractKey.__init__(self, self.n, self.e)
    def __eq__(self, other:t.Any) -> bool:
        ...
    def __hash__(self) -> int:
        return hash((self.n, self.e))
    def encrypt_int(self, message:bytes) -> int:
        """Faster than standard encrypt if data is already an integer"""
    def encrypt(self, message:bytes) -> bytes:
        """Encrypts using PKCS#1 v1.5
        `message` must be 11 bytes smaller than key size"""
    def verify_optimized(self, signature:bytes, cleartext:bytes) -> None:
        """When cleartext has been pulled out of message already this is more efficient
        raises VerificationError when the signature doesn't match the message"""
    def verify(self, message:bytes, signature:bytes, hash_method:str='SHA-512') -> None:
        """raises VerificationError when the signature doesn't match the message"""
    def verify_unknown_method(self, message:bytes, signature:bytes) -> str:
        """Slower than standard verify as the hash method needs to be determined
        raises VerificationError when the signature doesn't match the message
        returns the name of the used hash"""


class PrivateKey(AbstractKey):
    """Represents a private RSA key"""
    __slots__ = ('d', 'p', 'q', 'exp1', 'exp2', 'coef')
    def __init__(self, n: int, e: int, d: int, p: int, q: int) -> None:
        super().__init__(n, e)
        self.d:int = d
        self.p:int = p
        self.q:int = q
        self.exp1:int = int(d % (p - 1))
        self.exp2:int = int(d % (q - 1))
        self.coef:int = ...
    def __getitem__(self, key: str) -> int:
        return getattr(self, key)
    def __repr__(self) -> str:
        return f'PrivateKey({self.n}, {self.e}, {self.d}, {self.p}, {self.q})'
    def __getstate__(self) -> tuple[int, int, int, int, int, int, int, int]:
        return self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef
    def __setstate__(self, state:tuple[int, int, int, int, int, int, int, int]) -> None:
        self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef = state
        AbstractKey.__init__(self, self.n, self.e)
    def __eq__(self, other:PrivateKey) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self.n==other.n and self.e==other.e and self.d==other.d and self.p==other.p and self.q==other.q and
                self.exp1==other.exp1 and self.exp2==other.exp2 and self.coef==other.coef)
    def __hash__(self) -> int:
        return hash((self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef))
    def blinded_decrypt(self, encrypted: int, blind_factor_generation_attempts:int=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS) -> int:
        """Decrypts the message using blinding to prevent side-channel attack"""
        # Blinding and un-blinding should be using the same factor
    def blinded_encrypt(self, message: int, blind_factor_generation_attempts:int=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS) -> int:
        """Encrypts the message using blinding to prevent side-channel attacks"""
    def decrypt(self, crypto:bytes, blind_factor_generation_attempts:int=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS) -> bytes:
        """Decrypts the given message using PKCS#1 v1.5
        raises `DecryptionError` on failure (never show the traceback!"""
    def sign_hash_optimized(self, cleartext:bytes, blind_factor_generation_attempts:int=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS) -> bytes:
        """Signs a precomputed hash with the private key
        `cleartext`: A precomputed hash to sign + asn1code of hash method
        raises OverflowError if the private key is too small to contain the requested hash"""
    def sign_hash(self, hash_value:bytes, hash_method:str='SHA-512', blind_factor_generation_attempts:int=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS) -> bytes:
        """Signs a precomputed hash with the private key
        `hash_value`: A precomputed hash to sign (ignores message).
        `hash_method`: the hash method used on the message. ['MD5', 'SHA-1', 'SHA-224', SHA-256', 'SHA-384', 'SHA-512']
        raises OverflowError: if the private key is too small to contain the requested hash
        raises ValueError: if `hash_method` is invalid"""
    def sign(self, message:bytes, hash_method:str='SHA-512', blind_factor_generation_attempts:int=DEFAULT_BLIND_FACTOR_MAX_ATTEMPTS) -> bytes:
        """Use more optimal sign methods if hash is already computed and/or asn1code is known"""


def generate(nbits:int, accurate:bool=True, exponent:int=DEFAULT_EXPONENT) -> tuple[PublicKey,PrivateKey]:
    ...
