from __future__ import annotations

__all__ = [
    "_RSAKeyring",
    "PublicKeys",
    "PrivateKeys",
    'encrypt_and_sign',
    'encrypt_and_double_sign',
    'decrypt_and_verify',
    'decrypt_and_double_verify',
    'decrypt_and_verify_unknown_method',
    'decrypt_and_double_verify_unknown_method',
    'generate',
    'generate_layers',
    'Manager',
    'ManagerEncodedABC',
    'ManagerBase64',
    'ManagerBase64Standard',
    'ManagerBase85',
    'ManagerBase95',
    'ManagerBase94',
    'ManagerBase93',
    'ManagerBase92',
    'ManagerBase91',
    'ManagerCompressed',
    'ManagerEncodedCompressedABC',
    'ManagerBase64Compressed',
    'ManagerBase64StandardCompressed',
    'ManagerBase85Compressed',
    'ManagerBase95Compressed',
    'ManagerBase94Compressed',
    'ManagerBase93Compressed',
    'ManagerBase92Compressed',
    'ManagerBase91Compressed',
]

from .__common import *
from .__common import _Keyring

from . import _Cbackend as backend


nl = '\n'

DEFAULT_METHOD:str = 'SHA-512'

class _RSAKeyring(_Keyring[T], t.Generic[T], abcs.Reversible, abcs.Collection, metaclass=abc.ABCMeta):
    _type:t.Literal[backend.PublicKey,backend.PrivateKey] = ...
    def __init_subclass__(cls, **kwargs):
        if (typ:=cls._type) is not backend.PublicKey and typ is not backend.PrivateKey:
            raise TypeError('cls must have _type be rsa.PrivateKey or rsa.PublicKey')
    __slots__ = ()
    # __match_args__ = ('_keys',) # defined in parent
    @classmethod
    @abc.abstractmethod
    def from_packed(cls, data:bytes) -> _RSAKeyring[T]:
        """Compact encoded bytes version"""
    @abc.abstractmethod
    def packed(self) -> bytes:
        """Compact encoded bytes version"""
    @t.final
    def key_sizes(self) -> abcs.Generator[int, t.Any, None]:
        for key in self._keys: # type: backend.AbstractKey
            yield key.n_size
    @t.final
    def ns(self) -> abcs.Generator[int, t.Any, None]:
        for key in self._keys: # type: backend.AbstractKey
            yield key.n
    @t.final
    def es(self) -> abcs.Generator[int, t.Any, None]:
        for key in self._keys: # type: backend.AbstractKey
            yield key.e
    @t.final
    def mutexes(self) -> abcs.Generator[threading.Lock, t.Any, None]:
        for key in self._keys: # type: backend.AbstractKey
            yield key.mutex
    @abc.abstractmethod
    def encrypt_and_sign(self, data:bytes, OPPOSITE_KEY_HERE:_RSAKeyring, method:str=DEFAULT_METHOD) -> bytes:
        """Sign and then encrypt; Results in a single binary"""
    @abc.abstractmethod
    def encrypt_and_double_sign(self, data:bytes, OPPOSITE_KEY_HERE:_RSAKeyring, method:str=DEFAULT_METHOD) -> bytes:
        """Sign before and after encryption; Results in a single binary"""
    @abc.abstractmethod
    def decrypt_and_verify(self, data:bytes, OPPOSITE_KEY_HERE:_RSAKeyring, method:str=DEFAULT_METHOD) -> bytes:
        """Decrypt and then verify from a single binary"""
    @abc.abstractmethod
    def decrypt_and_double_verify(self, data:bytes, OPPOSITE_KEY_HERE:_RSAKeyring, method:str=DEFAULT_METHOD) -> bytes:
        """Verify before and after decryption"""
    @abc.abstractmethod
    def decrypt_and_verify_unknown_method(self, data:bytes, OPPOSITE_KEY_HERE:_RSAKeyring) -> bytes:
        """Decrypt and then verify from a single binary; Slower since the method of signature is unknown"""
    @abc.abstractmethod
    def decrypt_and_double_verify_unknown_method(self, data:bytes, OPPOSITE_KEY_HERE:_RSAKeyring) -> bytes:
        """Verify before and after decryption; Slower since the method of signature is unknown"""


class PublicKeys(_RSAKeyring[backend.PublicKey]):
    _type:t.Final = backend.PublicKey
    __slots__ = ('_cached__max_input_size','_cached__output_size')
    __match_args__ = _RSAKeyring.__match_args__ + ('max_input_size', 'output_size')
    def __init__(self, keys:tuple[rsa.PublicKey,...]): # noqa
        self._keys:t.Final[tuple[backend.PublicKey,...]] = keys
    @property
    @memorize_method_first
    def max_input_size(self) -> int:
        """Equivalent to the size of the first key -11"""
        return self._keys[0].n_size-11
    @property
    @memorize_method_first
    def output_size(self) -> int:
        """Equivalent to the size of the final key"""
        return self._keys[-1].n_size
    @classmethod
    def from_packed(cls, data:bytes) -> PublicKeys:
        return cls(tuple(itertools.starmap(cls._type, PartitionLenUnsafe(list(map(b254decode_int, data.split(b'\x00'))), 2))))
    def packed(self) -> bytes:
        b254eint = b254encode_int
        return b'\x00'.join(b254eint(key.n)+b'\x00'+b254eint(key.e) for key in self._keys)
    def encrypt(self, data:bytes) -> bytes:
        __PublicKey_encrypt = backend.PublicKey.encrypt
        for key in self._keys:
            data:bytes = __PublicKey_encrypt(key, data)
        return data
    def verify(self, data:bytes, signatures:abcs.Iterable[bytes], method:str=DEFAULT_METHOD) -> None:
        message_hash:bytes = backend.compute_hash(data, method)
        cleartext:bytes = backend.HASH_ASN1[method] + message_hash
        __PublicKey_verify_optimized = backend.PublicKey.verify_optimized
        for sig,pk in zip(signatures,self._keys):
            __PublicKey_verify_optimized(pk, sig, cleartext)
    def verify_unknown_method(self, data:bytes, signatures:abcs.Iterable[bytes]) -> None:
        """Slower than standard verify, but useful if the method of hashing is unknown"""
        __PublicKey_verify_unknown_method = backend.PublicKey.verify_unknown_method
        for sig,pk in zip(signatures,self._keys):
            __PublicKey_verify_unknown_method(pk, data, sig)
    def encrypt_and_sign                        (self,data:bytes,private:PrivateKeys,method:str=DEFAULT_METHOD)->bytes:return encrypt_and_sign                        (data,public=self,private=private,method=method)
    def encrypt_and_double_sign                 (self,data:bytes,private:PrivateKeys,method:str=DEFAULT_METHOD)->bytes:return encrypt_and_double_sign                 (data,public=self,private=private,method=method)
    def decrypt_and_verify                      (self,data:bytes,private:PrivateKeys,method:str=DEFAULT_METHOD)->bytes:return decrypt_and_verify                      (data,public=self,private=private,method=method)
    def decrypt_and_double_verify               (self,data:bytes,private:PrivateKeys,method:str=DEFAULT_METHOD)->bytes:return decrypt_and_double_verify               (data,public=self,private=private,method=method)
    def decrypt_and_verify_unknown_method       (self,data:bytes,private:PrivateKeys                          )->bytes:return decrypt_and_verify_unknown_method       (data,public=self,private=private               )
    def decrypt_and_double_verify_unknown_method(self,data:bytes,private:PrivateKeys                          )->bytes:return decrypt_and_double_verify_unknown_method(data,public=self,private=private               )


class PrivateKeys(_RSAKeyring[backend.PrivateKey]):
    _type:t.Final = backend.PrivateKey
    __slots__ = ()
    def __init__(self, keys:tuple[rsa.PrivateKey,...]): # noqa
        self._keys:t.Final[tuple[backend.PrivateKey,...]] = keys
    @classmethod
    def from_packed(cls, data:bytes) -> PrivateKeys:
        return cls(tuple(itertools.starmap(cls._type, PartitionLenUnsafe(list(map(b254decode_int, data.split(b'\x00'))), 5))))
    def packed(self) -> bytes:
        b254eint = b254encode_int
        return b'\x00'.join(
            b254eint(key.n)+b'\x00'+
            b254eint(key.e)+b'\x00'+
            b254eint(key.d)+b'\x00'+
            b254eint(key.p)+b'\x00'+
            b254eint(key.q)
            for key in self._keys
        )
    def decrypt(self, data:bytes) -> bytes:
        __PrivateKey_decrypt = backend.PrivateKey.decrypt
        for key in reversed(self._keys):
            data:bytes = __PrivateKey_decrypt(key, data)
        return data
    def sign(self, data:bytes, method:str=DEFAULT_METHOD) -> list[bytes]:
        """The size of each signature corresponds to the key sizes"""
        cleartext:bytes = backend.HASH_ASN1[method] + backend.compute_hash(data, method)
        __PrivateKey_sign_hash_optimized = backend.PrivateKey.sign_hash_optimized
        return [__PrivateKey_sign_hash_optimized(key, cleartext) for key in self._keys]
    def ds(self) -> abcs.Generator[int,t.Any,None]:
        for key in self._keys: yield key.d
    def ps(self) -> abcs.Generator[int,t.Any,None]:
        for key in self._keys: yield key.p
    def qs(self) -> abcs.Generator[int,t.Any,None]:
        for key in self._keys: yield key.q
    def exp1s(self) -> abcs.Generator[int,t.Any,None]:
        for key in self._keys: yield key.exp1
    def exp2s(self) -> abcs.Generator[int,t.Any,None]:
        for key in self._keys: yield key.exp2
    def coefs(self) -> abcs.Generator[int,t.Any,None]:
        for key in self._keys: yield key.coef
    def encrypt_and_sign                        (self,data:bytes,public:PublicKeys,method:str=DEFAULT_METHOD)->bytes:return encrypt_and_sign                        (data, public=public, private=self, method=method)
    def encrypt_and_double_sign                 (self,data:bytes,public:PublicKeys,method:str=DEFAULT_METHOD)->bytes:return encrypt_and_double_sign                 (data, public=public, private=self, method=method)
    def decrypt_and_verify                      (self,data:bytes,public:PublicKeys,method:str=DEFAULT_METHOD)->bytes:return decrypt_and_verify                      (data, public=public, private=self, method=method)
    def decrypt_and_double_verify               (self,data:bytes,public:PublicKeys,method:str=DEFAULT_METHOD)->bytes:return decrypt_and_double_verify               (data, public=public, private=self, method=method)
    def decrypt_and_verify_unknown_method       (self,data:bytes,public:PublicKeys                          )->bytes:return decrypt_and_verify_unknown_method       (data, public=public, private=self               )
    def decrypt_and_double_verify_unknown_method(self,data:bytes,public:PublicKeys                          )->bytes:return decrypt_and_double_verify_unknown_method(data, public=public, private=self               )

def encrypt_and_sign                        (data:bytes,public:PublicKeys,private:PrivateKeys,method:str=DEFAULT_METHOD)->bytes:
    """Sign and then encrypt; Results in a single binary"""
    b93e = b93encode
    return b95decode(b93e(public.encrypt(data)) + b' ' + b'`'.join(map(b93e, private.sign(data, method=method))))
def encrypt_and_double_sign                 (data:bytes,public:PublicKeys,private:PrivateKeys,method:str=DEFAULT_METHOD)->bytes:
    """Sign before and after encryption; Results in a single binary"""
    b93e = b93encode
    encrypted:bytes = public.encrypt(data)
    return b95decode(
        b93e(encrypted) + b' ' +
        b'`'.join(map(b93e, private.sign(data, method=method))) + b' ' +
        b'`'.join(map(b93e, private.sign(encrypted, method=method)))
    )
def decrypt_and_verify                      (data:bytes,public:PublicKeys,private:PrivateKeys,method:str=DEFAULT_METHOD)->bytes:
    """Decrypt and then verify from a single binary"""
    b93d = b93decode
    data,pre_sigs = b95encode(data).split(b' ') # type: bytes,bytes
    data = b93d(data)
    data = private.decrypt(data)
    public.verify(data,map(b93d, pre_sigs.split(b'`')),method=method)
    return data
def decrypt_and_double_verify               (data:bytes,public:PublicKeys,private:PrivateKeys,method:str=DEFAULT_METHOD)->bytes:
    """Verify before and after decryption"""
    b93d = b93decode
    data,pre_sigs,post_sigs = b95encode(data).split(b' ') # type: bytes,bytes,bytes
    data = b93d(data)
    public.verify(data,map(b93d, post_sigs.split(b'`')),method=method)
    data = private.decrypt(data)
    public.verify(data,map(b93d, pre_sigs.split(b'`')),method=method)
    return data
def decrypt_and_verify_unknown_method       (data:bytes,public:PublicKeys,private:PrivateKeys                          )->bytes:
    """Decrypt and then verify from a single binary; Slower since the method of signature is unknown"""
    b93d = b93decode
    data,pre_sigs = b95encode(data).split(b' ')
    data = b93d(data)
    data:bytes = private.decrypt(data)
    public.verify_unknown_method(data, map(b93d, pre_sigs.split(b'`')))
    return data
def decrypt_and_double_verify_unknown_method(data:bytes,public:PublicKeys,private:PrivateKeys                          )->bytes:
    """Verify before and after decryption; Slower since the method of signature is unknown"""
    b93d = b93decode
    data,pre_sigs,post_sigs = b95encode(data).split(b' ') # type: bytes,bytes,bytes
    data = b93d(data)
    public.verify_unknown_method(data,map(b93d, post_sigs.split(b'`')))
    data = private.decrypt(data)
    public.verify_unknown_method(data,map(b93d, pre_sigs.split(b'`')))
    return data

def generate(size:int=2048, layers:int=1) -> tuple[PublicKeys, PrivateKeys]:
    """Be cautious when increasing `layers` as it can immensely increase encryption times, encryption sizes; the same applies to `size`
    Size increases linearly for each level by 11, ex: levels=3,size=64 means key1size=64,key2size=64+11,key3size=64+11*2
    size is in bits
    poolsize should be the number of processes you want or None if you want all cores to be used"""
    #                    88 because it is 11 bytes bigger each time so 88 bits
    pub,pri = more_itertools.unzip(backend.generate(size+88*i) for i in range(layers))
    return PublicKeys(tuple(pub)), PrivateKeys(tuple(pri))
def generate_layers(first_size:int=2048, /, *sizes:int):
    sizes:list[int] = sorted([first_size, *sizes])
    it:abcs.Iterator[int] = iter(sizes)
    last_size:int = next(it)
    for size in it:
        if size < last_size+88:
            raise OverflowError(f"Not enough space for layer of size {last_size} bits to fit into next layer of size {size} (88 total bits of space needed; got {size - last_size + 88} bits)")
    pub,pri = more_itertools.unzip(map(backend.generate, sizes))
    return PublicKeys(tuple(pub)), PrivateKeys(tuple(pri))
# def generate_msg_size(msg_size:int=2048, layers:int=1) -> tuple[PublicKeys, PrivateKeys]:
#     """Be cautious when increasing `layers` as it can immensely increase encryption times, encryption sizes; the same applies to `size`
#     Size increases linearly for each level by 11, ex: levels=3,size=64 means key1size=64,key2size=64+11,key3size=64+11*2
#     size is in bits
#     poolsize should be the number of processes you want or None if you want all cores to be used"""
#     msg_size = msg_size + 88 # 88 because it is 11 bytes bigger each time so 88 bits
#     pub,pri = more_itertools.unzip(backend.generate(msg_size+88*i) for i in range(layers))
#     return PublicKeys(tuple(pub)), PrivateKeys(tuple(pri))
# def generate_pool(size:int=2048, layers:int=1, *, poolsize:t.Optional[int]=None) -> tuple[PublicKeys, PrivateKeys]:
#     """Be cautious when increasing `layers` as it can immensely increase encryption times, encryption sizes; the same applies to `size`
#     Size increases linearly for each level by 11, ex: levels=3,size=64 means key1size=64,key2size=64+11,key3size=64+11*2
#     size is in bits
#     poolsize should be the number of processes you want or None if you want all cores to be used"""
#     warnings.warn("Unstable")
#     if poolsize is None:
#         poolsize:int = multiprocessing.cpu_count()
#     elif poolsize > (hyperthreaded_cpu_count:=multiprocessing.cpu_count()):
#         raise ValueError(f"poolsize of {poolsize} is larger than the number of hyperthreaded cores ({hyperthreaded_cpu_count}) - did you make a mistake?")
#     pub,pri = more_itertools.unzip(backend.generate(size+88*i, poolsize=poolsize) for i in range(layers))
#     return PublicKeys(tuple(pub)), PrivateKeys(tuple(pri))

class Manager:
    """Wrapper for rsa interactions"""
    __slots__ = ('public_keys','private_keys','partner_public_keys')
    __match_args__ = __slots__ + ('max_input_size','output_size')
    @t.final
    def __init__(self, public_keys:PublicKeys, private_keys:PrivateKeys, partner_public_keys:PublicKeys):
        self.public_keys:PublicKeys = public_keys
        self.private_keys:PrivateKeys = private_keys
        self.partner_public_keys:PublicKeys = partner_public_keys
    @property
    @t.final
    def max_input_size(self) -> int:
        return self.public_keys.max_input_size
    @property
    @t.final
    def output_size(self) -> int:
        return self.public_keys.output_size
    @classmethod
    @t.final
    def generate(cls, partner_public_keys:PublicKeys, size:int=2048, layers:int=1) -> Manager:
        pub,pri = generate(size, layers)
        return cls(pub, pri, partner_public_keys)
    @classmethod
    @t.final
    def generate_layers(cls, partner_public_keys:PublicKeys, first_size:int=2048, /, *sizes:int) -> Manager:
        pub,pri = generate_layers(first_size, *sizes)
        return cls(pub, pri, partner_public_keys)
    @t.final
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(public_keys={self.public_keys!r},  private_keys={self.private_keys!r}, partner_public_keys={self.partner_public_keys!r})"
    @t.final
    def repr_nice(self, indent:int=0, indent_size=4) -> str:
        """Much more nice repr"""
        do_indent:str = ' '*indent_size
        extra_indent:str = do_indent*indent
        sub_indent_am:int = indent+1
        return f"{extra_indent}{self.__class__.__name__}(\n" \
               f"{extra_indent}{do_indent}public_keys=        {        self.public_keys.repr_nice(sub_indent_am, indent_size=indent_size)},\n" \
               f"{extra_indent}{do_indent}private_keys=       {       self.private_keys.repr_nice(sub_indent_am, indent_size=indent_size)},\n" \
               f"{extra_indent}{do_indent}partner_public_keys={self.partner_public_keys.repr_nice(sub_indent_am, indent_size=indent_size)})"
    # def encrypt(self, data:bytes) -> tuple[bytes,list[bytes]]:
    #     enc = self.partner_public_keys.encrypt(data)
    #     return enc, self.private_keys.sign(data)
    # def decrypt(self, data:bytes, signatures:abcs.Iterable[bytes]) -> bytes:
    #     data = self.private_keys.decrypt(data)
    #     self.partner_public_keys.verify(data, signatures)
    #     return data
    def encrypt_and_sign                        (self,data:bytes,method:str=DEFAULT_METHOD)->bytes:return encrypt_and_sign                        (data,public=self.partner_public_keys,private=self.private_keys,method=method)
    def encrypt_and_double_sign                 (self,data:bytes,method:str=DEFAULT_METHOD)->bytes:return encrypt_and_double_sign                 (data,public=self.partner_public_keys,private=self.private_keys,method=method)
    def decrypt_and_verify                      (self,data:bytes,method:str=DEFAULT_METHOD)->bytes:return decrypt_and_verify                      (data,public=self.partner_public_keys,private=self.private_keys,method=method)
    def decrypt_and_double_verify               (self,data:bytes,method:str=DEFAULT_METHOD)->bytes:return decrypt_and_double_verify               (data,public=self.partner_public_keys,private=self.private_keys,method=method)
    def decrypt_and_verify_unknown_method       (self,data:bytes                          )->bytes:return decrypt_and_verify_unknown_method       (data,public=self.partner_public_keys,private=self.private_keys               )
    def decrypt_and_double_verify_unknown_method(self,data:bytes                          )->bytes:return decrypt_and_double_verify_unknown_method(data,public=self.partner_public_keys,private=self.private_keys               )

class ManagerEncodedABC(Manager, metaclass=abc.ABCMeta):
    """All data is encoded, usually in base64 or base85"""
    __slots__ = ()
    @staticmethod
    @abc.abstractmethod
    def _encode(s:bytes) -> bytes:
        ...
    @staticmethod
    @abc.abstractmethod
    def _decode(s:bytes) -> bytes:
        ...
    def encrypt_and_sign                        (self,data:bytes,method:str=DEFAULT_METHOD)->bytes:return self.__class__._encode(encrypt_and_sign                        (data ,public=self.partner_public_keys,private=self.private_keys,method=method))
    def encrypt_and_double_sign                 (self,data:bytes,method:str=DEFAULT_METHOD)->bytes:return self.__class__._encode(encrypt_and_double_sign                 (data ,public=self.partner_public_keys,private=self.private_keys,method=method))
    def decrypt_and_verify                      (self,data:bytes,method:str=DEFAULT_METHOD)->bytes:return decrypt_and_verify                      (self.__class__._decode(data),public=self.partner_public_keys,private=self.private_keys,method=method)
    def decrypt_and_double_verify               (self,data:bytes,method:str=DEFAULT_METHOD)->bytes:return decrypt_and_double_verify               (self.__class__._decode(data),public=self.partner_public_keys,private=self.private_keys,method=method)
    def decrypt_and_verify_unknown_method       (self,data:bytes                          )->bytes:return decrypt_and_verify_unknown_method       (self.__class__._decode(data),public=self.partner_public_keys,private=self.private_keys               )
    def decrypt_and_double_verify_unknown_method(self,data:bytes                          )->bytes:return decrypt_and_double_verify_unknown_method(self.__class__._decode(data),public=self.partner_public_keys,private=self.private_keys               )

class ManagerBase64(ManagerEncodedABC):
    __slots__ = ()
    @staticmethod
    def _encode(s:bytes) -> bytes:
        return base64.urlsafe_b64encode(s)
    @staticmethod
    def _decode(s:bytes) -> bytes:
        return base64.urlsafe_b64decode(s)
class ManagerBase64Standard(ManagerEncodedABC):
    __slots__ = ()
    @staticmethod
    def _encode(s:bytes) -> bytes:
        return base64.standard_b64encode(s)
    @staticmethod
    def _decode(s:bytes) -> bytes:
        return base64.standard_b64decode(s)
class ManagerBase85(ManagerEncodedABC):
    __slots__ = ()
    @staticmethod
    def _encode(s:bytes) -> bytes:
        return base64.b85encode(s)
    @staticmethod
    def _decode(s:bytes) -> bytes:
        return base64.b85decode(s)
class ManagerBase95(ManagerEncodedABC):
    __slots__ = ()
    @staticmethod
    def _encode(s:bytes) -> bytes: return b95encode(s)
    @staticmethod
    def _decode(s:bytes) -> bytes: return b95decode(s)
class ManagerBase94(ManagerEncodedABC):
    __slots__ = ()
    @staticmethod
    def _encode(s:bytes) -> bytes: return b94encode(s)
    @staticmethod
    def _decode(s:bytes) -> bytes: return b94decode(s)
class ManagerBase93(ManagerEncodedABC):
    __slots__ = ()
    @staticmethod
    def _encode(s:bytes) -> bytes: return b93encode(s)
    @staticmethod
    def _decode(s:bytes) -> bytes: return b93decode(s)
class ManagerBase92(ManagerEncodedABC):
    __slots__ = ()
    @staticmethod
    def _encode(s:bytes) -> bytes: return b92encode(s)
    @staticmethod
    def _decode(s:bytes) -> bytes: return b92decode(s)
class ManagerBase91(ManagerEncodedABC):
    __slots__ = ()
    @staticmethod
    def _encode(s:bytes) -> bytes: return b91encode(s)
    @staticmethod
    def _decode(s:bytes) -> bytes: return b91decode(s)

class ManagerCompressed(Manager):
    """Data is compressed, if minimum savings are available
    Be careful as this could potentially be insecure in the event that an attacker can manipulate what is encrypted, see https://en.wikipedia.org/wiki/CRIME and https://en.wikipedia.org/wiki/BREACH"""
    __slots__ = ()
    def encrypt_and_sign                        (self,data:bytes,method:str=DEFAULT_METHOD,min_savings:float=0.10)->bytes:return encrypt_and_sign       (conditional_compress(data,min_savings=min_savings),public=self.partner_public_keys,private=self.private_keys,method=method)
    def encrypt_and_double_sign                 (self,data:bytes,method:str=DEFAULT_METHOD,min_savings:float=0.10)->bytes:return encrypt_and_double_sign(conditional_compress(data,min_savings=min_savings),public=self.partner_public_keys,private=self.private_keys,method=method)
    def decrypt_and_verify                      (self,data:bytes,method:str=DEFAULT_METHOD                       )->bytes:return conditional_decompress (decrypt_and_verify                      (data,     public=self.partner_public_keys,private=self.private_keys,method=method))
    def decrypt_and_double_verify               (self,data:bytes,method:str=DEFAULT_METHOD                       )->bytes:return conditional_decompress (decrypt_and_double_verify               (data,     public=self.partner_public_keys,private=self.private_keys,method=method))
    def decrypt_and_verify_unknown_method       (self,data:bytes                                                 )->bytes:return conditional_decompress (decrypt_and_verify_unknown_method       (data,     public=self.partner_public_keys,private=self.private_keys              ))
    def decrypt_and_double_verify_unknown_method(self,data:bytes                                                 )->bytes:return conditional_decompress (decrypt_and_double_verify_unknown_method(data,     public=self.partner_public_keys,private=self.private_keys              ))

class ManagerEncodedCompressedABC(ManagerEncodedABC, metaclass=abc.ABCMeta):
    """All data is encoded in base64 & data is compressed, if minimum savings are available
    Be careful as this could potentially be insecure in the event that an attacker can manipulate what is encrypted, see https://en.wikipedia.org/wiki/CRIME and https://en.wikipedia.org/wiki/BREACH"""
    __slots__ = ()
    def encrypt_and_sign                        (self,data:bytes,method:str=DEFAULT_METHOD,min_savings:float=0.10)->bytes:return self.__class__._encode(encrypt_and_sign       (conditional_compress      (data,min_savings=min_savings),public=self.partner_public_keys,private=self.private_keys,method=method))
    def encrypt_and_double_sign                 (self,data:bytes,method:str=DEFAULT_METHOD,min_savings:float=0.10)->bytes:return self.__class__._encode(encrypt_and_double_sign(conditional_compress      (data,min_savings=min_savings),public=self.partner_public_keys,private=self.private_keys,method=method))
    def decrypt_and_verify                      (self,data:bytes,method:str=DEFAULT_METHOD                       )->bytes:return conditional_decompress(decrypt_and_verify                      (self.__class__._decode(data),public=self.partner_public_keys,private=self.private_keys,method=method)).tobytes()
    def decrypt_and_double_verify               (self,data:bytes,method:str=DEFAULT_METHOD                       )->bytes:return conditional_decompress(decrypt_and_double_verify               (self.__class__._decode(data),public=self.partner_public_keys,private=self.private_keys,method=method)).tobytes()
    def decrypt_and_verify_unknown_method       (self,data:bytes                                                 )->bytes:return conditional_decompress(decrypt_and_verify_unknown_method       (self.__class__._decode(data),public=self.partner_public_keys,private=self.private_keys              )).tobytes()
    def decrypt_and_double_verify_unknown_method(self,data:bytes                                                 )->bytes:return conditional_decompress(decrypt_and_double_verify_unknown_method(self.__class__._decode(data),public=self.partner_public_keys,private=self.private_keys              )).tobytes()

class ManagerBase64Compressed(ManagerEncodedCompressedABC, ManagerBase64): pass
class ManagerBase64StandardCompressed(ManagerEncodedCompressedABC, ManagerBase64Standard): pass
class ManagerBase85Compressed(ManagerEncodedCompressedABC, ManagerBase85): pass
class ManagerBase95Compressed(ManagerEncodedCompressedABC, ManagerBase95): pass
class ManagerBase94Compressed(ManagerEncodedCompressedABC, ManagerBase94): pass
class ManagerBase93Compressed(ManagerEncodedCompressedABC, ManagerBase93): pass
class ManagerBase92Compressed(ManagerEncodedCompressedABC, ManagerBase92): pass
class ManagerBase91Compressed(ManagerEncodedCompressedABC, ManagerBase91): pass
