from __future__ import annotations

__all__ = [
    '_Keyring',
]

from .__common import *

nl = '\n'

class _Keyring(t.Generic[T], abcs.Reversible[T], abcs.Collection[T], metaclass=abc.ABCMeta):
    _type = ...
    @abc.abstractmethod
    def __init_subclass__(cls, **kwargs): ...
    __slots__ = __match_args__ = ('_keys',)
    @t.final
    def __init__(self, keys:tuple[T,...]):
        self._keys:tuple[T,...] = keys
    @classmethod
    @abc.abstractmethod
    def from_packed(cls, data:bytes) -> _Keyring[T]: ...
    @t.final
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._keys!r})"
    @t.final
    def __iter__(self) -> abcs.Iterator[T]:
        return iter(self._keys)
    @t.final
    def __reversed__(self) -> abcs.Iterator[T]:
        return reversed(self._keys)
    @t.final
    def __len__(self) -> int:
        return len(self._keys)
    @t.final
    def __hash__(self) -> int:
        return hash(self._keys)
    @t.final
    def __getitem__(self, item:int) -> bytes:
        return self._keys[item]
    @t.final
    def __contains__(self, item:t.Any) -> bool: # can't type hint this
        return item in self._keys
    @t.final
    def repr_nice(self, indent:int=0, indent_size:int=4) -> str:
        do_indent = ' '*indent_size
        extra_indent = do_indent*indent
        return f"{extra_indent}{self.__class__.__name__}(\n" \
               f"{extra_indent}{do_indent}{f',{nl}{extra_indent}{do_indent}'.join(map(repr, self._keys))}\n" \
               f"{extra_indent})" #FAR TOO MUCH WORK TO ENCODE THE INTS IN __INIT__! ^^^^^^^^^^^^^^^^__
    @abc.abstractmethod
    def packed(self) -> bytes: ...
