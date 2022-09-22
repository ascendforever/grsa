# noinspection PyPep8Naming




PYXIMPORT_INSTALLED:bool = False
try:
    from . import Cbackend as backend
except ImportError:
    from pyximport import install as ____pyximport_install
    from warnings import warn as ____warn
    ____warn("Pyximport has been installed because this is the first time the package is running", ImportWarning)
    # you cannot redirect pyximport compilation messages
    ____pyximport_install(language_level=3, inplace=True)
    PYXIMPORT_INSTALLED = True
    from . import _Cbackend as backend

from ._main import *

__version__ = '1.0.0'
