from .runner import BinaryMixin


class GCCMixin(BinaryMixin):
    COMPILER = "gcc"


class GXXMixin(BinaryMixin):
    COMPILER = "g++"
