from .runner import BinaryMixin


class OCamlMixin(BinaryMixin):
    COMPILER = "ocamlopt"
