class FwtriageError(Exception):
    """Base class of every error fwtriage raises on purpose."""


class FormatError(FwtriageError):
    """The bytes do not hold a valid instance of the format being parsed."""


class BudgetExceeded(FwtriageError):
    """An extraction limit was reached."""

    def __init__(self, limit: str, value: int) -> None:
        super().__init__(f"{limit} limit of {value:,} reached")
        self.limit = limit
        self.value = value


class MissingExtra(FwtriageError):
    """The format is recognized, but unpacking it needs an optional extra."""

    def __init__(self, extra: str, codec: str) -> None:
        super().__init__(f"{codec} needs the '{extra}' extra: pip install 'fwtriage[{extra}]'")
        self.extra = extra
        self.codec = codec


class OnlineError(FwtriageError):
    """A network lookup failed."""


class PolicyError(FwtriageError):
    """The policy file is invalid."""
