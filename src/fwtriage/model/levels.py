from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"unknown severity '{value}'") from None


class Confidence(IntEnum):
    INDICATOR = 0
    LIKELY = 1
    CONFIRMED = 2

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Confidence":
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"unknown confidence '{value}'") from None
