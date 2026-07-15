"""Structured IDAX exceptions and error values."""

from ._native import (
    ConflictError,
    ErrorCategory,
    ErrorInfo,
    IdaxError,
    InternalError,
    NotFoundError,
    SdkError,
    UnsupportedError,
    ValidationError,
)

__all__ = [
    "ConflictError",
    "ErrorCategory",
    "ErrorInfo",
    "IdaxError",
    "InternalError",
    "NotFoundError",
    "SdkError",
    "UnsupportedError",
    "ValidationError",
]
