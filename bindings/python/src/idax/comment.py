"""Ordinary, repeatable, anterior, and posterior comments."""

from ._native.comment import (
    add_anterior,
    add_posterior,
    anterior_lines,
    append,
    clear_anterior,
    clear_posterior,
    get,
    get_anterior,
    get_posterior,
    posterior_lines,
    remove,
    remove_anterior_line,
    remove_posterior_line,
    render,
    set,
    set_anterior,
    set_anterior_lines,
    set_posterior,
    set_posterior_lines,
)

__all__ = [
    "add_anterior", "add_posterior", "anterior_lines", "append",
    "clear_anterior", "clear_posterior", "get", "get_anterior",
    "get_posterior", "posterior_lines", "remove", "remove_anterior_line",
    "remove_posterior_line", "render", "set", "set_anterior",
    "set_anterior_lines", "set_posterior", "set_posterior_lines",
]
