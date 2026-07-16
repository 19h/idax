"""Opaque register-value tracking with owned semantic results."""

from ._native.registers import (
    NearestValue,
    ReferenceMutation,
    TrackedValue,
    TrackingState,
    ValueCandidate,
    ValueOrigin,
    clear_control_flow_cache,
    clear_data_reference_cache,
    constant_at,
    control_flow_reference_changed,
    data_reference_changed,
    nearest_at,
    stack_delta_at,
    track,
)

__all__ = [
    "NearestValue",
    "ReferenceMutation",
    "TrackedValue",
    "TrackingState",
    "ValueCandidate",
    "ValueOrigin",
    "clear_control_flow_cache",
    "clear_data_reference_cache",
    "constant_at",
    "control_flow_reference_changed",
    "data_reference_changed",
    "nearest_at",
    "stack_delta_at",
    "track",
]
