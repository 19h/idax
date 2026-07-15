class OperationOptions:
    strict_validation: bool
    allow_partial_results: bool
    cancel_on_user_break: bool
    quiet: bool
    def __init__(self) -> None: ...

class RangeOptions:
    start: int
    end: int
    inclusive_end: bool
    def __init__(self) -> None: ...

class WaitOptions:
    timeout_ms: int
    poll_interval_ms: int
    def __init__(self) -> None: ...
