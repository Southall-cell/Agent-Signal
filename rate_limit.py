"""Small process-local fixed-window limiter keyed by stable agent principal."""
import math
import threading
import time
from typing import Callable, Dict, Tuple


class PerKeyRateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60, clock: Callable[[], float] = time.monotonic):
        if max_requests < 1 or window_seconds < 1:
            raise ValueError("Rate-limit settings must be positive.")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: Dict[str, Tuple[int, int]] = {}

    def check(self, key_fingerprint: str) -> int:
        """Return 0 if allowed; otherwise return Retry-After seconds."""
        now = self._clock()
        window = int(now // self.window_seconds)
        with self._lock:
            # Bound stale state when many keys are seen over time.
            if len(self._windows) > 10000:
                self._windows = {key: item for key, item in self._windows.items() if item[0] >= window}
            stored_window, count = self._windows.get(key_fingerprint, (window, 0))
            if stored_window != window:
                count = 0
            if count >= self.max_requests:
                return max(1, math.ceil((window + 1) * self.window_seconds - now))
            self._windows[key_fingerprint] = (window, count + 1)
            return 0
