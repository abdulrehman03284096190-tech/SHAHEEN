from __future__ import annotations

import threading
from queue import Queue
from typing import Callable, TypeVar

T = TypeVar("T")


class TaskManager:
    def __init__(self) -> None:
        self._tasks: dict[str, threading.Thread] = {}
        self._queues: dict[str, Queue] = {}

    def start_background(self, name: str, target: Callable[[], None], *, daemon: bool = True) -> threading.Thread:
        thread = threading.Thread(target=target, name=name, daemon=daemon)
        self._tasks[name] = thread
        thread.start()
        return thread

    def queue_for(self, name: str) -> Queue:
        self._queues.setdefault(name, Queue())
        return self._queues[name]
