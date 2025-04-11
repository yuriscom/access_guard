from abc import ABC, abstractmethod
from typing import Optional

from casbin.model import Model
from casbin.persist import Adapter

class CasbinAdapterABC(Adapter, ABC):
    def __init__(self):
        self._is_filtered = False

    def is_filtered(self) -> bool:
        return self._is_filtered

    def set_filtered(self, is_filtered: bool = True):
        self._is_filtered = is_filtered

    @abstractmethod
    def load_policy(self, model: Model):
        pass
