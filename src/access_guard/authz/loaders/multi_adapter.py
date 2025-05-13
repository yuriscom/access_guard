from casbin import Model

from access_guard.authz.loaders.policy_loader_abc import PolicyLoaderABC


class MultiAdapter(PolicyLoaderABC):
    def __init__(self, loaders: list[PolicyLoaderABC]):
        self.loaders = loaders

    def load_policy(self, model: Model, filter: dict = None):
        for loader in self.loaders:
            loader.load_policy(model, filter=filter)

    def save_policy(self, model: Model):
        raise NotImplementedError("MultiAdapter does not support saving policies.")

    def add_policy(self, sec, ptype, rule):
        raise NotImplementedError()

    def remove_policy(self, sec, ptype, rule):
        raise NotImplementedError()

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        raise NotImplementedError()