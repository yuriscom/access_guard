from typing import Optional

from pydantic import BaseModel


class CasbinPolicy(BaseModel):
    ptype: str  # "p" for permission, "g" for role assignment
    sub: str  # subject (user email or role path)
    obj: Optional[str] = None # object (resource path)
    act: Optional[str] = None # action
    effect: Optional[str] = None # typically "allow"

    def to_tuple(self) -> tuple[str, ...]:
        base = [self.ptype, self.sub, self.obj, self.act, self.effect]
        values = [str(x or "") for x in base]
        # Trim trailing empty values
        while values and values[-1] == "":
            values.pop()
        return tuple(values)

    def to_tuple_and_string(self) -> tuple[tuple[str, ...], str]:
        tup = self.to_tuple()
        return tup, ",".join(tup)

    @classmethod
    def to_string(cls, tup: tuple):
        return ",".join(tup)