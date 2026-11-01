"""Colunas de enumeração persistidas pelo valor, não pelo nome do membro."""

import enum

from sqlalchemy import Enum


def enum_column(enum_cls: type[enum.Enum], length: int = 32) -> Enum:
    return Enum(
        enum_cls,
        native_enum=False,
        length=length,
        values_callable=lambda items: [item.value for item in items],
    )
