"""Deterministic comparison for the version constraints used by advisory intake."""

from __future__ import annotations

import re
from dataclasses import dataclass


Version = tuple[int, ...]
_VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-+][0-9A-Za-z.-]+)?$")
_COMPARATOR = re.compile(r"(>=|<=|==|=|>|<)\s*(v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?)")


@dataclass(frozen=True)
class Interval:
    lower: Version | None = None
    lower_inclusive: bool = True
    upper: Version | None = None
    upper_inclusive: bool = True


def _version(value: str) -> Version | None:
    match = _VERSION.fullmatch(value.strip())
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _compare(left: Version, right: Version) -> int:
    size = max(len(left), len(right))
    normalized_left = left + (0,) * (size - len(left))
    normalized_right = right + (0,) * (size - len(right))
    return (normalized_left > normalized_right) - (normalized_left < normalized_right)


def _increment_prefix(version: Version, index: int) -> Version:
    values = list(version[:index + 1])
    values[index] += 1
    return tuple(values)


def _single_interval(expression: str) -> Interval | None:
    value = expression.strip()
    if not value:
        return None
    wildcard = re.fullmatch(r"v?(\d+(?:\.\d+)*)\.(?:x|X|\*)", value)
    if wildcard:
        base = tuple(int(part) for part in wildcard.group(1).split("."))
        return Interval(base, True, _increment_prefix(base, len(base) - 1), False)
    if value.startswith(("^", "~")):
        operator, raw = value[0], value[1:].strip()
        base = _version(raw)
        if base is None:
            return None
        if operator == "~":
            index = 0 if len(base) == 1 else len(base) - 2
        else:
            index = next((index for index, part in enumerate(base) if part), len(base) - 1)
        return Interval(base, True, _increment_prefix(base, index), False)
    exact = _version(value)
    if exact is not None:
        return Interval(exact, True, exact, True)

    matches = list(_COMPARATOR.finditer(value))
    if not matches:
        return None
    remainder = _COMPARATOR.sub("", value).replace(",", "").strip()
    if remainder:
        return None
    interval = Interval()
    for match in matches:
        operator, raw = match.groups()
        parsed = _version(raw)
        if parsed is None:
            return None
        if operator in {"=", "=="}:
            constraint = Interval(parsed, True, parsed, True)
        elif operator == ">=":
            constraint = Interval(lower=parsed, lower_inclusive=True)
        elif operator == ">":
            constraint = Interval(lower=parsed, lower_inclusive=False)
        elif operator == "<=":
            constraint = Interval(upper=parsed, upper_inclusive=True)
        else:
            constraint = Interval(upper=parsed, upper_inclusive=False)
        interval = _intersection(interval, constraint)
        if interval is None:
            return None
    return interval


def _intersection(left: Interval, right: Interval) -> Interval | None:
    lower, lower_inclusive = left.lower, left.lower_inclusive
    if right.lower is not None and (
        lower is None or _compare(right.lower, lower) > 0
        or (_compare(right.lower, lower) == 0 and not right.lower_inclusive)
    ):
        lower, lower_inclusive = right.lower, right.lower_inclusive
    elif right.lower is not None and lower is not None and _compare(right.lower, lower) == 0:
        lower_inclusive = lower_inclusive and right.lower_inclusive

    upper, upper_inclusive = left.upper, left.upper_inclusive
    if right.upper is not None and (
        upper is None or _compare(right.upper, upper) < 0
        or (_compare(right.upper, upper) == 0 and not right.upper_inclusive)
    ):
        upper, upper_inclusive = right.upper, right.upper_inclusive
    elif right.upper is not None and upper is not None and _compare(right.upper, upper) == 0:
        upper_inclusive = upper_inclusive and right.upper_inclusive

    if lower is not None and upper is not None:
        comparison = _compare(lower, upper)
        if comparison > 0 or (comparison == 0 and not (lower_inclusive and upper_inclusive)):
            return None
    return Interval(lower, lower_inclusive, upper, upper_inclusive)


def _parse(expression: str) -> list[Interval] | None:
    alternatives: list[Interval] = []
    for part in re.split(r"\s*\|\|\s*", expression.strip()):
        interval = _single_interval(part)
        if interval is None:
            return None
        alternatives.append(interval)
    return alternatives or None


def ranges_relation(declared: str, affected_constraints: list[str]) -> str:
    """Return overlap only when parsed intervals prove it, disjoint when all disprove it."""
    declared_intervals = _parse(declared)
    if declared_intervals is None or not affected_constraints:
        return "unresolved"
    affected: list[Interval] = []
    for constraint in affected_constraints:
        parsed = _parse(str(constraint))
        if parsed is None:
            return "unresolved"
        affected.extend(parsed)
    for left in declared_intervals:
        for right in affected:
            if _intersection(left, right) is not None:
                return "overlaps"
    return "disjoint"
