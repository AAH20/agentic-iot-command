"""Auditable data-center lifecycle costing helpers (Decimal, no price fetching)."""
from __future__ import annotations

from decimal import Decimal, InvalidOperation, localcontext
from typing import Any


def _d(value: Any, name: str, *, minimum: Decimal | None = None) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{name} must be a finite decimal")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{name} must be a finite decimal") from exc
    if not result.is_finite() or (minimum is not None and result < minimum):
        raise ValueError(f"{name} is outside its allowed range")
    return result


def price_extended(*, quantity: Any, unit_price: Any, waste_factor: Any = 0,
                   low_unit_price: Any | None = None, high_unit_price: Any | None = None,
                   quantity_unit: str, price_unit: str, quantity_currency: str,
                   price_currency: str) -> dict[str, Decimal]:
    """Calculate bounded takeoff totals, rejecting unit/currency mismatches."""
    if not quantity_unit.strip() or quantity_unit.strip() != price_unit.strip():
        raise ValueError("quantity and price units must match after explicit normalization")
    if quantity_currency.upper() != price_currency.upper():
        raise ValueError("quantity and price currencies must match after dated FX normalization")
    q = _d(quantity, "quantity", minimum=Decimal(0))
    waste = _d(waste_factor, "waste_factor", minimum=Decimal(0))
    if waste > 1:
        raise ValueError("waste_factor cannot exceed 1")
    base = _d(unit_price, "unit_price", minimum=Decimal(0))
    low = base if low_unit_price is None else _d(low_unit_price, "low_unit_price", minimum=Decimal(0))
    high = base if high_unit_price is None else _d(high_unit_price, "high_unit_price", minimum=Decimal(0))
    if low > base or high < base:
        raise ValueError("low <= base <= high is required")
    factor = q * (Decimal(1) + waste)
    return {"low": factor * low, "base": factor * base, "high": factor * high}


def lifecycle_present_value(*, quantity: Any, unit_price: Any, horizon_months: int,
                            discount_rate: Any = 0, annual_escalation: Any = 0,
                            recurrence_months: int | None = None, start_month: int = 0,
                            waste_factor: Any = 0) -> Decimal:
    """NPV of a one-off or recurring known-rate cost; excludes tax/financing by default."""
    if isinstance(horizon_months, bool) or not 1 <= horizon_months <= 600:
        raise ValueError("horizon_months must be between 1 and 600")
    if isinstance(start_month, bool) or not 0 <= start_month <= horizon_months:
        raise ValueError("start_month must be within the estimate horizon")
    if recurrence_months is not None and (isinstance(recurrence_months, bool) or recurrence_months < 1):
        raise ValueError("recurrence_months must be a positive integer")
    rate = _d(discount_rate, "discount_rate", minimum=Decimal(0))
    escalation = _d(annual_escalation, "annual_escalation")
    if rate >= 1 or escalation <= -1 or escalation > 1:
        raise ValueError("discount must be <100%; escalation must be >-100% and <=100%")
    base = _d(quantity, "quantity", minimum=Decimal(0)) * _d(unit_price, "unit_price", minimum=Decimal(0))
    base *= Decimal(1) + _d(waste_factor, "waste_factor", minimum=Decimal(0))
    if _d(waste_factor, "waste_factor") > 1:
        raise ValueError("waste_factor cannot exceed 1")
    months = list(range(start_month, horizon_months + 1, recurrence_months or (horizon_months + 1)))
    with localcontext() as ctx:
        ctx.prec = 34
        total = Decimal(0)
        for month in months:
            years = Decimal(month) / Decimal(12)
            escalator = ctx.power(Decimal(1) + escalation, years)
            discount = ctx.power(Decimal(1) + rate, years)
            total += base * escalator / discount
        return total.quantize(Decimal("0.000001"))


def unit_economics(*, lifecycle_pv: Any, horizon_months: int, discount_rate: Any,
                   denominators: dict[str, Any]) -> dict[str, Decimal | None]:
    """Annualize lifecycle PV then divide by explicit physical/service denominators."""
    if isinstance(horizon_months, bool) or not 1 <= horizon_months <= 600:
        raise ValueError("horizon_months must be between 1 and 600")
    years = Decimal(horizon_months) / Decimal(12)
    pv = _d(lifecycle_pv, "lifecycle_pv", minimum=Decimal(0))
    rate = _d(discount_rate, "discount_rate", minimum=Decimal(0))
    if rate >= 1:
        raise ValueError("discount_rate must be below 100%")
    with localcontext() as ctx:
        ctx.prec = 34
        factor = Decimal(1) / years if rate == 0 else rate / (1 - ctx.power(1 + rate, -years))
        annualized = pv * factor
        result: dict[str, Decimal | None] = {"annualized_lifecycle_cost": annualized.quantize(Decimal("0.01"))}
        for name, raw in denominators.items():
            denominator = _d(raw, name, minimum=Decimal(0))
            result[name] = None if denominator == 0 else (annualized / denominator).quantize(Decimal("0.000001"))
        return result
