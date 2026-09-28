import unittest
from decimal import Decimal

from control_plane_core.costing import lifecycle_present_value, price_extended, unit_economics


class CostingTests(unittest.TestCase):
    def test_takeoff_requires_normalized_units_and_currency(self):
        result = price_extended(quantity=10, unit_price="2.50", waste_factor="0.1",
            low_unit_price=2, high_unit_price=3, quantity_unit="m", price_unit="m",
            quantity_currency="USD", price_currency="usd")
        self.assertEqual(result, {"low": Decimal("22.0"), "base": Decimal("27.50"), "high": Decimal("33.0")})
        with self.assertRaisesRegex(ValueError, "units must match"):
            price_extended(quantity=1, unit_price=1, quantity_unit="m", price_unit="ft", quantity_currency="USD", price_currency="USD")
        with self.assertRaisesRegex(ValueError, "currencies must match"):
            price_extended(quantity=1, unit_price=1, quantity_unit="m", price_unit="m", quantity_currency="EUR", price_currency="USD")

    def test_lifecycle_cost_models_one_off_and_recurring_cashflows(self):
        self.assertEqual(lifecycle_present_value(quantity=100, unit_price=10, horizon_months=120), Decimal("1000.000000"))
        recurring = lifecycle_present_value(quantity=100, unit_price=10, horizon_months=24, recurrence_months=12, start_month=12)
        self.assertGreater(recurring, Decimal("1900"))
        self.assertLess(recurring, Decimal("2100"))

    def test_unit_economics_returns_null_for_missing_or_zero_denominators(self):
        result = unit_economics(lifecycle_pv=12000, horizon_months=120, discount_rate=0,
                                denominators={"usd_per_kw_year": 10, "usd_per_work_unit": 0})
        self.assertEqual(result["annualized_lifecycle_cost"], Decimal("1200.00"))
        self.assertEqual(result["usd_per_kw_year"], Decimal("120.000000"))
        self.assertIsNone(result["usd_per_work_unit"])

    def test_rejects_invalid_financial_bounds(self):
        with self.assertRaises(ValueError):
            lifecycle_present_value(quantity=1, unit_price=1, horizon_months=601)
        with self.assertRaises(ValueError):
            lifecycle_present_value(quantity=1, unit_price=1, horizon_months=12, discount_rate=1)


if __name__ == "__main__":
    unittest.main()
