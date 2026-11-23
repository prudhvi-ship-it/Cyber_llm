"""Regression tests for the actual FRA-style flow reporter behavior."""
import unittest

from flow_summariser import FlowSummariser


class FraFlowReporterTests(unittest.TestCase):
    def test_square_root_allocation_respects_budget_and_flow_caps(self):
        allocations = FlowSummariser._sqrt_token_allocation([100, 400, 900], 300)
        self.assertEqual(sum(allocations), 300)
        self.assertLessEqual(allocations[0], 100)
        self.assertLessEqual(allocations[1], 400)
        self.assertLessEqual(allocations[2], 900)
        self.assertGreater(allocations[2], allocations[0])

    def test_short_flows_keep_their_complete_allocation(self):
        self.assertEqual(
            FlowSummariser._sqrt_token_allocation([10, 20, 30], 100),
            [10, 20, 30],
        )

    def test_token_truncation_preserves_both_edges(self):
        bounded = FlowSummariser._truncate_flow_tokens(
            "BEGINNING_MARKER " + ("middle " * 500) + " END_MARKER",
            40,
        )
        self.assertIn("BEGINNING_MARKER", bounded)
        self.assertIn("END_MARKER", bounded)
        self.assertIn("final part of the flow", bounded)


if __name__ == "__main__":
    unittest.main()
