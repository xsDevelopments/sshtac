import unittest

from tac.marks import Mark, PaneState, capture_range, mark_at


def st(history_size: int, cursor_y: int, limit: int = 50_000) -> PaneState:
    return PaneState(history_size=history_size, cursor_y=cursor_y, history_limit=limit)


class TestMarks(unittest.TestCase):
    def test_mark_is_absolute(self):
        self.assertEqual(mark_at(st(100, 7)), Mark(line=107, history_size=100))

    def test_no_scroll_since_mark(self):
        r = capture_range(mark_at(st(0, 3)), st(0, 10))
        self.assertEqual((r.start, r.end, r.note), (3, 10, None))

    def test_output_scrolled_into_history(self):
        m = mark_at(st(100, 20))  # absolute 120
        r = capture_range(m, st(130, 23))  # 30 lines scrolled off
        self.assertEqual((r.start, r.end), (-10, 23))
        self.assertIsNone(r.note)

    def test_no_mark_captures_all(self):
        r = capture_range(None, st(40, 5))
        self.assertEqual((r.start, r.end), (-40, 5))
        self.assertIn("no mark", r.note)

    def test_history_cleared(self):
        r = capture_range(mark_at(st(500, 10)), st(3, 8))
        self.assertEqual((r.start, r.end), (-3, 8))
        self.assertIn("cleared", r.note)

    def test_screen_clear_with_scroll_on_clear(self):
        # `clear` pushes the screen into history and homes the cursor.
        r = capture_range(mark_at(st(100, 10)), st(116, 0))
        self.assertEqual((r.start, r.end), (-6, 0))

    def test_mark_below_cursor_clamped(self):
        r = capture_range(Mark(line=50, history_size=0), st(0, 5))
        self.assertEqual((r.start, r.end), (5, 5))
        self.assertIn("below the cursor", r.note)

    def test_history_limit_flagged(self):
        r = capture_range(mark_at(st(2000, 10)), st(2000, 20, limit=2000))
        self.assertEqual((r.start, r.end), (10, 20))
        self.assertIn("history-limit", r.note)

    def test_start_never_before_top(self):
        r = capture_range(Mark(line=-999, history_size=0), st(10, 2))
        self.assertEqual(r.start, -10)

    def test_negative_cursor_guard(self):
        r = capture_range(None, st(0, -1))
        self.assertEqual((r.start, r.end), (0, 0))

    def test_range_always_ordered(self):
        for hist in (0, 5, 100):
            for cy in (0, 3, 40):
                for mline in (-10, 0, 50, 200):
                    for mhist in (0, 50, 200):
                        r = capture_range(Mark(mline, mhist), st(hist, cy))
                        self.assertLessEqual(r.start, r.end)
                        self.assertGreaterEqual(r.start, -hist)


if __name__ == "__main__":
    unittest.main()
