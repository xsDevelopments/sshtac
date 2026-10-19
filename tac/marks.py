"""Results-buffer mark arithmetic. Pure functions, no tmux calls.

tmux numbers pane lines relative to the visible screen: 0 is the top visible
line, negative numbers reach back into history, down to -history_size. We store
a mark as an *absolute* line (history_size + cursor_y at the time) so it stays
put while new output scrolls the screen.

Two things can invalidate a mark, and both are clamped rather than raised:

* history was cleared (`clear-history`, ESC[3J): history_size shrinks below the
  value recorded with the mark, so we capture everything that is left;
* history hit `history-limit`: old lines fall off the top but history_size stops
  growing, so the mark drifts down and a capture may miss earliest lines. We
  flag this so the user knows.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Mark:
    line: int  # absolute: history_size + cursor_y when the mark was set
    history_size: int


@dataclass(frozen=True)
class PaneState:
    history_size: int
    cursor_y: int
    history_limit: int


@dataclass(frozen=True)
class CaptureRange:
    start: int  # tmux-relative line, for capture-pane -S
    end: int  # tmux-relative line, for capture-pane -E
    note: str | None = None


def mark_at(state: PaneState) -> Mark:
    return Mark(line=state.history_size + state.cursor_y, history_size=state.history_size)


def capture_range(mark: Mark | None, state: PaneState) -> CaptureRange:
    """Range from the mark (inclusive) to the cursor line (inclusive)."""
    top = -state.history_size
    end = max(state.cursor_y, 0)
    notes: list[str] = []

    if mark is None:
        start = top
        notes.append("no mark yet; capturing all history")
    elif state.history_size < mark.history_size:
        start = top
        notes.append("history was cleared since the mark; capturing what remains")
    else:
        start = mark.line - state.history_size
        if start < top:
            start = top
            notes.append("mark is beyond the start of history; clamped")
        if start > end:
            start = end
            notes.append("mark is below the cursor (screen cleared?); capturing the current line")

    if state.history_limit > 0 and state.history_size >= state.history_limit:
        notes.append("history-limit reached; the earliest lines since the mark may be missing")

    return CaptureRange(start=start, end=end, note="; ".join(notes) or None)
