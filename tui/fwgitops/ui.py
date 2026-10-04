"""Small curses building blocks: a menu, a text field, a message, a pager."""

from __future__ import annotations

import curses

ESCAPE = 27
ENTER = (curses.KEY_ENTER, 10, 13)
BACKSPACE = (curses.KEY_BACKSPACE, 127, 8)


class Cancelled(Exception):
    """The person pressed Escape."""


def _put(screen, row: int, column: int, text: str, attribute: int = 0) -> None:
    height, width = screen.getmaxyx()
    if 0 <= row < height and column < width:
        try:
            screen.addnstr(row, column, text, max(0, width - column - 1), attribute)
        except curses.error:
            pass  # Writing to the last cell of a window raises; nothing is lost.


def _frame(screen, title: str, footer: str) -> None:
    screen.erase()
    height, _ = screen.getmaxyx()
    _put(screen, 0, 1, title, curses.A_BOLD)
    _put(screen, height - 1, 1, footer, curses.A_DIM)


def menu(
    screen,
    title: str,
    items: list[str],
    footer: str = "Up/Down to move, Enter to choose, Esc to go back",
    selected: int = 0,
    keys: str = "",
    dim: set[int] | None = None,
) -> tuple[int, str]:
    """Shows a list and returns (index, key).

    key is "" when Enter was pressed, or one of the letters in `keys`.
    """
    dim = dim or set()
    selected = max(0, min(selected, len(items) - 1))
    top = 0
    while True:
        _frame(screen, title, footer)
        height, _ = screen.getmaxyx()
        visible = max(1, height - 4)
        if selected < top:
            top = selected
        if selected >= top + visible:
            top = selected - visible + 1
        if not items:
            _put(screen, 2, 3, "(nothing here yet)", curses.A_DIM)
        for row, index in enumerate(range(top, min(len(items), top + visible))):
            attribute = curses.A_REVERSE if index == selected else (curses.A_DIM if index in dim else 0)
            _put(screen, 2 + row, 1, ("> " if index == selected else "  ") + items[index], attribute)
        screen.refresh()

        key = screen.getch()
        if key == ESCAPE:
            raise Cancelled
        if key in (curses.KEY_UP, ord("k")) and items:
            selected = (selected - 1) % len(items)
        elif key in (curses.KEY_DOWN, ord("j")) and items:
            selected = (selected + 1) % len(items)
        elif key in ENTER and items:
            return selected, ""
        elif 0 <= key < 256 and chr(key) in keys:
            return selected, chr(key)


def choose(screen, title: str, options: list[str], default: int = 0) -> int:
    return menu(screen, title, options, selected=default)[0]


def text_input(screen, title: str, prompt: str, default: str = "", hint: str = "", error: str = "") -> str:
    value = default
    curses.curs_set(1)
    try:
        while True:
            _frame(screen, title, "Enter to accept, Esc to cancel")
            _put(screen, 2, 1, prompt)
            if hint:
                _put(screen, 3, 1, hint, curses.A_DIM)
            if error:
                _put(screen, 7, 1, error, curses.A_BOLD)
            _put(screen, 5, 1, "> " + value)
            screen.move(5, min(3 + len(value), screen.getmaxyx()[1] - 2))
            screen.refresh()

            key = screen.getch()
            if key == ESCAPE:
                raise Cancelled
            if key in ENTER:
                return value
            if key in BACKSPACE:
                value = value[:-1]
            elif 32 <= key < 127:
                value += chr(key)
    finally:
        curses.curs_set(0)


def ask(screen, title: str, prompt: str, check, default: str = "", hint: str = ""):
    """Asks until `check` accepts the answer, showing its complaint otherwise."""
    error = ""
    value = default
    while True:
        value = text_input(screen, title, prompt, value, hint, error)
        try:
            return check(value)
        except ValueError as problem:
            error = str(problem)


def pager(screen, title: str, text: str) -> None:
    lines = text.splitlines() or ["(nothing to show)"]
    top = 0
    while True:
        _frame(screen, title, "Up/Down/PgUp/PgDn to scroll, Enter or Esc to close")
        height, _ = screen.getmaxyx()
        visible = max(1, height - 4)
        for row, line in enumerate(lines[top : top + visible]):
            attribute = 0
            if line.startswith("+") and not line.startswith("+++"):
                attribute = curses.A_BOLD
            elif line.startswith("-") and not line.startswith("---"):
                attribute = curses.A_DIM
            _put(screen, 2 + row, 1, line, attribute)
        screen.refresh()

        key = screen.getch()
        limit = max(0, len(lines) - visible)
        if key == ESCAPE or key in ENTER or key == ord("q"):
            return
        if key in (curses.KEY_UP, ord("k")):
            top = max(0, top - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            top = min(limit, top + 1)
        elif key == curses.KEY_PPAGE:
            top = max(0, top - visible)
        elif key in (curses.KEY_NPAGE, ord(" ")):
            top = min(limit, top + visible)


def message(screen, title: str, text: str) -> None:
    pager(screen, title, text)
