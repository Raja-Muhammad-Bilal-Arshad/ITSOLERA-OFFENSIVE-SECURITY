"""
progress.py
-----------
Minimal dependency-free progress bar for the CLI, used to show module
execution progress without requiring an external package like tqdm.
"""

import sys


class ProgressBar:
    def __init__(self, total, prefix="Progress", width=30):
        self.total = max(total, 1)
        self.prefix = prefix
        self.width = width
        self.current = 0

    def update(self, step_label=""):
        self.current += 1
        self._render(step_label)

    def _render(self, step_label):
        fraction = self.current / self.total
        filled = int(self.width * fraction)
        bar = "#" * filled + "-" * (self.width - filled)
        pct = int(fraction * 100)
        label = f" | {step_label}" if step_label else ""
        line = f"\r{self.prefix}: [{bar}] {pct}% ({self.current}/{self.total}){label}"
        sys.stdout.write(line.ljust(100))
        sys.stdout.flush()
        if self.current >= self.total:
            sys.stdout.write("\n")
            sys.stdout.flush()
