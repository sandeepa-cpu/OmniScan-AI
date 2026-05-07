# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Policy helper for ``--gen-shell``.

OmniScan-AI does not generate reverse-shell or bind-shell one-liners. Use
scope-approved methods and isolated labs for execution proofs.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel


def print_shell_policy(console: Console) -> None:
    console.print(
        Panel.fit(
            "[bold]--gen-shell[/bold]\n\n"
            "This project does not emit reverse-shell, bind-shell, or similar "
            "post-exploitation payloads. For authorized work, document findings "
            "and use your engagement-approved tooling in controlled environments.",
            title="Policy",
            border_style="yellow",
        )
    )
