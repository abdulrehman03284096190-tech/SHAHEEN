from __future__ import annotations

from tkinter import ttk

PALETTE = {
    "bg_app": "#0B1120",
    "bg_sidebar": "#080E1B",
    "bg_content": "#0B1120",
    "bg_header": "#111C2E",
    "bg_panel": "#111C2E",
    "bg_card": "#111C2E",
    "bg_card_alt": "#152238",
    "bg_table": "#0E192B",
    "bg_table_alt": "#111E32",
    "bg_table_header": "#18273D",
    "border": "#1E2B40",
    "primary": "#3B82F6",
    "primary_hover": "#2563EB",
    "blue_hover": "#2563EB",
    "success": "#22C55E",
    "success_hover": "#16A34A",
    "warning": "#F59E0B",
    "warning_hover": "#D97706",
    "danger": "#EF4444",
    "danger_hover": "#DC2626",
    "info": "#3B82F6",
    "active_nav": "#1E3A8A",
    "nav_hover": "#152238",
    "text_primary": "#F1F5F9",
    "text_secondary": "#94A3B8",
    "text_label": "#94A3B8",
    "text_muted": "#64748B",
    "text_success": "#22C55E",
    "text_warning": "#F59E0B",
    "text_danger": "#EF4444",
    "input_bg": "#0E192B",
    "input_border": "#263750",
    "accent_blue": "#3B82F6",
}


def configure_ttk_theme(root) -> ttk.Style:
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(
        "TFrame",
        background=PALETTE["bg_panel"],
    )
    style.configure(
        "Treeview",
        background=PALETTE["bg_table"],
        fieldbackground=PALETTE["bg_table"],
        foreground=PALETTE["text_primary"],
        rowheight=32,
        font=("Segoe UI", 9),
        borderwidth=0,
        lightcolor=PALETTE["bg_table"],
        darkcolor=PALETTE["bg_table"],
    )
    style.configure(
        "Treeview.Heading",
        background=PALETTE["bg_table_header"],
        foreground=PALETTE["text_primary"],
        font=("Segoe UI", 9, "bold"),
        padding=(10, 8),
        relief="flat",
    )
    style.map(
        "Treeview",
        background=[("selected", PALETTE["primary"])],
        foreground=[("selected", "#FFFFFF")],
    )
    style.map(
        "Treeview.Heading",
        background=[("active", PALETTE["nav_hover"])],
    )
    style.configure(
        "Shaheen.Treeview",
        background=PALETTE["bg_table"],
        fieldbackground=PALETTE["bg_table"],
        foreground=PALETTE["text_primary"],
        rowheight=32,
        font=("Segoe UI", 9),
        borderwidth=0,
        lightcolor=PALETTE["bg_table"],
        darkcolor=PALETTE["bg_table"],
    )
    style.configure(
        "Shaheen.Treeview.Heading",
        background=PALETTE["bg_table_header"],
        foreground=PALETTE["text_primary"],
        font=("Segoe UI", 9, "bold"),
        padding=(10, 8),
        relief="flat",
    )
    style.map(
        "Shaheen.Treeview",
        background=[("selected", PALETTE["primary"])],
        foreground=[("selected", "#FFFFFF")],
    )
    style.map(
        "Shaheen.Treeview.Heading",
        background=[("active", PALETTE["nav_hover"])],
    )
    for scrollbar_style in ("TScrollbar", "Shaheen.Vertical.TScrollbar", "Shaheen.Horizontal.TScrollbar"):
        style.configure(
            scrollbar_style,
            background=PALETTE["bg_card_alt"],
            troughcolor=PALETTE["bg_table"],
            bordercolor=PALETTE["bg_table"],
            arrowcolor=PALETTE["text_secondary"],
        )
    style.configure(
        "Shaheen.TPanedwindow",
        background=PALETTE["bg_app"],
    )
    return style
