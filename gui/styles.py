from __future__ import annotations

try:
    import customtkinter as ctk
except Exception:
    ctk = None

from gui.theme import PALETTE


def style_primary_button(btn):
    if ctk is None:
        return
    btn.configure(
        fg_color=PALETTE['primary'],
        hover_color=PALETTE['primary_hover'],
        text_color=PALETTE['text_primary'],
        corner_radius=6,
        height=32,
    )


def style_success_button(btn):
    if ctk is None:
        return
    btn.configure(
        fg_color=PALETTE['success'],
        hover_color=PALETTE['success_hover'],
        text_color=PALETTE['text_primary'],
        corner_radius=6,
        height=32,
    )


def style_warning_button(btn):
    if ctk is None:
        return
    btn.configure(
        fg_color=PALETTE['warning'],
        hover_color=PALETTE['warning_hover'],
        text_color=PALETTE['text_primary'],
        corner_radius=6,
        height=32,
    )


def style_danger_button(btn):
    if ctk is None:
        return
    btn.configure(
        fg_color=PALETTE['danger'],
        hover_color=PALETTE['danger_hover'],
        text_color=PALETTE['text_primary'],
        corner_radius=6,
        height=32,
    )


def style_secondary_button(btn):
    if ctk is None:
        return
    btn.configure(
        fg_color=PALETTE['bg_card'],
        hover_color=PALETTE['nav_hover'],
        text_color=PALETTE['text_secondary'],
        border_width=1,
        border_color=PALETTE['border'],
        corner_radius=6,
        height=32,
    )


def style_input(entry):
    if ctk is None:
        return
    entry.configure(
        fg_color=PALETTE['input_bg'],
        text_color=PALETTE['text_primary'],
        border_color=PALETTE['input_border'],
        placeholder_text_color=PALETTE['text_muted'],
        corner_radius=6,
        height=32,
    )


def style_card_frame(frame):
    if ctk is None:
        return
    frame.configure(fg_color=PALETTE['bg_card'], border_width=1, border_color=PALETTE['border'], corner_radius=8)


def style_panel_frame(frame):
    if ctk is None:
        return
    frame.configure(fg_color=PALETTE['bg_panel'], border_width=1, border_color=PALETTE['border'], corner_radius=8)
