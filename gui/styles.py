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
        corner_radius=8,
        height=32,
    )


def style_success_button(btn):
    if ctk is None:
        return
    btn.configure(
        fg_color=PALETTE['success'],
        hover_color=PALETTE['success_hover'],
        text_color=PALETTE['text_primary'],
        corner_radius=8,
        height=32,
    )


def style_warning_button(btn):
    if ctk is None:
        return
    btn.configure(
        fg_color=PALETTE['warning'],
        hover_color=PALETTE['warning_hover'],
        text_color=PALETTE['text_primary'],
        corner_radius=8,
        height=32,
    )


def style_danger_button(btn):
    if ctk is None:
        return
    btn.configure(
        fg_color=PALETTE['danger'],
        hover_color=PALETTE['danger_hover'],
        text_color=PALETTE['text_primary'],
        corner_radius=8,
        height=32,
    )


def style_secondary_button(btn):
    if ctk is None:
        return
    btn.configure(
        fg_color=PALETTE['bg_card_alt'],
        hover_color=PALETTE['nav_hover'],
        text_color=PALETTE['text_secondary'],
        border_width=1,
        border_color=PALETTE['border'],
        corner_radius=8,
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
        border_width=1,
        corner_radius=8,
        height=34,
    )


def style_card_frame(frame):
    if ctk is None:
        return
    frame.configure(fg_color=PALETTE['bg_card'], border_width=1, border_color=PALETTE['border'], corner_radius=10)


def style_panel_frame(frame):
    if ctk is None:
        return
    frame.configure(fg_color=PALETTE['bg_panel'], border_width=1, border_color=PALETTE['border'], corner_radius=10)


def apply_enterprise_control_styles(root) -> None:
    if ctk is None:
        return

    def apply(widget) -> None:
        if isinstance(widget, ctk.CTkButton) and not hasattr(widget, "set_active"):
            current_color = widget.cget("fg_color")
            color_values = (
                current_color
                if isinstance(current_color, (tuple, list))
                else (current_color,)
            )
            if "transparent" not in color_values:
                if any(
                    color in color_values
                    for color in (
                        PALETTE["success"],
                        PALETTE["danger"],
                        PALETTE["warning"],
                    )
                ):
                    if PALETTE["success"] in color_values:
                        hover_color = PALETTE["success_hover"]
                    elif PALETTE["danger"] in color_values:
                        hover_color = PALETTE["danger_hover"]
                    else:
                        hover_color = PALETTE["warning_hover"]
                    widget.configure(hover_color=hover_color)
                elif PALETTE["primary"] in color_values:
                    widget.configure(
                        fg_color=PALETTE["primary"],
                        hover_color=PALETTE["primary_hover"],
                    )
                else:
                    widget.configure(
                        fg_color=PALETTE["bg_card_alt"],
                        hover_color=PALETTE["nav_hover"],
                    )
            else:
                widget.configure(hover_color=PALETTE["nav_hover"])
            widget.configure(
                corner_radius=8,
                font=("Segoe UI", 10),
                text_color_disabled=PALETTE["text_muted"],
                height=max(32, int(widget.cget("height"))),
            )
        elif isinstance(widget, ctk.CTkEntry):
            style_input(widget)
        elif isinstance(widget, ctk.CTkOptionMenu):
            widget.configure(
                fg_color=PALETTE["bg_card_alt"],
                button_color="#20334D",
                button_hover_color="#2A405E",
                text_color=PALETTE["text_primary"],
                dropdown_fg_color=PALETTE["bg_card"],
                dropdown_hover_color=PALETTE["nav_hover"],
                dropdown_text_color=PALETTE["text_primary"],
                corner_radius=8,
                height=34,
            )
        elif isinstance(widget, ctk.CTkTextbox):
            widget.configure(
                fg_color=PALETTE["input_bg"],
                text_color=PALETTE["text_primary"],
                border_color=PALETTE["input_border"],
                border_width=1,
                corner_radius=8,
            )

        for child in widget.winfo_children():
            apply(child)

    apply(root)
