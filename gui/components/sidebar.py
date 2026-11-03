from __future__ import annotations

import math
from collections.abc import Callable
from functools import lru_cache

import customtkinter as ctk
from PIL import Image, ImageDraw

SIDEBAR_BACKGROUND = "#080E1B"
SIDEBAR_HOVER = "#152238"
SIDEBAR_ACTIVE = "#3B82F6"
SIDEBAR_ACTIVE_HOVER = "#3478E8"
SIDEBAR_TEXT = "#F1F5F9"
SIDEBAR_SECONDARY = "#94A3B8"
SIDEBAR_ICON = "#8295B2"
SIDEBAR_DIVIDER = "#1E2B40"
SIDEBAR_WIDTH = 272

_ICON_SCALE = 3
_ICON_SIZE = 24


@lru_cache(maxsize=24)
def _icon_bitmap(name: str, color: str) -> Image.Image:
    scale = _ICON_SCALE
    image = Image.new("RGBA", (_ICON_SIZE * scale, _ICON_SIZE * scale))
    draw = ImageDraw.Draw(image)

    def point(x: float, y: float) -> tuple[int, int]:
        return round(x * scale), round(y * scale)

    def line(points: list[tuple[float, float]], width: int = 2) -> None:
        draw.line(
            [point(x, y) for x, y in points],
            fill=color,
            width=width * scale,
            joint="curve",
        )

    def circle(x: float, y: float, radius: float, fill: bool = False) -> None:
        left, top = point(x - radius, y - radius)
        right, bottom = point(x + radius, y + radius)
        if fill:
            draw.ellipse((left, top, right, bottom), fill=color)
        else:
            draw.ellipse(
                (left, top, right, bottom),
                outline=color,
                width=2 * scale,
            )

    if name == "dashboard":
        for box in ((3, 3, 10, 10), (14, 3, 21, 8), (3, 14, 10, 21), (14, 12, 21, 21)):
            draw.rounded_rectangle(
                tuple(value * scale for value in box),
                radius=1.2 * scale,
                outline=color,
                width=2 * scale,
            )
    elif name == "live":
        line([(2, 12), (6, 12), (8, 8), (11, 17), (14, 5), (17, 15), (19, 11), (22, 11)])
    elif name == "network":
        line([(6, 6), (17, 7), (18, 18), (6, 18), (6, 6)])
        line([(6, 6), (12, 12), (17, 7)])
        line([(6, 18), (12, 12), (18, 18)])
        for x, y in ((6, 6), (17, 7), (12, 12), (6, 18), (18, 18)):
            circle(x, y, 2.2, fill=True)
    elif name == "alerts":
        line([(12, 2.5), (20, 5.5), (19, 12), (17, 16), (12, 21), (7, 16), (5, 12), (4, 5.5), (12, 2.5)])
        line([(12, 7), (12, 13)])
        circle(12, 17, 0.8, fill=True)
    elif name == "reports":
        line([(7, 3), (14, 3), (19, 8), (19, 21), (5, 21), (5, 3), (7, 3)])
        line([(14, 3), (14, 8), (19, 8)])
        line([(8, 17), (8, 14), (11, 14), (11, 17), (8, 17)])
        line([(13, 17), (13, 12), (16, 12), (16, 17)])
    elif name == "settings":
        for angle in range(0, 360, 45):
            radians = math.radians(angle)
            line(
                [
                    (12 + math.cos(radians) * 7, 12 + math.sin(radians) * 7),
                    (12 + math.cos(radians) * 9.5, 12 + math.sin(radians) * 9.5),
                ],
                width=2,
            )
        circle(12, 12, 7)
        circle(12, 12, 2.8)
    elif name == "brand":
        line([(12, 2), (20, 5), (19, 13), (16, 18), (12, 22), (8, 18), (5, 13), (4, 5), (12, 2)])
        line([(8, 9), (12, 12), (16, 8)])
        line([(12, 12), (12, 17)])
        for x, y in ((8, 9), (16, 8), (12, 17)):
            circle(x, y, 1.25, fill=True)

    return image.resize((_ICON_SIZE * 2, _ICON_SIZE * 2), Image.Resampling.LANCZOS)


def _icon_image(name: str, color: str, size: int = 20) -> ctk.CTkImage:
    bitmap = _icon_bitmap(name, color)
    return ctk.CTkImage(light_image=bitmap, dark_image=bitmap, size=(size, size))


class BrandHeader(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass) -> None:
        super().__init__(master, fg_color="transparent", corner_radius=0)
        self.grid_columnconfigure(1, weight=1)
        logo_tile = ctk.CTkFrame(
            self,
            width=44,
            height=44,
            fg_color="#13213A",
            corner_radius=11,
        )
        logo_tile.grid(row=0, column=0, rowspan=2, padx=(0, 12), sticky="w")
        logo_tile.grid_propagate(False)
        ctk.CTkLabel(
            logo_tile,
            text="",
            image=_icon_image("brand", SIDEBAR_ACTIVE, 26),
        ).place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            self,
            text="SHAHEEN",
            text_color=SIDEBAR_TEXT,
            font=ctk.CTkFont(family="Segoe UI", size=19, weight="bold"),
            anchor="w",
        ).grid(row=0, column=1, sticky="sw")
        ctk.CTkLabel(
            self,
            text="NETWORK TRAFFIC ANALYSIS",
            text_color=SIDEBAR_SECONDARY,
            font=ctk.CTkFont(family="Segoe UI", size=8, weight="bold"),
            anchor="w",
        ).grid(row=1, column=1, sticky="nw", pady=(3, 0))


class NavigationItem(ctk.CTkButton):
    def __init__(
        self,
        master: ctk.CTkBaseClass,
        *,
        route: str,
        label: str,
        icon: str,
        command: Callable[[], None],
    ) -> None:
        self.route = route
        self._active = False
        self._icon_images = {
            "inactive": _icon_image(icon, SIDEBAR_ICON),
            "hover": _icon_image(icon, SIDEBAR_TEXT),
            "active": _icon_image(icon, SIDEBAR_TEXT),
        }
        super().__init__(
            master,
            text=label,
            image=self._icon_images["inactive"],
            compound="left",
            anchor="w",
            height=42,
            corner_radius=9,
            border_spacing=12,
            fg_color="transparent",
            hover_color=SIDEBAR_HOVER,
            text_color=SIDEBAR_SECONDARY,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=command,
        )
        for widget in (self, self._canvas, self._text_label, self._image_label):
            widget.bind("<Enter>", self._on_nav_hover_enter, add="+")
            widget.bind("<Leave>", self._on_nav_hover_leave, add="+")

    def set_active(self, active: bool) -> None:
        self._active = active
        self.configure(
            fg_color=SIDEBAR_ACTIVE if active else "transparent",
            hover_color=SIDEBAR_ACTIVE_HOVER if active else SIDEBAR_HOVER,
            text_color=SIDEBAR_TEXT if active else SIDEBAR_SECONDARY,
            image=self._icon_images["active" if active else "inactive"],
        )

    def _on_nav_hover_enter(self, _event: object) -> None:
        if not self._active:
            self.configure(
                text_color=SIDEBAR_TEXT,
                image=self._icon_images["hover"],
            )

    def _on_nav_hover_leave(self, _event: object) -> None:
        if not self._active:
            self.configure(
                text_color=SIDEBAR_SECONDARY,
                image=self._icon_images["inactive"],
            )


class NavigationSection(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, title: str) -> None:
        super().__init__(master, fg_color="transparent", corner_radius=0)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self,
            text=title,
            text_color="#71829C",
            font=ctk.CTkFont(family="Segoe UI", size=9, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=12, pady=(13, 7))
        self._next_row = 1

    def add_item(
        self,
        *,
        route: str,
        label: str,
        icon: str,
        command: Callable[[], None],
    ) -> NavigationItem:
        item = NavigationItem(
            self,
            route=route,
            label=label,
            icon=icon,
            command=command,
        )
        item.grid(
            row=self._next_row,
            column=0,
            sticky="ew",
            padx=4,
            pady=2,
        )
        self._next_row += 1
        return item


class SidebarFooter(ctk.CTkFrame):
    def __init__(
        self,
        master: ctk.CTkBaseClass,
        *,
        version: str,
        product_name: str,
    ) -> None:
        super().__init__(master, fg_color="transparent", corner_radius=0)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkFrame(self, height=1, fg_color=SIDEBAR_DIVIDER).grid(
            row=0, column=0, sticky="ew", pady=(0, 14),
        )
        footer_text = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        footer_text.grid(row=1, column=0, sticky="ew")
        ctk.CTkLabel(
            footer_text,
            text=f"SHAHEEN  {version}",
            text_color=SIDEBAR_SECONDARY,
            font=ctk.CTkFont(family="Segoe UI", size=9, weight="bold"),
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            footer_text,
            text=product_name,
            text_color="#71829C",
            font=ctk.CTkFont(family="Segoe UI", size=9),
            anchor="w",
        ).pack(anchor="w", pady=(4, 0))


class Sidebar(ctk.CTkFrame):
    def __init__(
        self,
        master: ctk.CTkBaseClass,
        *,
        version: str,
        product_name: str = "Network Analysis System",
    ) -> None:
        super().__init__(
            master,
            width=SIDEBAR_WIDTH,
            corner_radius=0,
            fg_color=SIDEBAR_BACKGROUND,
        )
        self.grid_propagate(False)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.brand_header = BrandHeader(self)
        self.brand_header.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=20,
            pady=(24, 18),
        )

        self.navigation = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            corner_radius=0,
            scrollbar_button_color="#24344E",
            scrollbar_button_hover_color="#344967",
        )
        self.navigation.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 8))
        self.navigation.grid_columnconfigure(0, weight=1)
        self.navigation.bind("<Configure>", self._schedule_scrollbar_sync, add="+")
        self.navigation._parent_canvas.bind(
            "<Configure>",
            self._schedule_scrollbar_sync,
            add="+",
        )

        self.footer = SidebarFooter(
            self,
            version=version,
            product_name=product_name,
        )
        self.footer.grid(
            row=2,
            column=0,
            sticky="ew",
            padx=20,
            pady=(8, 20),
        )

    def fit_navigation(self) -> None:
        self.after_idle(self._sync_navigation_scrollbar)

    def _schedule_scrollbar_sync(self, _event: object) -> None:
        self.after_idle(self._sync_navigation_scrollbar)

    def _sync_navigation_scrollbar(self) -> None:
        canvas = self.navigation._parent_canvas
        bounds = canvas.bbox("all")
        if bounds is None or canvas.winfo_height() <= 1:
            return
        content_height = bounds[3] - bounds[1]
        needs_scrollbar = content_height > canvas.winfo_height() + 1
        scrollbar = self.navigation._scrollbar
        if needs_scrollbar and not scrollbar.winfo_ismapped():
            scrollbar.grid()
        elif not needs_scrollbar and scrollbar.winfo_ismapped():
            scrollbar.grid_remove()

    def add_section(self, title: str) -> NavigationSection:
        section = NavigationSection(self.navigation, title)
        section.pack(fill="x")
        return section
