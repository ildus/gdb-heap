# -*- coding: utf-8 -*-

import os
import textwrap
import tkinter as tk

from PIL import Image
from PIL import ImageColor
from PIL import ImageDraw

from heap import hexdump_as_bytes


class ToolTip(object):
    """ Initial code taken from here:
    http://www.voidspace.org.uk/python/weblog/arch_d7_2006_07_01.shtml
    """

    def __init__(self, widget):
        self.widget = widget
        self.window = None

    def show(self, text="", pos=None):
        self.window = tk.Toplevel(self.widget)
        self.window.wm_overrideredirect(1)

        # Get current mouse position or user specified position
        if pos is None:
            x, y = self.window.winfo_pointerxy()
        else:
            x, y = pos

        self.window.wm_geometry("+%d+%d" % (x, y))

        # Add label with yellow background
        label = tk.Label(self.window, text=text, justify=tk.LEFT, background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hide(self):
        if self.window is not None:
            self.window.destroy()


def draw_chunk_usage(chunks, range_, size=(1024, 128)):
    chunk_map = {}
    start, end = range_
    width, height = size
    line_length = 40

    def on_enter(event):
        chunk_id = canvas.find_withtag("current")[0]
        chunk = chunk_map[chunk_id]
        text = os.linesep.join([textwrap.fill(str(chunk), line_length),
                                hexdump_as_bytes(chunk.as_mem(), line_length // 2, chars_only=False)])
        tool_tip.show(text)

    def on_leave(event):
        tool_tip.hide()

    canvas = tk.Canvas(width=width, height=height)
    canvas.pack()
    canvas.tag_bind("chunk", "<Enter>", on_enter)
    canvas.tag_bind("chunk", "<Leave>", on_leave)
    tool_tip = ToolTip(canvas)

    for chunk in chunks:
        chunk_start = chunk.as_address()
        data_start = chunk.as_mem()
        chunk_end = chunk_start + chunk.chunksize()
        color = "blue" if chunk.is_inuse() else "red"
        x0 = ((chunk_start - start) * width) // (end - start)
        x1 = ((data_start - start) * width) // (end - start)
        x2 = ((chunk_end - start) * width) // (end - start)
        chunk_id = canvas.create_rectangle(x0, 0, x2, height, fill=color, tag="chunk", width=3, activefill="purple")
        canvas.create_line(x1, 0, x1, height)
        chunk_map[chunk_id] = chunk
    tk.mainloop()


def plot_chunk_usage(chunks, range_, img_size=(1024, 128)):
    start, end = range_
    width, height = img_size
    image = Image.new("RGB", img_size, "WHITE")
    draw = ImageDraw.Draw(image)
    red = ImageColor.getcolor("RED", "RGB")
    green = ImageColor.getcolor("GREEN", "RGB")
    black = ImageColor.getcolor("BLACK", "RGB")
    white = ImageColor.getcolor("WHITE", "RGB")
    for chunk in chunks:
        chunk_start = chunk.as_address()
        data_start = chunk.as_mem()
        chunk_end = chunk_start + chunk.chunksize()
        if chunk_start >= start and chunk_end <= end:
            color = green if chunk.is_inuse() else red
            # Draw chunk metadata rectangle first
            # Leftmost top corner
            x1 = ((((chunk_start - start) * width) // (end - start)), 0)
            # Rightmost bottom corner
            x2 = ((((data_start - start) * width) // (end - start)), height)
            draw.rectangle((x1, x2), white, black)
            # Then draw chunk data rectangle
            x1 = ((((data_start - start) * width) // (end - start)), 0)
            x2 = ((((chunk_end - start) * width) // (end - start)), height)
            draw.rectangle((x1, x2), color, black)
            draw.text((x1[0] + 10, x1[1] + 10), hexdump_as_bytes(data_start, 32), black)
    return image
