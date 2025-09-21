import tkinter as tk
from tkinter import font as tkfont, filedialog
from PIL import Image, ImageDraw, ImageFont, ImageTk
import os
import sys
import threading
import time
from queue import Queue
from modules import email_breach


class RoundedCanvas(tk.Canvas):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

    def create_rounded_rect(self, x1, y1, x2, y2, r=10, **kwargs):
        """Draw a rounded rectangle"""
        points = [
            x1 + r, y1,
            x2 - r, y1,
            x2, y1,
            x2, y1 + r,
            x2, y2 - r,
            x2, y2,
            x2 - r, y2,
            x1 + r, y2,
            x1, y2,
            x1, y2 - r,
            x1, y1 + r,
            x1, y1
        ]
        return self.create_polygon(points, smooth=True, splinesteps=36, **kwargs)


class NestedRoundedBox:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Multinedor UI - Arcade Title")
        self.root.geometry("500x500")
        self.root.resizable(False, False)

        # Outer purple container
        self.canvas = RoundedCanvas(self.root, width=500, height=500, bg="#9A6DE5", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        # Draw inner rounded container
        self.canvas.create_rounded_rect(
            20, 55, 480, 480,
            r=18,
            fill="#ECE9E7",
            outline="#000000",
            width=1
        )

        # Load arcade font for title
        font_path = os.path.join(os.path.dirname(__file__), "ARCADE_N.ttf")
        if os.path.exists(font_path):
            try:
                arcade_font = ImageFont.truetype(font_path, 30)
                img = Image.new("RGBA", (500, 60), (154, 109, 229, 0))
                draw = ImageDraw.Draw(img)
                draw.text((70, 7), "MULTINEDOR!!!", font=arcade_font, fill="#201E4B")
                self.title_img = ImageTk.PhotoImage(img)
                self.canvas.create_image(0, 0, anchor="nw", image=self.title_img)
            except Exception:
                title_font = tkfont.Font(family="Arial Black", size=28, weight="bold")
                self.canvas.create_text(250, 20, text="MULTINEDOR!!!", font=title_font, fill="#201E4B")
        else:
            title_font = tkfont.Font(family="Arial Black", size=28, weight="bold")
            self.canvas.create_text(250, 20, text="MULTINEDOR!!!", font=title_font, fill="#201E4B")

        # Subtitle
        subtitle_font = tkfont.Font(family="Arial", size=9)
        self.canvas.create_text(250, 40, text="Version 1.0 | Education use only", font=subtitle_font, fill="#F1EAD8")

        # --- Big Tool Buttons ---
        btn_defs = [
            ("PASSWORD_STRENGTH\n     CHECKER", "password_checker", "#FFC567"),
            ("NETWORK_SCANNER", "network_scanner", "#FB7DA8"),
            ("PORT_SCANNER", "port_scanner", "#FD5A46"),
            ("EMAIL_BREACH\n  DETECTOR", "email_breach_detector", "#00995E")
        ]

        btn_w, btn_h = 190, 55
        start_x, start_y = 45, 75
        gap_x, gap_y = 30, 20

        arcade_font_small = None
        if os.path.exists(font_path):
            try:
                arcade_font_small = ImageFont.truetype(font_path, 10)
            except Exception:
                arcade_font_small = None

        for i, (label, tag, color) in enumerate(btn_defs):
            row, col = divmod(i, 2)
            x1 = start_x + col * (btn_w + gap_x)
            y1 = start_y + row * (btn_h + gap_y)
            x2, y2 = x1 + btn_w, y1 + btn_h

            # Drop shadow
            self.canvas.create_rounded_rect(x1 + 5, y1 + 5, x2 + 5, y2 + 5, 20, fill="#61615d", outline="")
            # Main button
            self.canvas.create_rounded_rect(x1, y1, x2, y2, 20, fill=color, outline="#000000", width=1, tags=(tag,))

            if arcade_font_small:
                img = Image.new("RGBA", (btn_w, btn_h), (0, 0, 0, 0))
                draw = ImageDraw.Draw(img)
                bbox = draw.textbbox((0, 0), label, font=arcade_font_small)
                w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
                draw.text(((btn_w - w) // 2, (btn_h - h) // 2), label, font=arcade_font_small, fill="black")
                tk_img = ImageTk.PhotoImage(img)
                self.canvas.create_image(x1, y1, anchor="nw", image=tk_img, tags=(tag,))
                if not hasattr(self, "btn_imgs"):
                    self.btn_imgs = []
                self.btn_imgs.append(tk_img)
            else:
                btn_font = tkfont.Font(family="Arial", size=7, weight="bold")
                self.canvas.create_text((x1 + x2) // 2, (y1 + y2) // 2, text=label, font=btn_font, fill="black", tags=(tag,))

            # Bind click
            self.canvas.tag_bind(tag, "<Button-1>", lambda e, name=tag: self.on_button_click(name))

        # --- More Button ---
        btn_w, btn_h = 100, 25
        x1 = (500 - btn_w) // 2
        y1 = start_y + 2 * (55 + gap_y)  # placed below 2 rows of big buttons
        x2, y2 = x1 + btn_w, y1 + btn_h

        tag = "more_button"

        self.canvas.create_rounded_rect(x1 + 4, y1 + 4, x2 + 4, y2 + 4, 12, fill="#61615d", outline="")
        self.canvas.create_rounded_rect(x1, y1, x2, y2, 12, fill="#FFFFFF", outline="#000000", width=1, tags=(tag,))

        if arcade_font_small:
            img = Image.new("RGBA", (btn_w, btn_h), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            text = "MORE.."
            bbox = draw.textbbox((0, 0), text, font=arcade_font_small)
            w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
            draw.text(((btn_w - w) // 2, (btn_h - h) // 2), text, font=arcade_font_small, fill="black")
            tk_img = ImageTk.PhotoImage(img)
            self.canvas.create_image(x1, y1, anchor="nw", image=tk_img, tags=(tag,))
            if not hasattr(self, "btn_imgs"):
                self.btn_imgs = []
            self.btn_imgs.append(tk_img)
        else:
            btn_font = tkfont.Font(family="Arial", size=9, weight="bold")
            self.canvas.create_text((x1 + x2) // 2, (y1 + y2) // 2,
                                    text="MORE..", font=btn_font, fill="black", tags=(tag,))

        self.canvas.tag_bind(tag, "<Button-1>", lambda e, name=tag: self.on_button_click(name))

        # --- Utility Buttons (with icons) ---
        util_labels = ["Export", "Help", "About", "Settings"]
        util_tags = ["export", "help", "about", "settings"]

        icon_path = os.path.join(os.path.dirname(__file__), "icons")
        self.icons = {}
        for tag in util_tags:
            file_path = os.path.join(icon_path, f"{tag}.png")
            if os.path.exists(file_path):
                img = Image.open(file_path).resize((15, 15))
                self.icons[tag] = ImageTk.PhotoImage(img)

        self.icon_refs = []
        btn_w, btn_h = 80, 30
        gap_x = 13
        total_width = len(util_labels) * btn_w + (len(util_labels) - 1) * gap_x
        start_x = (500 - total_width) // 2 - 25
        y1 = 270
        corner_radius = 12

        for i, (label, tag) in enumerate(zip(util_labels, util_tags)):
            x1 = start_x + i * (btn_w + gap_x)
            x2, y2 = x1 + btn_w, y1 + btn_h

            # Drop shadow
            self.canvas.create_rounded_rect(x1 + 3, y1 + 3, x2 + 3, y2 + 3, corner_radius, fill="#61615d", outline="")
            # Main button background
            self.canvas.create_rounded_rect(x1, y1, x2, y2, corner_radius, fill="#d8c2fc", outline="#000000", width=1, tags=(tag,))
            # Place icon
            if tag in self.icons:
                icon_img = self.icons[tag]
                self.canvas.create_image(x1 + 14, (y1 + y2)//2, image=icon_img, anchor="w", tags=(tag,))
                self.icon_refs.append(icon_img)
            # Place text
            btn_font = tkfont.Font(family="Arial", size=8, weight="bold")
            self.canvas.create_text(x1 + 32, (y1 + y2)//2, text=label, font=btn_font, fill="black", anchor="w", tags=(tag,))
            # Bind click
            self.canvas.tag_bind(tag, "<Button-1>", lambda e, name=tag: self.on_button_click(name))

        # --- Result & Logs Label ---
        logs_icon_path = os.path.join(icon_path, "logs.png")
        if os.path.exists(logs_icon_path):
            logs_img = Image.open(logs_icon_path).resize((20, 20))
            self.logs_icon = ImageTk.PhotoImage(logs_img)
            self.canvas.create_image(45, 330, image=self.logs_icon, anchor="w")
        result_font = tkfont.Font(family="Arial", size=10, weight="bold")
        self.canvas.create_text(85, 330, text="Result & Logs", font=result_font, fill="black", anchor="w")

        # --- Result & Logs Container ---
        box_x1, box_y1 = 45, 345
        box_x2, box_y2 = 454, 460
        corner_radius = 18

        self.canvas.create_rounded_rect(box_x1 + 4, box_y1 + 4, box_x2 + 4, box_y2 + 4, r=corner_radius, fill="#61615d", outline="")
        self.canvas.create_rounded_rect(box_x1, box_y1, box_x2, box_y2, r=corner_radius, fill="#FFFFFF", outline="#000000", width=1)

        # --- Functional Text Box for Logs ---
        pad = 10
        inner_x = box_x1 + pad
        inner_y = box_y1 + pad
        inner_w = (box_x2 - box_x1) - 2 * pad
        inner_h = (box_y2 - box_y1) - 2 * pad

        self.log_box = tk.Text(self.canvas, bg="#FFFFFF", fg="black", wrap="word", bd=0, padx=6, pady=6, state="disabled")
        self.log_scroll = tk.Scrollbar(self.canvas, orient="vertical", command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=self.log_scroll.set)

        scrollbar_width = 12
        self.canvas.create_window(inner_x, inner_y, anchor="nw", window=self.log_box, width=inner_w - scrollbar_width, height=inner_h)
        self.canvas.create_window(box_x2 - pad, inner_y, anchor="ne", window=self.log_scroll, height=inner_h)

        # Logs memory
        self.logs = []

        def log_message_local(msg):
            self.logs.append(msg)
            self.log_box.config(state="normal")
            self.log_box.insert(tk.END, msg + "\n")
            self.log_box.see(tk.END)
            self.log_box.config(state="disabled")
            print(msg)

        self.log_message = log_message_local

        class TextRedirector:
            def __init__(self, widget, tag="stdout"):
                self.widget = widget
                self.tag = tag
            def write(self, msg):
                if msg.strip():
                    self.widget.config(state="normal")
                    self.widget.insert(tk.END, msg, (self.tag,))
                    self.widget.see(tk.END)
                    self.widget.config(state="disabled")
            def flush(self): pass

        sys.stdout = TextRedirector(self.log_box, "stdout")
        sys.stderr = TextRedirector(self.log_box, "stderr")

    # --- Password Checker Popup ---
    def open_password_checker(self):
        self.log_message("[UI] Opened Password Strength Checker window")
        win = tk.Toplevel(self.root)
        win.title("Password Strength Checker")
        win.geometry("420x280")
        win.resizable(False, False)
        win.lift()
        win.focus_force()

        lbl = tk.Label(win, text="Enter password to evaluate:", anchor="w")
        lbl.pack(pady=(12, 4))
        pw_entry = tk.Entry(win, show="*", width=36)
        pw_entry.pack()

        output = tk.Text(win, height=10, width=52, state="disabled", bg="#f7f7f7")
        output.pack(pady=(8, 8))

        def run_check():
            pwd = pw_entry.get()
            if not pwd:
                self.log_message("[Password Checker] No password entered")
                return

            try:
                from modules.password_checker import PasswordChecker
                checker = PasswordChecker()
                result = checker.comprehensive_check(pwd)

                lines = []
                lines.append(f"Strength: {result.get('strength_level')}")
                lines.append(f"Score: {result.get('strength_score')}")
                lines.append(f"Entropy: {result.get('entropy_bits')} bits")

                lines.append("\nDetails:")
                for d in result.get("details", []):
                    lines.append(" " + str(d))

                if result.get("recommendations"):
                    lines.append("\nRecommendations:")
                    for r in result.get("recommendations", []):
                        lines.append(" - " + str(r))

                out_text = "\n".join(lines)

                output.config(state="normal")
                output.delete("1.0", tk.END)
                output.insert(tk.END, out_text)
                output.config(state="disabled")

                for ln in out_text.splitlines():
                    self.log_message("[Password Checker] " + ln)

            except Exception as e:
                self.log_message(f"[Password Checker] Error: {e}")
                output.config(state="normal")
                output.delete("1.0", tk.END)
                output.insert(tk.END, f"Error: {e}")
                output.config(state="disabled")

        run_btn = tk.Button(win, text="Check Strength", command=run_check)
        run_btn.pack(pady=(0, 10))

    # --- Network Scanner Popup (unchanged) ---
    def open_network_scanner(self):
        self.log_message("[UI] Opened Network Scanner window")
        win = tk.Toplevel(self.root)
        win.title("Network Scanner")
        win.geometry("560x460")
        win.resizable(False, False)
        win.lift()
        win.focus_force()

        frame = tk.Frame(win)
        frame.pack(pady=(10, 6), padx=10, anchor="w")

        tk.Label(frame, text="Target (IP or network):").grid(row=0, column=0, sticky="w")
        target_entry = tk.Entry(frame, width=36)
        target_entry.grid(row=0, column=1, padx=(6,0))
        target_entry.insert(0, "192.168.1.0/24")

        tk.Label(frame, text="Ports (optional):").grid(row=1, column=0, sticky="w", pady=(6,0))
        ports_entry = tk.Entry(frame, width=36)
        ports_entry.grid(row=1, column=1, padx=(6,0), pady=(6,0))
        ports_entry.insert(0, "22,80,443")

        portscan_var = tk.IntVar(value=0)
        tk.Checkbutton(frame, text="Run port scan on hosts", variable=portscan_var).grid(row=2, column=0, columnspan=2, sticky="w")

        output = tk.Text(win, height=16, width=70, state="disabled", bg="#f7f7f7")
        output.pack(padx=10, pady=(8,4))
        scrollbar = tk.Scrollbar(win, orient="vertical", command=output.yview)
        output.configure(yscrollcommand=scrollbar.set)
        scrollbar.place(in_=output, relx=1.0, rely=0, relheight=1.0, x=-2)

        status_var = tk.StringVar(value="Idle")
        tk.Label(win, textvariable=status_var).pack()

        start_btn = tk.Button(win, text="Start Scan")
        start_btn.pack(pady=4)

        def append_output(line):
            output.config(state="normal")
            output.insert(tk.END, line + "\n")
            output.see(tk.END)
            output.config(state="disabled")
            self.log_message("[Network Scanner] " + line)

        def start_scan():
            target = target_entry.get().strip()
            do_portscan = bool(portscan_var.get())
            port_spec = ports_entry.get().strip() or "22,80,443"

            if not target:
                append_output("Please enter a valid target.")
                return

            start_btn.config(state="disabled")
            status_var.set("Scanning...")

            def worker():
                try:
                    from modules.network_scan import NetworkScanner
                    scanner = NetworkScanner()
                    from modules.port_scanner import PortScanner
                    ps = PortScanner()
                    ports = ps.generate_port_list(port_spec)

                    results = scanner.enhanced_scan_network(
                        target,
                        do_portscan=do_portscan,
                        port_list=ports,
                        port_scanner_obj=ps
                    )
                    formatted = scanner.format_scan_results(results)
                    win.after(0, lambda: append_output(formatted))
                except Exception as e:
                    win.after(0, lambda: append_output(f"Error: {e}"))
                finally:
                    win.after(0, lambda: (start_btn.config(state="normal"), status_var.set("Idle")))

            threading.Thread(target=worker, daemon=True).start()

        start_btn.config(command=start_scan)

    # --- Port Scanner Popup (fully featured) ---
    def open_port_scanner(self):
        self.log_message("[UI] Opened Port Scanner window")
        win = tk.Toplevel(self.root)
        win.title("Port Scanner")
        win.geometry("560x520")
        win.resizable(False, False)
        win.lift()
        win.focus_force()

        frame = tk.Frame(win)
        frame.pack(pady=(10, 6), padx=10, anchor="w")

        tk.Label(frame, text="Target (IP or hostname):").grid(row=0, column=0, sticky="w")
        target_entry = tk.Entry(frame, width=36)
        target_entry.grid(row=0, column=1, padx=(6,0))
        target_entry.insert(0, "127.0.0.1")

        tk.Label(frame, text="Ports (e.g. 22,80,8000-8010):").grid(row=1, column=0, sticky="w", pady=(6,0))
        ports_entry = tk.Entry(frame, width=36)
        ports_entry.grid(row=1, column=1, padx=(6,0), pady=(6,0))
        ports_entry.insert(0, "22,80,443")

        # timeout and threads fields (useful tuning)
        tk.Label(frame, text="Timeout (s):").grid(row=2, column=0, sticky="w", pady=(6,0))
        timeout_entry = tk.Entry(frame, width=12)
        timeout_entry.grid(row=2, column=1, sticky="w", pady=(6,0))
        timeout_entry.insert(0, "3.0")

        tk.Label(frame, text="Threads:").grid(row=3, column=0, sticky="w", pady=(6,0))
        threads_entry = tk.Entry(frame, width=12)
        threads_entry.grid(row=3, column=1, sticky="w", pady=(6,0))
        threads_entry.insert(0, "100")

        # detailed options: none / single / open-only / all
        tk.Label(frame, text="Detailed option:").grid(row=4, column=0, sticky="w", pady=(6,0))
        detail_mode_var = tk.StringVar(value="none")
        detail_none_rb = tk.Radiobutton(frame, text="None", variable=detail_mode_var, value="none")
        detail_single_rb = tk.Radiobutton(frame, text="Single port", variable=detail_mode_var, value="single")
        detail_open_rb = tk.Radiobutton(frame, text="Open ports only", variable=detail_mode_var, value="open")
        detail_all_rb = tk.Radiobutton(frame, text="All ports (open+closed)", variable=detail_mode_var, value="all")
        detail_none_rb.grid(row=4, column=1, sticky="w")
        detail_single_rb.grid(row=4, column=1)
        detail_open_rb.grid(row=5, column=1, sticky="w")
        detail_all_rb.grid(row=5, column=1)

        # single port entry (used when 'Single port' selected)
        tk.Label(frame, text="Single port (for Single port mode):").grid(row=6, column=0, sticky="w", pady=(6,0))
        single_port_entry = tk.Entry(frame, width=12)
        single_port_entry.grid(row=6, column=1, sticky="w", pady=(6,0))
        single_port_entry.insert(0, "")

        output = tk.Text(win, height=16, width=70, state="disabled", bg="#f7f7f7")
        output.pack(padx=10, pady=(8,4))
        scrollbar = tk.Scrollbar(win, orient="vertical", command=output.yview)
        output.configure(yscrollcommand=scrollbar.set)
        scrollbar.place(in_=output, relx=1.0, rely=0, relheight=1.0, x=-2)

        status_var = tk.StringVar(value="Idle")
        status_label = tk.Label(win, textvariable=status_var)
        status_label.pack()

        btn_frame = tk.Frame(win)
        btn_frame.pack(pady=6)
        start_btn = tk.Button(btn_frame, text="Start Scan")
        start_btn.pack(side="left", padx=6)
        export_btn = tk.Button(btn_frame, text="Export Results", state="disabled")
        export_btn.pack(side="left", padx=6)

        # caches to export or reuse
        cache = {"summary": None, "detailed_blocks": [], "structured_results": None}

        # append output helper with tagging support
        def append_output(line, tag=None):
            output.config(state="normal")
            # capture start index
            start_index = output.index("end-1c")
            output.insert(tk.END, line + "\n")
            end_index = output.index("end-1c")
            if tag:
                output.tag_add(tag, start_index, end_index)
                output.tag_config(tag, foreground="blue", underline=1)
            output.see(tk.END)
            output.config(state="disabled")
            # also log to main logs (line by line)
            for ln in (line + "\n").splitlines():
                self.log_message("[Port Scanner] " + ln)

        def export_results():
            if cache["summary"] is None:
                append_output("No results to export.")
                return
            # ask where to save
            fpath = filedialog.asksaveasfilename(title="Save port scan results", defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("CSV", "*.csv"), ("All files", "*.*")])
            if not fpath:
                return
            try:
                # combine summary + detailed blocks
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(cache["summary"] + "\n\n")
                    for b in cache["detailed_blocks"]:
                        f.write(b + "\n\n")
                append_output(f"Results exported to {fpath}")
            except Exception as e:
                append_output(f"Export failed: {e}")

        export_btn.config(command=export_results)

        # handler to run detailed single-port analysis (from clickable line)
        def run_single_port_detail(port):
            def worker():
                try:
                    from modules.port_scanner import PortScanner
                    try:
                        tval = float(timeout_entry.get())
                    except Exception:
                        tval = 3.0
                    try:
                        th = int(threads_entry.get())
                    except Exception:
                        th = 100
                    ps = PortScanner(timeout=tval, max_threads=th)
                    det = ps.detailed_port_analysis(target_entry.get().strip(), port)
                    block = ps.format_detailed(det)
                    cache["detailed_blocks"].append(block)
                    win.after(0, lambda b=block: append_output("\n" + b))
                except Exception as e:
                    win.after(0, lambda: append_output(f"Detailed analysis failed for port {port}: {e}"))
            threading.Thread(target=worker, daemon=True).start()

        # tag line and bind click safely
        def insert_clickable_open_port_line(port):
            tag = f"open_port_{port}"
            text = f"  [Open] {port}/tcp  (click for details)"
            append_output(text, tag=tag)
            # use closure to bind port value safely
            def callback(event, p=port):
                run_single_port_detail(p)
            output.tag_bind(tag, "<Button-1>", callback)

        # worker to run the full scan and optional detailed analyses
        def start_scan():
            target = target_entry.get().strip()
            spec = ports_entry.get().strip()
            mode = detail_mode_var.get()
            single_port_raw = single_port_entry.get().strip()
            try:
                timeout = float(timeout_entry.get())
            except Exception:
                timeout = 3.0
            try:
                threads = int(threads_entry.get())
            except Exception:
                threads = 100

            if not target or not spec:
                append_output("Please enter valid target and ports.")
                return

            # if single mode, validate port
            if mode == "single":
                try:
                    single_port = int(single_port_raw)
                    if not (1 <= single_port <= 65535):
                        append_output("Single port invalid.")
                        return
                except Exception:
                    append_output("Single port invalid.")
                    return
            else:
                single_port = None

            # clear UI state
            start_btn.config(state="disabled")
            export_btn.config(state="disabled")
            output.config(state="normal")
            output.delete("1.0", tk.END)
            output.config(state="disabled")
            cache["summary"] = None
            cache["detailed_blocks"] = []
            cache["structured_results"] = None
            status_var.set("Scanning...")

            def worker():
                try:
                    from modules.port_scanner import PortScanner
                    ps = PortScanner(timeout=timeout, max_threads=threads)
                    ports = ps.generate_port_list(spec)
                    # run scan
                    results = ps.scan_host_ports(target, ports)
                    summary = ps.format_scan_results(results)
                    cache["summary"] = summary
                    cache["structured_results"] = results
                    win.after(0, lambda: append_output(summary))

                    # clickable open ports
                    open_ports = [ent['port'] for ent in results.get("open_ports", [])]
                    if open_ports:
                        win.after(0, lambda: append_output("\nOpen ports (click to view details):"))
                        for p in open_ports:
                            # insert clickable line for each open port
                            win.after(0, lambda p=p: insert_clickable_open_port_line(p))
                    else:
                        win.after(0, lambda: append_output("\nNo open ports found."))

                    # handle detailed modes
                    if mode == "single" and single_port is not None:
                        win.after(0, lambda: append_output(f"\nRunning detailed analysis for port {single_port}..."))
                        try:
                            det = ps.detailed_port_analysis(target, single_port)
                            block = ps.format_detailed(det)
                        except Exception as e:
                            block = f"Port {single_port}: detailed analysis error: {e}"
                        cache["detailed_blocks"].append(block)
                        win.after(0, lambda b=block: append_output("\n" + b))
                    elif mode == "open":
                        if open_ports:
                            win.after(0, lambda: append_output("\nGathering detailed info for open ports..."))
                            # analyze open ports in parallel with bounded pool
                            q = Queue()
                            for p in open_ports:
                                q.put(p)
                            threads_list = []
                            pool_size = min(20, max(1, len(open_ports)))
                            def detail_worker():
                                while not q.empty():
                                    try:
                                        p = q.get_nowait()
                                    except Exception:
                                        break
                                    try:
                                        det = ps.detailed_port_analysis(target, p)
                                        block = ps.format_detailed(det)
                                    except Exception as e:
                                        block = f"Port {p}: detailed analysis error: {e}"
                                    cache["detailed_blocks"].append(block)
                                    win.after(0, lambda b=block: append_output("\n" + b))
                                    q.task_done()
                            for _ in range(pool_size):
                                t = threading.Thread(target=detail_worker, daemon=True)
                                threads_list.append(t)
                                t.start()
                            for t in threads_list:
                                t.join()
                        else:
                            win.after(0, lambda: append_output("\nNo open ports to analyze."))
                    elif mode == "all":
                        all_ports = [ent['port'] for ent in results.get("open_ports", [])] + [ent['port'] for ent in results.get("closed_ports", [])]
                        all_ports = sorted(set(all_ports))
                        if all_ports:
                            win.after(0, lambda: append_output("\nGathering detailed info for all ports..."))
                            # analyze all ports in parallel with bounded pool
                            q = Queue()
                            for p in all_ports:
                                q.put(p)
                            threads_list = []
                            pool_size = min(20, max(1, len(all_ports)))
                            def detail_worker_all():
                                while not q.empty():
                                    try:
                                        p = q.get_nowait()
                                    except Exception:
                                        break
                                    try:
                                        det = ps.detailed_port_analysis(target, p)
                                        block = ps.format_detailed(det)
                                    except Exception as e:
                                        block = f"Port {p}: detailed analysis error: {e}"
                                    cache["detailed_blocks"].append(block)
                                    win.after(0, lambda b=block: append_output("\n" + b))
                                    q.task_done()
                            for _ in range(pool_size):
                                t = threading.Thread(target=detail_worker_all, daemon=True)
                                threads_list.append(t)
                                t.start()
                            for t in threads_list:
                                t.join()
                        else:
                            win.after(0, lambda: append_output("\nNo ports to analyze."))
                    # enable export
                    win.after(0, lambda: export_btn.config(state="normal"))
                except Exception as e:
                    win.after(0, lambda: append_output(f"Error: {e}"))
                finally:
                    win.after(0, lambda: (start_btn.config(state="normal"), status_var.set("Idle")))

            threading.Thread(target=worker, daemon=True).start()

        start_btn.config(command=start_scan)

    # --- Email Breach Detector popup (ADDED) ---
    def open_email_breach_detector(self):
        self.log_message("[UI] Opened Email Breach Detector window")
        win = tk.Toplevel(self.root)
        win.title("Email Breach Detector")
        win.geometry("560x500")
        win.resizable(False, False)
        win.lift()
        win.focus_force()

        # Try to import backend functions from email_breach_tool (best-effort)
        try:
            # backend module expected to provide these functions:
            # run_email_breach(email, provider, force_refresh) -> (report_text, breaches, error)
            # check_pwned_password(password) -> (found, count, error)
            # get_api_key(provider) and set_api_key(provider, key)
            from email_breach_tool import run_email_breach, check_pwned_password, get_api_key, set_api_key
            backend_available = True
        except Exception as exc:
            backend_available = False
            backend_import_error = exc

        if not backend_available:
            tk.Label(win, text=f"Backend import error: {backend_import_error}", fg="red").pack(pady=20)
            self.log_message(f"[Email Breach] Backend import error: {backend_import_error}")
            return

        # Input frame
        frame = tk.Frame(win)
        frame.pack(pady=10, padx=10, anchor="w")

        tk.Label(frame, text="Email:").grid(row=0, column=0, sticky="w")
        email_entry = tk.Entry(frame, width=36)
        email_entry.grid(row=0, column=1, padx=6)
        email_entry.insert(0, "")

        tk.Label(frame, text="Password (HIBP check):").grid(row=1, column=0, sticky="w", pady=(6,0))
        pwd_entry = tk.Entry(frame, width=36, show="*")
        pwd_entry.grid(row=1, column=1, padx=6, pady=(6,0))

        tk.Label(frame, text="Provider:").grid(row=2, column=0, sticky="w", pady=(6,0))
        provider_var = tk.StringVar(value="local")
        providers = [("Local DB", "local"), ("LeakCheck API", "leakcheck"), ("BreachDirectory", "breachdirectory")]
        for i, (text, val) in enumerate(providers):
            tk.Radiobutton(frame, text=text, variable=provider_var, value=val).grid(row=2, column=i+1, sticky="w")

        # Output Text
        output = tk.Text(win, height=18, width=70, state="disabled", bg="#f7f7f7")
        output.pack(padx=10, pady=(8,4))
        scrollbar = tk.Scrollbar(win, orient="vertical", command=output.yview)
        output.configure(yscrollcommand=scrollbar.set)
        scrollbar.place(in_=output, relx=1.0, rely=0, relheight=1.0, x=-2)

        # Buttons
        btn_frame = tk.Frame(win)
        btn_frame.pack(pady=6)
        check_email_btn = tk.Button(btn_frame, text="Check Email")
        check_pwd_btn = tk.Button(btn_frame, text="Check Password")
        export_btn = tk.Button(btn_frame, text="Export Result", state="disabled")
        key_btn = tk.Button(btn_frame, text="Manage API Keys")
        for b in (check_email_btn, check_pwd_btn, export_btn, key_btn):
            b.pack(side="left", padx=4)

        cache = {"last_report": ""}

        def append_output(text: str):
            output.config(state="normal")
            output.insert(tk.END, text + "\n")
            output.see(tk.END)
            output.config(state="disabled")
            for ln in text.splitlines():
                self.log_message("[Email Breach] " + ln)

        # Run email check (uses backend run_email_breach)
        def run_check_email():
            email = email_entry.get().strip()
            prov = provider_var.get()
            if not email:
                append_output("Enter an email first.")
                return

            append_output(f"Running {prov} check for {email} ...")
            # run in background thread
            def worker():
                try:
                    rpt, breaches, err = run_email_breach(email, provider=prov, force_refresh=True)
                    cache["last_report"] = rpt
                    win.after(0, lambda: output.config(state="normal"))
                    win.after(0, lambda: output.delete("1.0", tk.END))
                    win.after(0, lambda: output.insert(tk.END, rpt))
                    win.after(0, lambda: output.config(state="disabled"))
                    win.after(0, lambda: export_btn.config(state="normal"))
                    # also log lines
                    for ln in rpt.splitlines():
                        self.log_message("[Email Breach] " + ln)
                except Exception as e:
                    win.after(0, lambda: append_output(f"Email check failed: {e}"))

            threading.Thread(target=worker, daemon=True).start()

        # Run password check (HIBP Pwned Passwords)
        def run_check_pwd():
            pwd = pwd_entry.get()
            if not pwd:
                append_output("Enter a password first.")
                return
            append_output("Checking password against HIBP Pwned Passwords (k-anonymity)...")
            def worker():
                try:
                    found, cnt, err = check_pwned_password(pwd)
                    if err:
                        win.after(0, lambda: append_output(f"Password check error: {err}"))
                    else:
                        if found:
                            win.after(0, lambda: append_output(f"Password FOUND in breaches — seen {cnt} times!"))
                        else:
                            win.after(0, lambda: append_output("Password NOT found in known breaches."))
                except Exception as e:
                    win.after(0, lambda: append_output(f"Password check failed: {e}"))
            threading.Thread(target=worker, daemon=True).start()

        # Export result
        def run_export():
            if not cache["last_report"]:
                append_output("No report to export. Run a check first.")
                return
            fpath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
            if not fpath:
                return
            try:
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(cache["last_report"])
                append_output(f"Exported report to {fpath}")
            except Exception as e:
                append_output(f"Export failed: {e}")

        # Manage keys popup
        def run_manage_keys():
            k_win = tk.Toplevel(win)
            k_win.title("Manage API Keys")
            k_win.geometry("520x140")
            k_win.resizable(False, False)

            tk.Label(k_win, text="LeakCheck API Key:").grid(row=0, column=0, sticky="w", padx=8, pady=8)
            leak_entry = tk.Entry(k_win, width=60)
            leak_entry.grid(row=0, column=1, padx=8, pady=8)
            try:
                leak_entry.insert(0, get_api_key("leakcheck") or "")
            except Exception:
                leak_entry.insert(0, "")

            tk.Label(k_win, text="BreachDirectory API Key:").grid(row=1, column=0, sticky="w", padx=8, pady=4)
            bd_entry = tk.Entry(k_win, width=60)
            bd_entry.grid(row=1, column=1, padx=8, pady=4)
            try:
                bd_entry.insert(0, get_api_key("breachdirectory") or "")
            except Exception:
                bd_entry.insert(0, "")

            def save_keys():
                try:
                    set_api_key("leakcheck", leak_entry.get() or None)
                    set_api_key("breachdirectory", bd_entry.get() or None)
                    append_output("API keys updated and saved to settings.")
                except Exception as e:
                    append_output(f"Failed to save keys: {e}")
                k_win.destroy()

            def clear_keys():
                try:
                    set_api_key("leakcheck", None)
                    set_api_key("breachdirectory", None)
                    append_output("API keys cleared from settings.")
                except Exception as e:
                    append_output(f"Failed to clear keys: {e}")
                k_win.destroy()

            btnf = tk.Frame(k_win)
            btnf.grid(row=2, column=0, columnspan=2, pady=8)
            tk.Button(btnf, text="Save", command=save_keys).pack(side="left", padx=8)
            tk.Button(btnf, text="Clear", command=clear_keys).pack(side="left", padx=8)
            tk.Button(btnf, text="Close", command=k_win.destroy).pack(side="left", padx=8)

        check_email_btn.config(command=run_check_email)
        check_pwd_btn.config(command=run_check_pwd)
        export_btn.config(command=run_export)
        key_btn.config(command=run_manage_keys)

    def on_button_click(self, name):
        self.log_message(f"Clicked: {name}")

        if name == "password_checker":
            self.open_password_checker()
        elif name == "network_scanner":
            self.open_network_scanner()
        elif name == "port_scanner":
            self.open_port_scanner()
        elif name == "email_breach_detector":
            # open the newly added email breach popup
            self.open_email_breach_detector()
        elif name == "more_button":
            self.log_message("More button clicked!")
        elif name == "export":
            self.log_message("Export clicked!")
        elif name == "help":
            self.log_message("Help clicked!")
        elif name == "about":
            self.log_message("About clicked!")
        elif name == "settings":
            self.log_message("Settings clicked!")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = NestedRoundedBox()
    app.run()
