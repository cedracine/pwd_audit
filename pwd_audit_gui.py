#!/usr/bin/env python3
"""
pwd_audit_gui.py — Password Audit GUI (Tkinter)
Fusionne, nettoie et audite les exports CSV Chrome/Firefox/Opera.
Tourne sur Windows 10 et Raspberry Pi (TwisterOS).

Dépendances :
  pip install zxcvbn requests
"""

import csv
import os
import re
import socket
import ssl
import sys
import hashlib
import threading
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# ── zxcvbn optionnel ─────────────────────────────────────────────────────────
try:
    from zxcvbn import zxcvbn as _zxcvbn
    HAS_ZXCVBN = True
except ImportError:
    HAS_ZXCVBN = False

# ── Constantes ────────────────────────────────────────────────────────────────
DEAD_TIMEOUT = 5
MAX_WORKERS  = 30
STRENGTH_LABELS = {0: "Très faible", 1: "Faible", 2: "Moyen", 3: "Fort", 4: "Très fort"}
COLORS = {
    "bg":       "#1a1a2e",
    "panel":    "#16213e",
    "accent":   "#e94560",
    "accent2":  "#0f3460",
    "text":     "#eaeaea",
    "muted":    "#8892a4",
    "green":    "#4ecca3",
    "yellow":   "#f5a623",
    "red":      "#e94560",
    "border":   "#2a2a4a",
    "input_bg": "#0d1b2a",
}

# ─────────────────────────────────────────────────────────────────────────────
# CSV PARSING
# ─────────────────────────────────────────────────────────────────────────────

def _ff_ts(ts_str):
    try:
        ts = int(ts_str)
        if ts > 1e12:
            ts /= 1000
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
    except Exception:
        return ""

BROWSER_FORMATS = {
    "chrome": {
        "detect": lambda h: "name" in h and "url" in h and "username" in h and "password" in h,
        "name":     lambda r: r.get("name", ""),
        "url":      lambda r: r.get("url", ""),
        "username": lambda r: r.get("username", ""),
        "password": lambda r: r.get("password", ""),
        "date":     lambda r: r.get("date_password_modified") or r.get("date_created") or "",
    },
    "firefox": {
        "detect": lambda h: "guid" in h and "timepasswordchanged" in h,
        "name":     lambda r: "",
        "url":      lambda r: r.get("url", ""),
        "username": lambda r: r.get("username", ""),
        "password": lambda r: r.get("password", ""),
        "date":     lambda r: _ff_ts(r.get("timepasswordchanged") or r.get("timecreated") or ""),
    },
}

def detect_browser(headers):
    h = {k.lower().strip() for k in headers}
    for name, fmt in BROWSER_FORMATS.items():
        if fmt["detect"](h):
            return name, fmt
    return "unknown", None

def extract_domain(url):
    url = url.strip()
    if not url:
        return ""
    url = re.sub(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", "", url)
    url = re.sub(r"^[^@]+@", "", url)
    domain = re.split(r"[/?#]", url)[0]
    domain = re.sub(r":\d+$", "", domain)
    domain = re.sub(r"^www\.", "", domain, flags=re.IGNORECASE)
    return domain.lower().strip()

def load_csv(filepath):
    entries = []
    try:
        with open(filepath, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames or []
            browser, fmt = detect_browser(headers)
            source = os.path.basename(filepath)
            if fmt is None:
                return [], f"Format non reconnu : {source}"
            for row in reader:
                row_low = {k.lower().strip(): v for k, v in row.items()}
                merged = {**row, **row_low}
                url      = fmt["url"](merged).strip()
                username = fmt["username"](merged).strip()
                password = fmt["password"](merged).strip()
                name     = fmt["name"](merged).strip()
                date_raw = fmt["date"](merged).strip()
                domain   = extract_domain(url)
                if not domain and not url:
                    continue
                entries.append({
                    "domain": domain or url, "name": name, "url": url,
                    "username": username, "password": password,
                    "date": date_raw, "source": browser,
                })
    except Exception as e:
        return [], str(e)
    return entries, None

# ─────────────────────────────────────────────────────────────────────────────
# STRENGTH
# ─────────────────────────────────────────────────────────────────────────────

def score_password(pwd):
    if not HAS_ZXCVBN or not pwd:
        return "", ""
    try:
        r = _zxcvbn(pwd[:72])  # zxcvbn hard limit = 72 chars
        s = r["score"]
        return str(s), STRENGTH_LABELS.get(s, "")
    except Exception:
        return "4", "Très fort"  # >72 chars = très fort par définition

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN CHECK
# ─────────────────────────────────────────────────────────────────────────────

def check_domain(domain):
    if not domain or "." not in domain:
        return ("dead", "invalid_domain")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="HEAD")
        try:
            kw = {"timeout": DEAD_TIMEOUT}
            if scheme == "https":
                kw["context"] = ctx
            with urllib.request.urlopen(req, **kw) as resp:
                code = resp.status
                if code in (200, 201, 301, 302, 303, 307, 308):
                    return ("alive", str(code))
                elif code == 403:
                    return ("review", "403_forbidden")
                else:
                    return ("review", f"http_{code}")
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return ("review", "403_forbidden")
            return ("review", f"http_{e.code}")
        except urllib.error.URLError as e:
            reason = str(e.reason)
            if "Name or service not known" in reason or "nodename nor servname" in reason:
                return ("dead", "NXDOMAIN")
            continue
        except socket.timeout:
            continue
        except Exception as e:
            return ("dead", str(e)[:60])
    return ("dead", "timeout")

def check_domains_threaded(domains, progress_cb, cancel_flag):
    results = {}
    total = len(domains)
    done = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_to_domain = {ex.submit(check_domain, d): d for d in domains}
        for future in as_completed(future_to_domain):
            if cancel_flag():
                ex.shutdown(wait=False, cancel_futures=True)
                break
            domain = future_to_domain[future]
            try:
                status, reason = future.result()
            except Exception as e:
                status, reason = "dead", str(e)[:60]
            results[domain] = (status, reason)
            done += 1
            progress_cb(done, total)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# SORT
# ─────────────────────────────────────────────────────────────────────────────

import functools

def final_sort(entries):
    def cmp(a, b):
        if a["domain"].lower() != b["domain"].lower():
            return -1 if a["domain"].lower() < b["domain"].lower() else 1
        da = a["date"][:10] if a["date"] else ""
        db = b["date"][:10] if b["date"] else ""
        if da == db:
            return 0
        if not da:
            return -1
        if not db:
            return 1
        return -1 if da > db else 1
    return sorted(entries, key=functools.cmp_to_key(cmp))

# ─────────────────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────────────────

class PwdAuditApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("🔐 Password Audit")
        self.configure(bg=COLORS["bg"])
        self.resizable(True, True)
        self.minsize(820, 620)

        self._csv_files  = []
        self._entries    = []
        self._cancelled  = False
        self._output_dir = tk.StringVar(value=os.path.expanduser("~"))

        self._build_ui()
        self._center()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _center(self):
        self.update_idletasks()
        w, h = 900, 700
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self, bg=COLORS["accent2"], pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔐  Password Audit", font=("Courier", 22, "bold"),
                 bg=COLORS["accent2"], fg=COLORS["accent"]).pack(side="left", padx=20)
        tk.Label(hdr, text="Chrome · Firefox · Opera → Proton Pass",
                 font=("Courier", 10), bg=COLORS["accent2"], fg=COLORS["muted"]).pack(side="left")

        # ── Notebook (tabs) ──
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook",       background=COLORS["bg"],    borderwidth=0)
        style.configure("TNotebook.Tab",   background=COLORS["panel"], foreground=COLORS["muted"],
                        padding=[14, 6],   font=("Courier", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["accent2"])],
                  foreground=[("selected", COLORS["accent"])])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=8)

        self._tab_guide  = self._make_tab(nb, "📋  Guide")
        self._tab_files  = self._make_tab(nb, "📂  Fichiers CSV")
        self._tab_audit  = self._make_tab(nb, "🔍  Audit")
        self._tab_result = self._make_tab(nb, "📊  Résultats")

        nb.add(self._tab_guide,  text="📋  Guide")
        nb.add(self._tab_files,  text="📂  Fichiers CSV")
        nb.add(self._tab_audit,  text="🔍  Audit")
        nb.add(self._tab_result, text="📊  Résultats")

        self._nb = nb
        self._build_guide()
        self._build_files()
        self._build_audit()
        self._build_result()

    def _make_tab(self, nb, _):
        f = tk.Frame(nb, bg=COLORS["bg"])
        return f

    # ── Tab 1 : Guide ─────────────────────────────────────────────────────────

    def _build_guide(self):
        f = self._tab_guide
        self._section(f, "À PROPOS")
        txt = (
            "Cet outil fusionne et nettoie les exports CSV de Chrome, Firefox et Opera.\n"
            "Il analyse la force de chaque mot de passe et détecte les domaines morts.\n"
            "Les résultats peuvent être exportés directement vers Proton Pass.\n"
        )
        self._para(f, txt)

        self._section(f, "ÉTAPES")
        steps = [
            ("1", "Exporter les CSV",
             "Chrome  →  chrome://password-manager/settings  →  Exporter\n"
             "Firefox →  about:logins  →  ⋯  →  Exporter les identifiants\n"
             "Opera   →  Paramètres  →  Avancé  →  Sécurité  →  Exporter"),
            ("2", "Ajouter les fichiers",
             "Onglet 📂 Fichiers CSV  →  bouton 'Ajouter CSV(s)'"),
            ("3", "Lancer l'audit",
             "Onglet 🔍 Audit  →  choisir le dossier de sortie  →  bouton 'Lancer l'Audit'"),
            ("4", "Consulter les résultats",
             "Onglet 📊 Résultats  →  3 fichiers générés :\n"
             "  • passwords_clean.csv   (à importer dans Proton Pass)\n"
             "  • sites_dead.csv        (comptes à supprimer)\n"
             "  • sites_to_review.csv   (à vérifier manuellement)"),
        ]
        for num, title, desc in steps:
            row = tk.Frame(f, bg=COLORS["bg"])
            row.pack(fill="x", padx=20, pady=3)
            tk.Label(row, text=num, font=("Courier", 16, "bold"),
                     bg=COLORS["accent"], fg="white", width=3, anchor="center").pack(side="left")
            col = tk.Frame(row, bg=COLORS["bg"])
            col.pack(side="left", padx=10)
            tk.Label(col, text=title, font=("Courier", 11, "bold"),
                     bg=COLORS["bg"], fg=COLORS["green"], anchor="w").pack(anchor="w")
            tk.Label(col, text=desc, font=("Courier", 9),
                     bg=COLORS["bg"], fg=COLORS["muted"], justify="left", anchor="w").pack(anchor="w")

        self._section(f, "DÉPENDANCES PYTHON")
        dep_frame = tk.Frame(f, bg=COLORS["panel"], padx=15, pady=10)
        dep_frame.pack(fill="x", padx=20, pady=4)

        zx_color = COLORS["green"] if HAS_ZXCVBN else COLORS["red"]
        zx_status = "✅  installé" if HAS_ZXCVBN else "❌  manquant"
        tk.Label(dep_frame, text=f"zxcvbn  →  {zx_status}  (scoring force des mots de passe)",
                 font=("Courier", 10), bg=COLORS["panel"], fg=zx_color).pack(anchor="w")

        if not HAS_ZXCVBN:
            tk.Label(dep_frame, text="    Installe avec :  pip install zxcvbn",
                     font=("Courier", 9), bg=COLORS["panel"], fg=COLORS["yellow"]).pack(anchor="w")

        tk.Label(dep_frame,
                 text="requests / urllib  →  ✅  stdlib (détection domaines morts)",
                 font=("Courier", 10), bg=COLORS["panel"], fg=COLORS["green"]).pack(anchor="w")

    # ── Tab 2 : Fichiers ──────────────────────────────────────────────────────

    def _build_files(self):
        f = self._tab_files
        self._section(f, "FICHIERS CSV SÉLECTIONNÉS")

        btn_row = tk.Frame(f, bg=COLORS["bg"])
        btn_row.pack(fill="x", padx=20, pady=(0, 8))
        self._btn(btn_row, "➕  Ajouter CSV(s)", self._add_files).pack(side="left", padx=(0, 8))
        self._btn(btn_row, "🗑  Vider la liste", self._clear_files, danger=True).pack(side="left")

        # Listbox
        lf = tk.Frame(f, bg=COLORS["border"], padx=1, pady=1)
        lf.pack(fill="both", expand=True, padx=20, pady=4)
        inner = tk.Frame(lf, bg=COLORS["input_bg"])
        inner.pack(fill="both", expand=True)

        sb = tk.Scrollbar(inner, bg=COLORS["panel"])
        sb.pack(side="right", fill="y")
        self._file_list = tk.Listbox(inner, yscrollcommand=sb.set,
                                     bg=COLORS["input_bg"], fg=COLORS["text"],
                                     selectbackground=COLORS["accent2"],
                                     font=("Courier", 10), borderwidth=0,
                                     highlightthickness=0, activestyle="none")
        self._file_list.pack(fill="both", expand=True)
        sb.config(command=self._file_list.yview)

        self._file_count_lbl = tk.Label(f, text="0 fichier(s) sélectionné(s)",
                                        font=("Courier", 9), bg=COLORS["bg"], fg=COLORS["muted"])
        self._file_count_lbl.pack(padx=20, anchor="w")

        # Remove selected
        self._btn(f, "➖  Retirer la sélection", self._remove_selected).pack(padx=20, pady=6, anchor="w")

    def _add_files(self):
        files = filedialog.askopenfilenames(
            title="Sélectionner les CSV",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        for fp in files:
            if fp not in self._csv_files:
                self._csv_files.append(fp)
                self._file_list.insert("end", fp)
        self._file_count_lbl.config(text=f"{len(self._csv_files)} fichier(s) sélectionné(s)")

    def _clear_files(self):
        self._csv_files.clear()
        self._file_list.delete(0, "end")
        self._file_count_lbl.config(text="0 fichier(s) sélectionné(s)")

    def _remove_selected(self):
        sel = list(self._file_list.curselection())
        for i in reversed(sel):
            self._file_list.delete(i)
            del self._csv_files[i]
        self._file_count_lbl.config(text=f"{len(self._csv_files)} fichier(s) sélectionné(s)")

    # ── Tab 3 : Audit ─────────────────────────────────────────────────────────

    def _build_audit(self):
        f = self._tab_audit

        self._section(f, "DOSSIER DE SORTIE")
        out_row = tk.Frame(f, bg=COLORS["bg"])
        out_row.pack(fill="x", padx=20, pady=(0, 12))
        tk.Entry(out_row, textvariable=self._output_dir,
                 font=("Courier", 10), bg=COLORS["input_bg"], fg=COLORS["text"],
                 insertbackground=COLORS["text"], relief="flat", bd=4).pack(side="left", fill="x", expand=True)
        self._btn(out_row, "📁", self._pick_output_dir).pack(side="left", padx=(6, 0))

        self._section(f, "OPTIONS")
        self._do_domain_check = tk.BooleanVar(value=True)
        self._chk(f, "🌐  Vérifier les domaines morts (réseau requis, ~30s–2min)",
                  self._do_domain_check)

        # Lancer
        launch_row = tk.Frame(f, bg=COLORS["bg"])
        launch_row.pack(padx=20, pady=16, anchor="w")
        self._launch_btn = self._btn(launch_row, "🚀  Lancer l'Audit", self._start_audit, big=True)
        self._launch_btn.pack(side="left")
        self._cancel_btn = self._btn(launch_row, "⛔  Annuler", self._cancel_audit, danger=True)
        self._cancel_btn.pack(side="left", padx=(10, 0))
        self._cancel_btn.config(state="disabled")

        self._section(f, "LOG")
        log_frame = tk.Frame(f, bg=COLORS["border"], padx=1, pady=1)
        log_frame.pack(fill="both", expand=True, padx=20, pady=4)
        self._log_widget = scrolledtext.ScrolledText(
            log_frame, font=("Courier", 9), bg=COLORS["input_bg"], fg=COLORS["green"],
            insertbackground=COLORS["green"], relief="flat", state="disabled",
            wrap="word", height=10,
        )
        self._log_widget.pack(fill="both", expand=True)

        # Progress
        pb_frame = tk.Frame(f, bg=COLORS["bg"])
        pb_frame.pack(fill="x", padx=20, pady=(0, 8))
        style = ttk.Style()
        style.configure("Audit.Horizontal.TProgressbar",
                        troughcolor=COLORS["panel"], background=COLORS["accent"],
                        borderwidth=0, lightcolor=COLORS["accent"], darkcolor=COLORS["accent"])
        self._progress = ttk.Progressbar(pb_frame, style="Audit.Horizontal.TProgressbar",
                                         mode="determinate", length=400)
        self._progress.pack(side="left", fill="x", expand=True)
        self._progress_lbl = tk.Label(pb_frame, text="", font=("Courier", 9),
                                      bg=COLORS["bg"], fg=COLORS["muted"], width=14)
        self._progress_lbl.pack(side="left", padx=(8, 0))

    def _pick_output_dir(self):
        d = filedialog.askdirectory(title="Dossier de sortie")
        if d:
            self._output_dir.set(d)

    # ── Tab 4 : Résultats ─────────────────────────────────────────────────────

    def _build_result(self):
        f = self._tab_result
        self._section(f, "FICHIERS GÉNÉRÉS")

        self._result_text = tk.Text(f, font=("Courier", 10), bg=COLORS["input_bg"],
                                    fg=COLORS["text"], relief="flat", state="disabled",
                                    height=6, padx=12, pady=8)
        self._result_text.pack(fill="x", padx=20, pady=4)

        self._section(f, "APERÇU — passwords_clean.csv")

        tv_frame = tk.Frame(f, bg=COLORS["border"], padx=1, pady=1)
        tv_frame.pack(fill="both", expand=True, padx=20, pady=4)

        cols = ("domain", "username", "date", "source", "score", "label", "site")
        style = ttk.Style()
        style.configure("Audit.Treeview",
                        background=COLORS["input_bg"], foreground=COLORS["text"],
                        fieldbackground=COLORS["input_bg"], rowheight=22,
                        font=("Courier", 9))
        style.configure("Audit.Treeview.Heading",
                        background=COLORS["accent2"], foreground=COLORS["accent"],
                        font=("Courier", 9, "bold"), relief="flat")
        style.map("Audit.Treeview", background=[("selected", COLORS["accent2"])])

        self._tree = ttk.Treeview(tv_frame, columns=cols, show="headings",
                                  style="Audit.Treeview")
        widths = {"domain": 160, "username": 150, "date": 90, "source": 70,
                  "score": 50, "label": 90, "site": 80}
        heads  = {"domain": "Domaine", "username": "Username", "date": "Date",
                  "source": "Browser", "score": "Score", "label": "Force", "site": "Statut"}
        for c in cols:
            self._tree.heading(c, text=heads[c])
            self._tree.column(c, width=widths[c], minwidth=40, stretch=True)

        sb_y = tk.Scrollbar(tv_frame, orient="vertical",   command=self._tree.yview)
        sb_x = tk.Scrollbar(tv_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        sb_y.pack(side="right",  fill="y")
        sb_x.pack(side="bottom", fill="x")
        self._tree.pack(fill="both", expand=True)

        btn_row = tk.Frame(f, bg=COLORS["bg"])
        btn_row.pack(padx=20, pady=8, anchor="w")
        self._btn(btn_row, "📂  Ouvrir le dossier de sortie", self._open_output).pack(side="left")

    # ── Audit logic ───────────────────────────────────────────────────────────

    def _start_audit(self):
        if not self._csv_files:
            messagebox.showwarning("Aucun fichier", "Ajoute au moins un fichier CSV d'abord.")
            self._nb.select(1)
            return

        self._cancelled = False
        self._launch_btn.config(state="disabled")
        self._cancel_btn.config(state="normal")
        self._log_clear()
        self._progress["value"] = 0
        self._progress_lbl.config(text="")

        t = threading.Thread(target=self._run_audit, daemon=True)
        t.start()

    def _cancel_audit(self):
        self._cancelled = True
        self._log("⛔  Annulation demandée…", COLORS["red"])

    def _run_audit(self):
        try:
            self.__audit()
        except Exception as e:
            self._log(f"❌  Erreur inattendue : {e}", COLORS["red"])
        finally:
            self.after(0, lambda: self._launch_btn.config(state="normal"))
            self.after(0, lambda: self._cancel_btn.config(state="disabled"))

    def __audit(self):
        # 1. Load
        self._log("📂  Chargement des fichiers CSV…")
        all_entries = []
        for fp in self._csv_files:
            entries, err = load_csv(fp)
            if err:
                self._log(f"   ⚠️  {os.path.basename(fp)} : {err}", COLORS["yellow"])
            else:
                self._log(f"   ✅  {os.path.basename(fp)} — {len(entries)} entrées  [{entries[0]['source'] if entries else '?'}]")
                all_entries.extend(entries)

        self._log(f"\n   Total brut : {len(all_entries)} entrées")

        # 2. Dedup
        seen = set()
        deduped = []
        for e in all_entries:
            key = (e["domain"], e["username"], e["password"], e["date"])
            if key not in seen:
                seen.add(key)
                deduped.append(e)
        self._log(f"   Après déduplication : {len(deduped)} entrées")

        if self._cancelled:
            return

        # 3. Strength
        self._log("\n🔑  Calcul des scores de force…")
        for e in deduped:
            s, label = score_password(e["password"])
            e["strength_score"] = s
            e["strength_label"] = label
        self._log(f"   ✅  {len(deduped)} entrées scorées")

        if self._cancelled:
            return

        # 4. Domain check
        domain_status = {}
        if self._do_domain_check.get():
            domains = list({e["domain"] for e in deduped if e["domain"]})
            self._log(f"\n🌐  Vérification de {len(domains)} domaines…")
            self._progress["maximum"] = len(domains)

            def progress_cb(done, total):
                self.after(0, lambda: self._progress.config(value=done))
                self.after(0, lambda: self._progress_lbl.config(text=f"{done}/{total}"))

            domain_status = check_domains_threaded(
                domains, progress_cb, lambda: self._cancelled
            )
            alive  = sum(1 for s, _ in domain_status.values() if s == "alive")
            dead   = sum(1 for s, _ in domain_status.values() if s == "dead")
            review = sum(1 for s, _ in domain_status.values() if s == "review")
            self._log(f"   ✅ vivants : {alive}   💀 morts : {dead}   ⚠️ à vérifier : {review}")
        else:
            self._log("\n🌐  Vérification domaines skippée.")
            for e in deduped:
                domain_status[e["domain"]] = ("skipped", "")

        for e in deduped:
            status, reason = domain_status.get(e["domain"], ("unknown", ""))
            e["site_status"] = status
            e["site_reason"] = reason

        if self._cancelled:
            return

        # 5. Sort
        sorted_entries = final_sort(deduped)

        # 6. Write
        out = self._output_dir.get()
        self._log(f"\n💾  Export vers {out}…")
        domain_counts = defaultdict(int)
        for e in deduped:
            domain_counts[e["domain"]] += 1

        clean_fields = ["domain","name","url","username","password","date","source",
                        "strength_score","strength_label","site_status","site_reason"]
        clean_path = os.path.join(out, "passwords_clean.csv")
        with open(clean_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=clean_fields)
            w.writeheader()
            for e in sorted_entries:
                w.writerow({k: e.get(k, "") for k in clean_fields})

        dead_domains   = sorted(d for d, (s, _) in domain_status.items() if s == "dead")
        review_domains = sorted(d for d, (s, _) in domain_status.items() if s == "review")

        dead_path = os.path.join(out, "sites_dead.csv")
        with open(dead_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["domain","reason","entry_count"])
            w.writeheader()
            for d in dead_domains:
                _, reason = domain_status[d]
                w.writerow({"domain": d, "reason": reason, "entry_count": domain_counts[d]})

        review_path = os.path.join(out, "sites_to_review.csv")
        with open(review_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["domain","reason","entry_count"])
            w.writeheader()
            for d in review_domains:
                _, reason = domain_status[d]
                w.writerow({"domain": d, "reason": reason, "entry_count": domain_counts[d]})

        self._log(f"   ✅  passwords_clean.csv   ({len(sorted_entries)} entrées)")
        self._log(f"   💀  sites_dead.csv        ({len(dead_domains)} domaines)")
        self._log(f"   ⚠️   sites_to_review.csv   ({len(review_domains)} domaines)")
        self._log("\n🎉  Audit terminé !", COLORS["green"])

        # Update result tab
        self.after(0, lambda: self._populate_results(sorted_entries, clean_path, dead_path, review_path,
                                                     len(dead_domains), len(review_domains)))
        self.after(0, lambda: self._nb.select(3))

    def _populate_results(self, entries, clean_path, dead_path, review_path, n_dead, n_review):
        self._result_text.config(state="normal")
        self._result_text.delete("1.0", "end")
        self._result_text.insert("end",
            f"✅  passwords_clean.csv    →  {len(entries)} entrées  →  {clean_path}\n"
            f"💀  sites_dead.csv         →  {n_dead} domaines   →  {dead_path}\n"
            f"⚠️   sites_to_review.csv    →  {n_review} domaines  →  {review_path}\n\n"
            f"⚠️   Pense à supprimer les CSV sources après import dans Proton Pass !\n"
        )
        self._result_text.config(state="disabled")

        # Populate treeview (first 500 rows for perf)
        for row in self._tree.get_children():
            self._tree.delete(row)

        status_icons = {"alive": "✅", "dead": "💀", "review": "⚠️", "skipped": "—", "unknown": "?"}
        score_colors = {"0": COLORS["red"], "1": COLORS["red"], "2": COLORS["yellow"],
                        "3": COLORS["green"], "4": COLORS["green"], "": COLORS["muted"]}

        for e in entries[:500]:
            icon = status_icons.get(e.get("site_status", ""), "?")
            self._tree.insert("", "end", values=(
                e["domain"], e["username"], e["date"], e["source"],
                e.get("strength_score", ""), e.get("strength_label", ""),
                icon + " " + e.get("site_status", ""),
            ))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _section(self, parent, text):
        row = tk.Frame(parent, bg=COLORS["bg"])
        row.pack(fill="x", padx=20, pady=(14, 4))
        tk.Label(row, text=text, font=("Courier", 10, "bold"),
                 bg=COLORS["bg"], fg=COLORS["accent"]).pack(side="left")
        tk.Frame(row, bg=COLORS["border"], height=1).pack(side="left", fill="x", expand=True, padx=(8, 0))

    def _para(self, parent, text):
        tk.Label(parent, text=text, font=("Courier", 9), bg=COLORS["bg"],
                 fg=COLORS["muted"], justify="left", anchor="w",
                 wraplength=760).pack(fill="x", padx=20, pady=(0, 6))

    def _btn(self, parent, text, cmd, danger=False, big=False):
        bg = COLORS["red"] if danger else COLORS["accent2"]
        fg = COLORS["text"]
        font = ("Courier", 11, "bold") if big else ("Courier", 10, "bold")
        b = tk.Button(parent, text=text, command=cmd,
                      bg=bg, fg=fg, activebackground=COLORS["accent"],
                      activeforeground="white", relief="flat", padx=14, pady=6,
                      font=font, cursor="hand2", borderwidth=0)
        b.bind("<Enter>", lambda e: b.config(bg=COLORS["accent"] if not danger else "#c0392b"))
        b.bind("<Leave>", lambda e: b.config(bg=bg))
        return b

    def _chk(self, parent, text, var):
        style = ttk.Style()
        style.configure("Audit.TCheckbutton",
                        background=COLORS["bg"], foreground=COLORS["text"],
                        font=("Courier", 10))
        ttk.Checkbutton(parent, text=text, variable=var,
                        style="Audit.TCheckbutton").pack(padx=28, pady=3, anchor="w")

    def _log(self, text, color=None):
        def _do():
            self._log_widget.config(state="normal")
            tag = f"c{id(color)}"
            self._log_widget.tag_config(tag, foreground=color or COLORS["green"])
            self._log_widget.insert("end", text + "\n", tag)
            self._log_widget.see("end")
            self._log_widget.config(state="disabled")
        self.after(0, _do)

    def _log_clear(self):
        self._log_widget.config(state="normal")
        self._log_widget.delete("1.0", "end")
        self._log_widget.config(state="disabled")

    def _open_output(self):
        path = self._output_dir.get()
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}"')


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = PwdAuditApp()
    app.mainloop()
