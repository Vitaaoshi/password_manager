"""密码管理器现代GUI界面 - CustomTkinter实现"""
import sys, os, time, webbrowser, threading
from pathlib import Path
from typing import Optional
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk
from PIL import Image

# Windows 任务栏图标修复：让系统将此窗口识别为独立应用而非 Python 子进程
if sys.platform == "win32":
    import ctypes
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PasswordManager.App")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from config import (DB_DIR, DB_PATH, DEFAULT_CHARSET, ENGLISH_STYLES, CATEGORIES,
                    PASSWORD_EXPIRY_DAYS, CLIPBOARD_CLEAR_SECONDS, PAGINATION_PAGE_SIZE)
from crypto_utils import (derive_key, init_vault, verify_master_password,
                          get_vault_paths, generate_salt, RateLimiter)
from db_utils import VaultDB
from generators import (generate_random_number, generate_random_digit_string,
                        generate_password, calculate_password_strength, generate_username)
from backup import export_backup, import_backup, export_json_plain, export_csv

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── 设计常量 ──
_SIDEBAR_W = 190
_CARD_RADIUS = 12
_BTN_RADIUS = 8
_FONT = "微软雅黑"
_MONO = "Consolas"
_ICON_DIR = Path(__file__).parent
_ICON_ICO = _ICON_DIR / "app_icon.ico"
_ICON_PNG = _ICON_DIR / "app_icon.png"


class PasswordManagerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("密码管理器")
        self.geometry("1150x720")
        self.minsize(950, 620)
        if _ICON_ICO.exists():
            self.iconbitmap(_ICON_ICO)
        self.db: Optional[VaultDB] = None
        self.key: Optional[bytearray] = None
        self.last_activity = time.time()
        self.idle_timeout = 300
        self.current_frame: Optional[ctk.CTkFrame] = None
        self.rate_limiter = RateLimiter()
        self.show_password = False
        self.is_first_run = False
        # 批量模式状态
        self.batch_mode = False
        self.selected_ids: set = set()
        # 搜索关键词（用于高亮）
        self.search_keyword = ""
        self._show_auth_screen()
        self._bind_shortcuts()

    # ════════════════════════════════════════
    #  快捷键
    # ════════════════════════════════════════
    def _bind_shortcuts(self):
        self.bind("<Control-f>", lambda e: self._focus_search())
        self.bind("<Control-F>", lambda e: self._focus_search())
        self.bind("<Control-l>", lambda e: self._lock_session())
        self.bind("<Control-L>", lambda e: self._lock_session())

    def _focus_search(self):
        if hasattr(self, 'search_entry') and self.search_entry.winfo_exists():
            self.search_entry.focus()

    # ════════════════════════════════════════
    #  认证界面
    # ════════════════════════════════════════
    def _show_auth_screen(self):
        self._clear_frame()
        self.geometry("480x420")
        frame = ctk.CTkFrame(self, corner_radius=20, fg_color=("gray92", "gray17"))
        frame.pack(expand=True, fill="both", padx=36, pady=36)

        ctk.CTkLabel(frame, text="密码管理器", font=(_FONT, 26, "bold")).pack(pady=(36, 6))
        ctk.CTkLabel(frame, text="安全存储与生成工具", font=(_FONT, 12),
                     text_color=("gray40", "gray65")).pack(pady=(0, 28))

        salt_path, test_path = get_vault_paths()
        self.is_first_run = not (salt_path.exists() and test_path.exists())

        if self.is_first_run:
            ctk.CTkLabel(frame, text="首次使用，请设置主密码", font=(_FONT, 13)).pack()
            ctk.CTkLabel(frame, text="要求: 长度≥12，包含大小写、数字、特殊符号中至少3类",
                         font=(_FONT, 11), text_color=("gray40", "gray65")).pack(pady=(2, 10))
        else:
            ctk.CTkLabel(frame, text="请输入主密码", font=(_FONT, 13)).pack(pady=(0, 10))

        self.pwd_entry = ctk.CTkEntry(frame, placeholder_text="主密码", show="*",
                                       width=300, height=38, font=(_FONT, 13))
        self.pwd_entry.pack(pady=(0, 8))
        self.pwd_entry.focus()
        self.pwd_entry.bind("<Return>", lambda e: self._handle_auth())

        self.confirm_entry = ctk.CTkEntry(frame, placeholder_text="确认主密码", show="*",
                                           width=300, height=38, font=(_FONT, 13))
        if self.is_first_run:
            self.confirm_entry.pack(pady=(0, 8))
            self.confirm_entry.bind("<Return>", lambda e: self._handle_auth())
        else:
            self.confirm_entry.pack_forget()

        self.error_label = ctk.CTkLabel(frame, text="", text_color="#e74c3c", font=(_FONT, 11))
        self.error_label.pack(pady=(4, 4))

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=(8, 8))
        self.auth_btn = ctk.CTkButton(btn_frame, text="验证", width=130, height=36,
                                       font=(_FONT, 13, "bold"), corner_radius=_BTN_RADIUS,
                                       command=self._handle_auth)
        self.auth_btn.pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="显示密码", width=90, height=36,
                       fg_color="transparent", border_width=1,
                       font=(_FONT, 11), corner_radius=_BTN_RADIUS,
                       command=self._toggle_password_visibility).pack(side="left", padx=6)
        self.current_frame = frame

    def _toggle_password_visibility(self):
        self.show_password = not self.show_password
        show = "" if self.show_password else "*"
        self.pwd_entry.configure(show=show)
        self.confirm_entry.configure(show=show)

    def _handle_auth(self):
        mp = self.pwd_entry.get().strip()
        if not mp:
            self.error_label.configure(text="密码不能为空"); return
        if self.is_first_run:
            confirm = self.confirm_entry.get().strip()
            if mp != confirm:
                self.error_label.configure(text="两次输入的密码不一致"); return
            ok, msg = self._validate_master_password(mp)
            if not ok:
                self.error_label.configure(text=msg); return
            self.auth_btn.configure(state="disabled", text="初始化中...")
            self.update()
            def init():
                try:
                    salt, payload = init_vault(mp)
                    sp, tp = get_vault_paths()
                    sp.write_bytes(salt); tp.write_bytes(payload)
                    self.key = bytearray(derive_key(mp, salt))
                    self.after(0, lambda: self._on_auth_success())
                except Exception as e:
                    self.after(0, lambda: self.error_label.configure(text=f"初始化失败: {e}"))
                    self.after(0, lambda: self.auth_btn.configure(state="normal", text="验证"))
            threading.Thread(target=init, daemon=True).start()
        else:
            ok, remaining = self.rate_limiter.check_and_wait()
            if not ok:
                self.error_label.configure(text=f"失败次数过多，请等待 {remaining:.0f} 秒"); return
            self.auth_btn.configure(state="disabled", text="验证中...")
            self.update()
            def verify():
                try:
                    sp, tp = get_vault_paths()
                    salt = sp.read_bytes(); payload = tp.read_bytes()
                    if verify_master_password(mp, salt, payload):
                        self.rate_limiter.record_success()
                        self.key = bytearray(derive_key(mp, salt))
                        self.after(0, lambda: self._on_auth_success())
                    else:
                        self.rate_limiter.record_failure()
                        n = self.rate_limiter.get_failure_count()
                        self.after(0, lambda: self.error_label.configure(text=f"主密码错误 ({n}次)"))
                        self.after(0, lambda: self.auth_btn.configure(state="normal", text="验证"))
                except Exception as e:
                    self.after(0, lambda: self.error_label.configure(text=f"验证失败: {e}"))
                    self.after(0, lambda: self.auth_btn.configure(state="normal", text="验证"))
            threading.Thread(target=verify, daemon=True).start()

    def _validate_master_password(self, pw):
        if len(pw) < 12:
            return False, "主密码长度至少12位"
        cats = sum([any(c.isupper() for c in pw), any(c.islower() for c in pw),
                    any(c.isdigit() for c in pw),
                    any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pw)])
        if cats < 3:
            return False, "需包含大写、小写、数字、特殊符号中至少3类"
        return True, ""

    def _on_auth_success(self):
        self.geometry("1150x720")
        self._clear_frame()
        self.db = VaultDB(self.key)
        self.last_activity = time.time()
        self._build_main_interface()
        self._check_expiry_reminder()

    def _check_expiry_reminder(self):
        try:
            report = self.db.get_security_report()
            expired = report.get("expired_passwords", [])
            if expired:
                names = ", ".join(r["site_name"] for r in expired[:5])
                msg = f"{len(expired)} 个密码已过期或长期未更新:\n{names}"
                if len(expired) > 5: msg += f" ...及其他 {len(expired)-5} 个"
                self.after(500, lambda: messagebox.showwarning("密码过期提醒", msg))
        except Exception:
            pass

    # ════════════════════════════════════════
    #  主界面框架
    # ════════════════════════════════════════
    def _build_main_interface(self):
        container = ctk.CTkFrame(self, corner_radius=0, fg_color=("gray90", "gray14"))
        container.pack(expand=True, fill="both")
        self.current_frame = container

        # ── 侧边栏 ──
        sidebar = ctk.CTkFrame(container, width=_SIDEBAR_W, corner_radius=0,
                               fg_color=("gray88", "gray16"))
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # 侧边栏标题（图标 + 文字）
        header_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        header_frame.pack(fill="x", padx=12, pady=(18, 24))
        if _ICON_PNG.exists():
            _icon_img = ctk.CTkImage(light_image=Image.open(_ICON_PNG),
                                     dark_image=Image.open(_ICON_PNG), size=(28, 28))
            ctk.CTkLabel(header_frame, image=_icon_img, text="").pack(side="left")
            sidebar._icon_ref = _icon_img  # 防止被 GC 回收
        ctk.CTkLabel(header_frame, text="密码管理器", font=(_FONT, 15, "bold")).pack(side="left", padx=(6, 0))

        self.nav_buttons = {}
        nav_items = [
            ("records",  "所有记录", self._show_records),
            ("gen_pwd",  "密码生成", self._show_password_gen),
            ("gen_num",  "随机数",   self._show_number_gen),
            ("gen_user", "用户名",   self._show_username_gen),
            ("backup",   "备份恢复", self._show_backup),
            ("report",   "安全报告", self._show_security_report),
            ("recycle",  "回收站",   self._show_recycle_bin),
        ]
        for key, text, cmd in nav_items:
            btn = ctk.CTkButton(sidebar, text=f"  {text}", anchor="w",
                                height=36, fg_color="transparent",
                                font=(_FONT, 13), corner_radius=_BTN_RADIUS,
                                hover_color=("gray78", "gray25"),
                                command=lambda k=key, c=cmd: self._nav_select(k, c))
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[key] = btn

        # 底部按钮
        bottom = ctk.CTkFrame(sidebar, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=10, pady=12)
        ctk.CTkButton(bottom, text="  修改主密码", anchor="w", height=32,
                       fg_color="transparent", font=(_FONT, 12), corner_radius=_BTN_RADIUS,
                       hover_color=("gray78", "gray25"),
                       command=self._show_change_password_dialog).pack(fill="x", pady=1)
        ctk.CTkButton(bottom, text="  锁定", anchor="w", height=32,
                       fg_color="transparent", font=(_FONT, 12), corner_radius=_BTN_RADIUS,
                       hover_color=("gray78", "gray25"),
                       command=self._lock_session).pack(fill="x", pady=1)
        self.status_label = ctk.CTkLabel(bottom, text="", font=(_FONT, 10),
                                          text_color=("gray35", "gray70"))
        self.status_label.pack(pady=(8, 0))

        # ── 内容区 ──
        self.content_area = ctk.CTkFrame(container, corner_radius=12,
                                          fg_color=("gray92", "gray17"))
        self.content_area.pack(side="right", expand=True, fill="both", padx=10, pady=10)

        self._update_idle_timer()
        self._nav_select("records", self._show_records)

    def _nav_select(self, key, callback):
        for k, btn in self.nav_buttons.items():
            if k == key:
                btn.configure(fg_color=("gray78", "gray28"))
            else:
                btn.configure(fg_color="transparent")
        callback()

    # ── 工具方法 ──
    def _clear_frame(self):
        if self.current_frame:
            self.current_frame.destroy()
            self.current_frame = None

    def _clear_content(self):
        for w in self.content_area.winfo_children():
            w.destroy()
        self.batch_mode = False
        self.selected_ids.clear()
        self.search_keyword = ""

    def _copy_clipboard(self, text):
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.after(CLIPBOARD_CLEAR_SECONDS * 1000, self.clipboard_clear)

    def _lock_session(self):
        if self.key is not None:
            for i in range(len(self.key)):
                self.key[i] = 0
            self.key = None
        if self.db:
            self.db.close()
            self.db = None
        self.clipboard_clear()
        self._clear_frame()
        self.geometry("480x420")
        messagebox.showinfo("已锁定", "会话已锁定，请重新输入主密码")
        self._show_auth_screen()

    def _update_idle_timer(self):
        if self.key is not None:
            idle = time.time() - self.last_activity
            remaining = max(0, self.idle_timeout - int(idle))
            if remaining <= 60:
                self.status_label.configure(text=f"即将锁定 ({remaining}s)")
            elif remaining <= 120:
                self.status_label.configure(text=f"{remaining}s")
            else:
                self.status_label.configure(text="")
            if idle > self.idle_timeout:
                self._lock_session(); return
        self.after(1000, self._update_idle_timer)

    def _is_expired(self, rec):
        if rec.get("expire_at"):
            try: return datetime.now() > datetime.fromisoformat(rec["expire_at"])
            except: pass
        ref = rec.get("updated_at") or rec.get("created_at", "")
        if ref:
            try: return datetime.now() - datetime.fromisoformat(ref) > timedelta(days=PASSWORD_EXPIRY_DAYS)
            except: pass
        return False

    def _highlight_text(self, text, keyword):
        """返回带高亮标记的文本组件"""
        tb = ctk.CTkTextbox(height=20, font=(_FONT, 11), fg_color="transparent",
                            activate_scrollbars=False)
        tb.insert("1.0", text)
        if keyword:
            lower_text = text.lower()
            lower_kw = keyword.lower()
            start = 0
            while True:
                idx = lower_text.find(lower_kw, start)
                if idx == -1: break
                tb.tag_add("hl", f"1.{idx}", f"1.{idx + len(keyword)}")
                start = idx + 1
            tb.tag_config("hl", background="#ffc107", foreground="#1a1a1a")
        tb.configure(state="disabled")
        return tb

    # ════════════════════════════════════════
    #  记录列表页
    # ════════════════════════════════════════
    def _show_records(self):
        self._clear_content()
        root = ctk.CTkFrame(self.content_area, corner_radius=0, fg_color="transparent")
        root.pack(expand=True, fill="both")

        # ── 顶部栏 ──
        header = ctk.CTkFrame(root, height=50, corner_radius=10,
                              fg_color=("gray88", "gray20"))
        header.pack(fill="x", padx=8, pady=(8, 4))
        header.pack_propagate(False)

        ctk.CTkLabel(header, text="  所有记录", font=(_FONT, 16, "bold")).pack(side="left", padx=8)

        right = ctk.CTkFrame(header, fg_color="transparent")
        right.pack(side="right", padx=8)

        self.cat_filter_var = ctk.StringVar(value="全部")
        ctk.CTkOptionMenu(right, values=["全部"] + CATEGORIES, variable=self.cat_filter_var,
                          font=(_FONT, 11), width=90, height=30, corner_radius=_BTN_RADIUS,
                          command=lambda _: self._refresh_records()).pack(side="left", padx=3)

        self.search_var = ctk.StringVar()
        self.search_entry = ctk.CTkEntry(right, placeholder_text="搜索...", width=180, height=30,
                                         textvariable=self.search_var, font=(_FONT, 12),
                                         corner_radius=_BTN_RADIUS)
        self.search_entry.pack(side="left", padx=3)
        self.search_entry.bind("<Return>", lambda e: self._refresh_records())

        ctk.CTkButton(right, text="搜索", width=50, height=30, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS,
                       command=self._refresh_records).pack(side="left", padx=2)

        ctk.CTkButton(right, text="+ 添加", width=70, height=30, font=(_FONT, 11, "bold"),
                       corner_radius=_BTN_RADIUS,
                       command=self._show_add_record_dialog).pack(side="left", padx=3)

        # ── 批量操作栏（默认隐藏）──
        self.batch_bar = ctk.CTkFrame(root, height=40, corner_radius=8,
                                       fg_color=("gray85", "gray22"))
        self.batch_btn_frame = ctk.CTkFrame(self.batch_bar, fg_color="transparent")

        # ── 记录列表 ──
        self.records_list = ctk.CTkScrollableFrame(root, corner_radius=10)
        self.records_list.pack(expand=True, fill="both", padx=8, pady=4)

        # ── 分页 ──
        self.page_frame = ctk.CTkFrame(root, height=36, corner_radius=8, fg_color="transparent")
        self.page_frame.pack(fill="x", padx=8, pady=(2, 8))
        self.page_label = ctk.CTkLabel(self.page_frame, text="", font=(_FONT, 11))
        self.page_label.pack(side="left", padx=10)
        self.prev_btn = ctk.CTkButton(self.page_frame, text="< 上一页", width=80, height=28,
                                       font=(_FONT, 11), corner_radius=_BTN_RADIUS,
                                       command=lambda: self._go_page(-1))
        self.prev_btn.pack(side="right", padx=2)
        self.next_btn = ctk.CTkButton(self.page_frame, text="下一页 >", width=80, height=28,
                                       font=(_FONT, 11), corner_radius=_BTN_RADIUS,
                                       command=lambda: self._go_page(1))
        self.next_btn.pack(side="right", padx=2)

        self.current_page = 1
        self._refresh_records()

    def _refresh_records(self):
        for w in self.records_list.winfo_children():
            w.destroy()
        self.last_activity = time.time()

        try:
            kw = self.search_var.get().strip()
            self.search_keyword = kw
            records = self.db.search_enhanced(kw) if kw else self.db.get_all_records()
        except Exception as e:
            ctk.CTkLabel(self.records_list, text=f"读取失败: {e}", text_color="#e74c3c",
                          font=(_FONT, 12)).pack(pady=20); return

        cat = self.cat_filter_var.get()
        if cat != "全部":
            records = [r for r in records if r.get("category", "其他") == cat]

        ps = PAGINATION_PAGE_SIZE
        total = len(records)
        tp = max(1, (total + ps - 1) // ps)
        self.current_page = max(1, min(self.current_page, tp))
        start = (self.current_page - 1) * ps
        page_recs = records[start:start + ps]

        self.page_label.configure(text=f"共 {total} 条  第 {self.current_page}/{tp} 页")
        self.prev_btn.configure(state="normal" if self.current_page > 1 else "disabled")
        self.next_btn.configure(state="normal" if self.current_page < tp else "disabled")

        if not page_recs:
            ctk.CTkLabel(self.records_list,
                          text="暂无记录" if not kw else "未找到匹配记录",
                          font=(_FONT, 14), text_color=("gray35", "gray70")).pack(pady=50)
            return

        for rec in page_recs:
            self._build_record_card(rec)

    def _build_record_card(self, rec):
        expired = self._is_expired(rec)
        bg = ("#faf0f0", "#3a2020") if expired else None
        card = ctk.CTkFrame(self.records_list, corner_radius=_CARD_RADIUS, height=68,
                             fg_color=bg)
        card.pack(fill="x", pady=3)
        card.pack_propagate(False)

        left = ctk.CTkFrame(card, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=14, pady=8)

        # 批量复选框
        if self.batch_mode:
            cb = ctk.CTkCheckBox(left, text="", width=24, variable=ctk.BooleanVar(value=rec["id"] in self.selected_ids),
                                  command=lambda rid=rec["id"]: self._toggle_select(rid))
            cb.pack(side="left", padx=(0, 8))

        # 网站名 + 分类标签
        top = ctk.CTkFrame(left, fg_color="transparent")
        top.pack(fill="x")
        ctk.CTkLabel(top, text=rec["site_name"], font=(_FONT, 14, "bold")).pack(side="left")
        ctk.CTkLabel(top, text=f" {rec.get('category','其他')} ", font=(_FONT, 10),
                     text_color=("gray40", "gray65")).pack(side="left", padx=(6, 0))
        if expired:
            ctk.CTkLabel(top, text="已过期", font=(_FONT, 10),
                         text_color="#e67e22").pack(side="left", padx=(6, 0))

        # 用户名 + 日期
        sub = f"{rec['username']}  |  {rec['created_at'][:10]}"
        if self.search_keyword:
            ctk.CTkLabel(left, text=sub, font=(_FONT, 11),
                         text_color=("gray35", "gray70")).pack(anchor="w")
        else:
            ctk.CTkLabel(left, text=sub, font=(_FONT, 11),
                         text_color=("gray35", "gray70")).pack(anchor="w")

        # 操作按钮
        bf = ctk.CTkFrame(card, fg_color="transparent")
        bf.pack(side="right", padx=(0, 10))
        ctk.CTkButton(bf, text="查看", width=52, height=26, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS, fg_color="transparent", border_width=1,
                       command=lambda r=rec: self._show_detail_dialog(r)).pack(side="left", padx=2)
        ctk.CTkButton(bf, text="删除", width=52, height=26, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS, fg_color="#c0392b", hover_color="#e74c3c",
                       command=lambda rid=rec["id"]: self._delete_record(rid)).pack(side="left", padx=2)

    def _toggle_select(self, rid):
        if rid in self.selected_ids:
            self.selected_ids.discard(rid)
        else:
            self.selected_ids.add(rid)
        self._update_batch_bar()

    def _toggle_batch_mode(self):
        self.batch_mode = not self.batch_mode
        if not self.batch_mode:
            self.selected_ids.clear()
            self.batch_bar.pack_forget()
        else:
            self.batch_bar.pack(fill="x", padx=8, pady=(4, 0))
            for w in self.batch_btn_frame.winfo_children():
                w.destroy()
            self.batch_btn_frame.pack(side="right", padx=8)
            ctk.CTkLabel(self.batch_bar, text="批量模式", font=(_FONT, 12, "bold")).pack(side="left", padx=12)
            ctk.CTkButton(self.batch_btn_frame, text="批量删除", width=80, height=26,
                           font=(_FONT, 11), corner_radius=_BTN_RADIUS, fg_color="#c0392b",
                           command=self._batch_delete).pack(side="left", padx=3)
            ctk.CTkButton(self.batch_btn_frame, text="修改分类", width=80, height=26,
                           font=(_FONT, 11), corner_radius=_BTN_RADIUS,
                           command=self._batch_change_category).pack(side="left", padx=3)
            ctk.CTkButton(self.batch_btn_frame, text="退出批量", width=80, height=26,
                           font=(_FONT, 11), corner_radius=_BTN_RADIUS, fg_color="transparent",
                           border_width=1, command=self._toggle_batch_mode).pack(side="left", padx=3)
        self._refresh_records()

    def _update_batch_bar(self):
        n = len(self.selected_ids)
        # 更新选中数量显示（如果已有标签则更新）
        pass

    def _batch_delete(self):
        if not self.selected_ids:
            messagebox.showinfo("提示", "请先选择要删除的记录"); return
        if messagebox.askyesno("确认", f"确定要将 {len(self.selected_ids)} 条记录移入回收站？"):
            count = self.db.batch_delete_records(list(self.selected_ids))
            messagebox.showinfo("完成", f"已将 {count} 条记录移入回收站")
            self.selected_ids.clear()
            self.batch_mode = False
            self.batch_bar.pack_forget()
            self._refresh_records()

    def _batch_change_category(self):
        if not self.selected_ids:
            messagebox.showinfo("提示", "请先选择记录"); return
        dlg = ctk.CTkToplevel(self)
        dlg.title("批量修改分类")
        dlg.geometry("320x180")
        dlg.transient(self); dlg.grab_set()
        f = ctk.CTkFrame(dlg, corner_radius=12)
        f.pack(expand=True, fill="both", padx=20, pady=20)
        ctk.CTkLabel(f, text="选择新分类", font=(_FONT, 14, "bold")).pack(pady=(8, 12))
        cat_var = ctk.StringVar(value="其他")
        ctk.CTkOptionMenu(f, values=CATEGORIES, variable=cat_var, font=(_FONT, 12)).pack(pady=4)
        def save():
            count = self.db.batch_update_category(list(self.selected_ids), cat_var.get())
            messagebox.showinfo("完成", f"已更新 {count} 条记录的分类")
            dlg.destroy()
            self.selected_ids.clear()
            self.batch_mode = False
            self.batch_bar.pack_forget()
            self._refresh_records()
        ctk.CTkButton(f, text="确定", width=100, height=32, font=(_FONT, 12, "bold"),
                       corner_radius=_BTN_RADIUS, command=save).pack(pady=12)

    def _delete_record(self, rid):
        if messagebox.askyesno("确认删除", "确定要将此记录移入回收站？"):
            self.db.delete_record(rid)
            self._refresh_records()

    def _go_page(self, delta):
        self.current_page += delta
        self._refresh_records()

    # ════════════════════════════════════════
    #  添加/编辑记录对话框
    # ════════════════════════════════════════
    def _show_add_record_dialog(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("添加记录"); dlg.geometry("440x500")
        dlg.transient(self); dlg.grab_set()
        f = ctk.CTkFrame(dlg, corner_radius=14)
        f.pack(expand=True, fill="both", padx=20, pady=20)
        ctk.CTkLabel(f, text="添加新记录", font=(_FONT, 16, "bold")).pack(pady=(6, 14))

        entries = {}
        for ph, key in [("网站名称 *", "site"), ("用户名 *", "user"),
                        ("密码 *", "pwd"), ("网址 (可选)", "url"),
                        ("备注 (可选)", "notes")]:
            e = ctk.CTkEntry(f, placeholder_text=ph, height=34, font=(_FONT, 12),
                             corner_radius=_BTN_RADIUS)
            e.pack(fill="x", padx=10, pady=3)
            entries[key] = e

        cat_var = ctk.StringVar(value="其他")
        ctk.CTkOptionMenu(f, values=CATEGORIES, variable=cat_var, font=(_FONT, 11),
                          width=120).pack(padx=10, pady=4, anchor="w")

        ef = ctk.CTkFrame(f, fg_color="transparent")
        ef.pack(fill="x", padx=10, pady=3)
        ctk.CTkLabel(ef, text="过期日期:", font=(_FONT, 11)).pack(side="left")
        exp_entry = ctk.CTkEntry(ef, placeholder_text="YYYY-MM-DD", height=34,
                                  font=(_FONT, 12), corner_radius=_BTN_RADIUS)
        exp_entry.pack(side="left", fill="x", expand=True, padx=(5, 0))

        def save():
            site = entries["site"].get().strip()
            user = entries["user"].get().strip()
            pwd = entries["pwd"].get().strip()
            if not site or not user or not pwd:
                messagebox.showwarning("提示", "网站名称、用户名和密码为必填项"); return
            self.db.add_record(site, user, pwd,
                               entries["notes"].get().strip() or None,
                               entries["url"].get().strip() or None,
                               cat_var.get(), exp_entry.get().strip() or None)
            messagebox.showinfo("成功", "记录已添加"); dlg.destroy()
            self._refresh_records()

        ctk.CTkButton(f, text="保存", width=120, height=34, font=(_FONT, 13, "bold"),
                       corner_radius=_BTN_RADIUS, command=save).pack(pady=(10, 4))

    # ════════════════════════════════════════
    #  记录详情对话框
    # ════════════════════════════════════════
    def _show_detail_dialog(self, rec):
        dlg = ctk.CTkToplevel(self)
        dlg.title("记录详情"); dlg.geometry("520x540")
        dlg.transient(self); dlg.grab_set()
        f = ctk.CTkFrame(dlg, corner_radius=14)
        f.pack(expand=True, fill="both", padx=18, pady=18)

        ctk.CTkLabel(f, text=rec["site_name"], font=(_FONT, 18, "bold")).pack(pady=(8, 4))
        ctk.CTkLabel(f, text=rec.get("category", "其他"), font=(_FONT, 11),
                     text_color=("gray40", "gray65")).pack()

        for label, val in [("用户名", rec["username"]),
                           ("创建", rec.get("created_at", "")[:19]),
                           ("更新", (rec.get("updated_at") or "")[:19] or "—")]:
            rf = ctk.CTkFrame(f, fg_color="transparent")
            rf.pack(fill="x", pady=1, padx=14)
            ctk.CTkLabel(rf, text=f"{label}:", font=(_FONT, 12), width=60,
                         anchor="w").pack(side="left")
            ctk.CTkLabel(rf, text=val, font=(_FONT, 12, "bold")).pack(side="left")

        # 密码
        pf = ctk.CTkFrame(f, fg_color="transparent")
        pf.pack(fill="x", pady=1, padx=14)
        ctk.CTkLabel(pf, text="密码:", font=(_FONT, 12), width=60, anchor="w").pack(side="left")
        pwd_label = ctk.CTkLabel(pf, text="••••••••", font=(_MONO, 12, "bold"))
        pwd_label.pack(side="left")
        def toggle():
            if pwd_label.cget("text") == "••••••••":
                pwd_label.configure(text=rec["password"])
            else:
                pwd_label.configure(text="••••••••")
        ctk.CTkButton(pf, text="显示", width=44, height=24, font=(_FONT, 10),
                       corner_radius=_BTN_RADIUS, command=toggle).pack(side="left", padx=4)
        ctk.CTkButton(pf, text="复制", width=44, height=24, font=(_FONT, 10),
                       corner_radius=_BTN_RADIUS,
                       command=lambda: self._copy_clipboard(rec["password"])).pack(side="left", padx=2)

        if rec.get("url"):
            uf = ctk.CTkFrame(f, fg_color="transparent")
            uf.pack(fill="x", pady=1, padx=14)
            ctk.CTkLabel(uf, text="网址:", font=(_FONT, 12), width=60, anchor="w").pack(side="left")
            ctk.CTkLabel(uf, text=rec["url"], font=(_FONT, 11),
                         text_color=("#3498db", "#5dade2")).pack(side="left")
            ctk.CTkButton(uf, text="打开", width=44, height=24, font=(_FONT, 10),
                           corner_radius=_BTN_RADIUS,
                           command=lambda: self._open_url(rec["url"])).pack(side="left", padx=4)

        if rec.get("expire_at"):
            ctk.CTkLabel(f, text=f"过期日期: {rec['expire_at']}", font=(_FONT, 11),
                         text_color="#e67e22").pack(anchor="w", padx=14, pady=(4, 0))
        if rec.get("notes"):
            ctk.CTkLabel(f, text=f"备注: {rec['notes']}", font=(_FONT, 11),
                         text_color=("gray35", "gray70"),
                         wraplength=440, justify="left").pack(anchor="w", padx=14, pady=(8, 0))

        bf = ctk.CTkFrame(f, fg_color="transparent")
        bf.pack(fill="x", padx=14, pady=(12, 4))
        ctk.CTkButton(bf, text="编辑", width=72, height=28, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS,
                       command=lambda: self._edit_record_dialog(rec, dlg)).pack(side="left", padx=2)
        ctk.CTkButton(bf, text="历史", width=72, height=28, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS,
                       command=lambda: self._show_history_dialog(rec)).pack(side="left", padx=2)
        ctk.CTkButton(bf, text="关闭", width=72, height=28, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS, fg_color="transparent", border_width=1,
                       command=dlg.destroy).pack(side="right", padx=2)

    def _open_url(self, url):
        if url:
            if not url.startswith("http"): url = "https://" + url
            webbrowser.open(url)

    # ════════════════════════════════════════
    #  密码历史
    # ════════════════════════════════════════
    def _show_history_dialog(self, rec):
        dlg = ctk.CTkToplevel(self)
        dlg.title("密码历史"); dlg.geometry("400x280")
        dlg.transient(self); dlg.grab_set()
        f = ctk.CTkFrame(dlg, corner_radius=12)
        f.pack(expand=True, fill="both", padx=18, pady=18)
        ctk.CTkLabel(f, text=f"{rec['site_name']} 密码历史", font=(_FONT, 14, "bold")).pack(pady=(4, 10))

        history = self.db.get_password_history(rec["id"]) if self.db else []
        if not history:
            ctk.CTkLabel(f, text="暂无历史记录", font=(_FONT, 12),
                         text_color=("gray35", "gray70")).pack(pady=24)
        else:
            scroll = ctk.CTkScrollableFrame(f, height=140)
            scroll.pack(fill="x", pady=4)
            for h in history:
                hf = ctk.CTkFrame(scroll, corner_radius=8)
                hf.pack(fill="x", pady=2, padx=4)
                ctk.CTkLabel(hf, text=h["changed_at"][:19], font=(_FONT, 10),
                             text_color=("gray35", "gray70")).pack(side="left", padx=6)
                ctk.CTkButton(hf, text="回滚", width=48, height=22, font=(_FONT, 10),
                               corner_radius=_BTN_RADIUS,
                               command=lambda rid=rec["id"], d=dlg: self._do_rollback(rid, d)).pack(side="right", padx=6)

        ctk.CTkButton(f, text="关闭", width=80, height=28, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS, fg_color="transparent", border_width=1,
                       command=dlg.destroy).pack(pady=(8, 4))

    def _do_rollback(self, rid, dlg):
        if messagebox.askyesno("确认", "将恢复上一个密码"):
            if self.db and self.db.rollback_password(rid):
                messagebox.showinfo("成功", "密码已回滚"); dlg.destroy()
            else:
                messagebox.showerror("失败", "回滚失败")

    # ════════════════════════════════════════
    #  编辑记录
    # ════════════════════════════════════════
    def _edit_record_dialog(self, rec, parent_dlg):
        dlg = ctk.CTkToplevel(self)
        dlg.title("编辑记录"); dlg.geometry("440x460")
        dlg.transient(self); dlg.grab_set()
        parent_dlg.destroy()
        f = ctk.CTkFrame(dlg, corner_radius=14)
        f.pack(expand=True, fill="both", padx=20, pady=20)
        ctk.CTkLabel(f, text="编辑记录", font=(_FONT, 16, "bold")).pack(pady=(4, 12))

        entries = {}
        for ph, key, val in [("网站名称", "site", rec["site_name"]),
                              ("用户名", "user", rec["username"]),
                              ("密码", "pwd", rec["password"]),
                              ("网址", "url", rec.get("url") or ""),
                              ("备注", "notes", rec.get("notes") or "")]:
            e = ctk.CTkEntry(f, placeholder_text=ph, height=34, font=(_FONT, 12), corner_radius=_BTN_RADIUS)
            e.insert(0, val); e.pack(fill="x", padx=10, pady=3)
            entries[key] = e

        cat_var = ctk.StringVar(value=rec.get("category", "其他"))
        ctk.CTkOptionMenu(f, values=CATEGORIES, variable=cat_var, font=(_FONT, 11)).pack(padx=10, pady=4, anchor="w")

        ef = ctk.CTkFrame(f, fg_color="transparent")
        ef.pack(fill="x", padx=10, pady=3)
        ctk.CTkLabel(ef, text="过期日期:", font=(_FONT, 11)).pack(side="left")
        exp_e = ctk.CTkEntry(ef, height=34, font=(_FONT, 12), corner_radius=_BTN_RADIUS)
        if rec.get("expire_at"): exp_e.insert(0, rec["expire_at"])
        exp_e.pack(side="left", fill="x", expand=True, padx=(5, 0))

        def save():
            self.db.update_record(rec["id"],
                entries["site"].get().strip() or None, entries["user"].get().strip() or None,
                entries["pwd"].get().strip() or None, entries["notes"].get().strip() or None,
                entries["url"].get().strip() or None, cat_var.get(),
                exp_e.get().strip() or None)
            messagebox.showinfo("成功", "记录已更新"); dlg.destroy()
            self._refresh_records()

        ctk.CTkButton(f, text="保存", width=120, height=34, font=(_FONT, 13, "bold"),
                       corner_radius=_BTN_RADIUS, command=save).pack(pady=(8, 4))

    # ════════════════════════════════════════
    #  回收站
    # ════════════════════════════════════════
    def _show_recycle_bin(self):
        self._clear_content()
        root = ctk.CTkFrame(self.content_area, corner_radius=0, fg_color="transparent")
        root.pack(expand=True, fill="both")

        header = ctk.CTkFrame(root, height=50, corner_radius=10, fg_color=("gray88", "gray20"))
        header.pack(fill="x", padx=8, pady=(8, 4))
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="  回收站", font=(_FONT, 16, "bold")).pack(side="left", padx=8)
        ctk.CTkLabel(header, text="删除超过30天的记录将自动清理", font=(_FONT, 10),
                     text_color=("gray40", "gray65")).pack(side="left", padx=8)

        bf = ctk.CTkFrame(header, fg_color="transparent")
        bf.pack(side="right", padx=8)
        ctk.CTkButton(bf, text="清空回收站", width=90, height=28, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS, fg_color="#c0392b", hover_color="#e74c3c",
                       command=self._empty_recycle_bin).pack(side="left", padx=3)
        ctk.CTkButton(bf, text="批量模式", width=80, height=28, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS, fg_color="transparent", border_width=1,
                       command=lambda: self._toggle_batch_mode()).pack(side="left", padx=3)

        scroll = ctk.CTkScrollableFrame(root, corner_radius=10)
        scroll.pack(expand=True, fill="both", padx=8, pady=4)

        records = self.db.get_deleted_records() if self.db else []
        if not records:
            ctk.CTkLabel(scroll, text="回收站为空", font=(_FONT, 14),
                         text_color=("gray35", "gray70")).pack(pady=50); return

        for rec in records:
            card = ctk.CTkFrame(scroll, corner_radius=_CARD_RADIUS, height=60)
            card.pack(fill="x", pady=2)
            card.pack_propagate(False)

            left = ctk.CTkFrame(card, fg_color="transparent")
            left.pack(side="left", fill="both", expand=True, padx=14, pady=6)
            ctk.CTkLabel(left, text=rec["site_name"], font=(_FONT, 13, "bold")).pack(anchor="w")
            deleted = rec.get("deleted_at", "")[:19]
            ctk.CTkLabel(left, text=f"{rec['username']}  |  删除于 {deleted}", font=(_FONT, 10),
                         text_color=("gray35", "gray70")).pack(anchor="w")

            rb = ctk.CTkFrame(card, fg_color="transparent")
            rb.pack(side="right", padx=10)
            ctk.CTkButton(rb, text="恢复", width=52, height=24, font=(_FONT, 10),
                           corner_radius=_BTN_RADIUS,
                           command=lambda rid=rec["id"]: self._restore_record(rid)).pack(side="left", padx=2)
            ctk.CTkButton(rb, text="永久删除", width=72, height=24, font=(_FONT, 10),
                           corner_radius=_BTN_RADIUS, fg_color="#c0392b",
                           command=lambda rid=rec["id"]: self._perm_delete(rid)).pack(side="left", padx=2)

    def _restore_record(self, rid):
        if self.db and self.db.restore_record(rid):
            messagebox.showinfo("成功", "记录已恢复")
            self._show_recycle_bin()

    def _perm_delete(self, rid):
        if messagebox.askyesno("确认", "永久删除后无法恢复，确定？"):
            self.db.permanent_delete(rid)
            self._show_recycle_bin()

    def _empty_recycle_bin(self):
        if messagebox.askyesno("确认", "确定要清空回收站？此操作不可恢复"):
            n = self.db.empty_recycle_bin()
            messagebox.showinfo("完成", f"已永久删除 {n} 条记录")
            self._show_recycle_bin()

    # ════════════════════════════════════════
    #  密码生成器
    # ════════════════════════════════════════
    def _show_password_gen(self):
        self._clear_content()
        f = ctk.CTkFrame(self.content_area, corner_radius=12)
        f.pack(expand=True, fill="both", padx=20, pady=20)
        ctk.CTkLabel(f, text="密码生成器", font=(_FONT, 20, "bold")).pack(pady=(14, 18))

        settings = ctk.CTkFrame(f, corner_radius=10)
        settings.pack(fill="x", padx=28, pady=4)

        lf = ctk.CTkFrame(settings, fg_color="transparent")
        lf.pack(fill="x", pady=4)
        ctk.CTkLabel(lf, text="长度:", font=(_FONT, 12), width=50).pack(side="left", padx=(10, 0))
        self.pwd_len_var = ctk.IntVar(value=16)
        self.pwd_len_lbl = ctk.StringVar(value="16")
        ctk.CTkSlider(lf, from_=8, to=64, number_of_steps=56, variable=self.pwd_len_var,
                       command=lambda v: self.pwd_len_lbl.set(str(int(v)))).pack(side="left", fill="x", expand=True, padx=8)
        ctk.CTkLabel(lf, textvariable=self.pwd_len_lbl, font=(_FONT, 12, "bold"), width=28).pack(side="right", padx=8)

        self.charset_vars = {}
        cs = ctk.CTkFrame(settings, fg_color="transparent")
        cs.pack(fill="x", pady=4)
        ctk.CTkLabel(cs, text="字符:", font=(_FONT, 12), width=50).pack(side="left", padx=(10, 0), anchor="nw")
        for label, key in [("大写 A-Z", "uppercase"), ("小写 a-z", "lowercase"),
                           ("数字 0-9", "digits"), ("特殊符号", "special")]:
            ctk.CTkCheckBox(cs, text=label, variable=ctk.BooleanVar(value=True),
                             font=(_FONT, 11), command=lambda k=key: None).pack(anchor="w", padx=(18, 4), pady=1)
            self.charset_vars[key] = cs.winfo_children()[-1].cget("variable")

        ctk.CTkButton(settings, text="生成密码", width=140, height=36, font=(_FONT, 13, "bold"),
                       corner_radius=_BTN_RADIUS, command=self._do_generate_password).pack(pady=(8, 8))

        result = ctk.CTkFrame(f, corner_radius=10)
        result.pack(fill="x", padx=28, pady=12)
        self.pwd_result_var = ctk.StringVar(value="点击生成")
        ctk.CTkEntry(result, textvariable=self.pwd_result_var, font=(_MONO, 18, "bold"),
                     height=44, justify="center", state="readonly", corner_radius=_BTN_RADIUS).pack(fill="x", padx=18, pady=(14, 4))
        self.strength_var = ctk.StringVar(value="")
        self.strength_label = ctk.CTkLabel(result, textvariable=self.strength_var, font=(_FONT, 12))
        self.strength_label.pack(pady=(2, 6))

        sbf = ctk.CTkFrame(result, fg_color="transparent")
        sbf.pack(fill="x", padx=18, pady=(0, 14))
        ctk.CTkButton(sbf, text="复制", width=80, height=30, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS, command=self._copy_gen_password).pack(side="left", padx=4)
        ctk.CTkButton(sbf, text="保存", width=80, height=30, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS, command=self._save_generated_password).pack(side="left", padx=4)

    def _do_generate_password(self):
        length = self.pwd_len_var.get()
        cfg = {k: v.get() if hasattr(v, 'get') else True for k, v in self.charset_vars.items()}
        pwd = generate_password(length, cfg)
        self.pwd_result_var.set(pwd)
        strength, entropy = calculate_password_strength(pwd)
        colors = {"弱": "#e74c3c", "中": "#f39c12", "强": "#2ecc71", "极强": "#27ae60"}
        self.strength_var.set(f"强度: {strength}  |  熵: {entropy:.1f} bits")
        self.strength_label.configure(text_color=colors.get(strength, "gray"))

    def _copy_gen_password(self):
        pwd = self.pwd_result_var.get()
        if pwd and pwd != "点击生成":
            self._copy_clipboard(pwd)
            messagebox.showinfo("已复制", f"密码已复制（{CLIPBOARD_CLEAR_SECONDS}秒后清除）")

    def _save_generated_password(self):
        pwd = self.pwd_result_var.get()
        if not pwd or pwd == "点击生成": return
        dlg = ctk.CTkToplevel(self)
        dlg.title("保存密码"); dlg.geometry("400x300")
        dlg.transient(self); dlg.grab_set()
        f = ctk.CTkFrame(dlg, corner_radius=12)
        f.pack(expand=True, fill="both", padx=20, pady=20)
        ctk.CTkLabel(f, text="保存密码", font=(_FONT, 15, "bold")).pack(pady=(4, 10))
        site_e = ctk.CTkEntry(f, placeholder_text="网站名称 *", height=34, font=(_FONT, 12), corner_radius=_BTN_RADIUS)
        site_e.pack(fill="x", padx=10, pady=3)
        user_e = ctk.CTkEntry(f, placeholder_text="用户名 (可选)", height=34, font=(_FONT, 12), corner_radius=_BTN_RADIUS)
        user_e.pack(fill="x", padx=10, pady=3)
        cat_var = ctk.StringVar(value="其他")
        ctk.CTkOptionMenu(f, values=CATEGORIES, variable=cat_var, font=(_FONT, 11)).pack(padx=10, pady=4, anchor="w")
        def save():
            site = site_e.get().strip()
            if not site: messagebox.showwarning("提示", "网站名称不能为空"); return
            self.db.add_record(site, user_e.get().strip() or site, pwd, category=cat_var.get())
            messagebox.showinfo("已保存", "密码已保存"); dlg.destroy()
        ctk.CTkButton(f, text="保存", width=110, height=32, font=(_FONT, 12, "bold"),
                       corner_radius=_BTN_RADIUS, command=save).pack(pady=(8, 4))

    # ════════════════════════════════════════
    #  随机数生成器
    # ════════════════════════════════════════
    def _show_number_gen(self):
        self._clear_content()
        f = ctk.CTkFrame(self.content_area, corner_radius=12)
        f.pack(expand=True, fill="both", padx=20, pady=20)
        ctk.CTkLabel(f, text="随机数生成器", font=(_FONT, 20, "bold")).pack(pady=(14, 18))

        tv = ctk.CTkTabview(f, corner_radius=10)
        tv.pack(expand=True, fill="both", padx=20, pady=4)

        # 整数
        t1 = tv.add("整数")
        rf1 = ctk.CTkFrame(t1, fg_color="transparent")
        rf1.pack(expand=True, fill="both", padx=40, pady=24)
        min_v, max_v = ctk.StringVar(value="1"), ctk.StringVar(value="100")
        num_r = ctk.StringVar(value="")
        for lbl, var in [("最小值:", min_v), ("最大值:", max_v)]:
            ctk.CTkLabel(rf1, text=lbl, font=(_FONT, 12)).pack(pady=(6, 2))
            ctk.CTkEntry(rf1, textvariable=var, width=180, height=32, font=(_FONT, 12),
                          corner_radius=_BTN_RADIUS).pack(pady=(0, 8))
        def gen_int():
            try:
                mn, mx = int(min_v.get()), int(max_v.get())
                if mn > mx: messagebox.showwarning("", "最小值不能大于最大值"); return
                num_r.set(str(generate_random_number(mn, mx)))
            except ValueError: messagebox.showerror("", "请输入有效数字")
        ctk.CTkButton(rf1, text="生成", width=130, height=34, font=(_FONT, 13, "bold"),
                       corner_radius=_BTN_RADIUS, command=gen_int).pack(pady=(6, 6))
        ctk.CTkEntry(rf1, textvariable=num_r, width=220, height=40, font=(_MONO, 20, "bold"),
                     justify="center", state="readonly", corner_radius=_BTN_RADIUS).pack(pady=(8, 6))
        ctk.CTkButton(rf1, text="复制", width=80, height=28, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS,
                       command=lambda: self._copy_clipboard(num_r.get())).pack()

        # 数字串
        t2 = tv.add("数字串")
        rf2 = ctk.CTkFrame(t2, fg_color="transparent")
        rf2.pack(expand=True, fill="both", padx=40, pady=24)
        len_v, dig_r = ctk.StringVar(value="6"), ctk.StringVar(value="")
        ctk.CTkLabel(rf2, text="长度:", font=(_FONT, 12)).pack(pady=(8, 2))
        ctk.CTkEntry(rf2, textvariable=len_v, width=180, height=32, font=(_FONT, 12),
                      corner_radius=_BTN_RADIUS).pack(pady=(0, 8))
        def gen_dig():
            try:
                ln = int(len_v.get())
                if ln <= 0: messagebox.showwarning("", "长度必须大于0"); return
                dig_r.set(generate_random_digit_string(ln))
            except ValueError: messagebox.showerror("", "请输入有效数字")
        ctk.CTkButton(rf2, text="生成", width=130, height=34, font=(_FONT, 13, "bold"),
                       corner_radius=_BTN_RADIUS, command=gen_dig).pack(pady=(6, 6))
        ctk.CTkEntry(rf2, textvariable=dig_r, width=220, height=40, font=(_MONO, 20, "bold"),
                     justify="center", state="readonly", corner_radius=_BTN_RADIUS).pack(pady=(8, 6))
        ctk.CTkButton(rf2, text="复制", width=80, height=28, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS,
                       command=lambda: self._copy_clipboard(dig_r.get())).pack()

    # ════════════════════════════════════════
    #  用户名生成器
    # ════════════════════════════════════════
    def _show_username_gen(self):
        self._clear_content()
        f = ctk.CTkFrame(self.content_area, corner_radius=12)
        f.pack(expand=True, fill="both", padx=20, pady=20)
        ctk.CTkLabel(f, text="用户名生成器", font=(_FONT, 20, "bold")).pack(pady=(14, 18))

        tv = ctk.CTkTabview(f, corner_radius=10)
        tv.pack(expand=True, fill="both", padx=20, pady=4)

        # 中文
        cn_tab = tv.add("中文姓名")
        cn_r = ctk.StringVar(value="")
        cn_f = ctk.CTkFrame(cn_tab, fg_color="transparent")
        cn_f.pack(expand=True, fill="both", padx=50, pady=18)
        cn_len = ctk.StringVar(value="随机")
        cn_style = ctk.StringVar(value="传统型")
        rf = ctk.CTkFrame(cn_f, fg_color="transparent")
        rf.pack(fill="x", pady=4)
        ctk.CTkLabel(rf, text="字数:", font=(_FONT, 12)).pack(side="left")
        ctk.CTkOptionMenu(rf, values=["随机", "2字", "3字", "4字"], variable=cn_len,
                          font=(_FONT, 11), width=80).pack(side="left", padx=(4, 12))
        ctk.CTkLabel(rf, text="风格:", font=(_FONT, 12)).pack(side="left")
        ctk.CTkOptionMenu(rf, values=["传统型", "现代型", "文艺型", "网名"], variable=cn_style,
                          font=(_FONT, 11), width=80).pack(side="left", padx=4)
        def gen_cn():
            from generators import generate_chinese_full_name, generate_chinese_nickname, generate_chinese_username
            if cn_style.get() == "网名":
                cn_r.set(generate_chinese_nickname())
            else:
                raw = cn_len.get()
                length = None if raw == "随机" else int(raw[0])
                smap = {"传统型": "classic", "现代型": "modern", "文艺型": "literary"}
                if length: cn_r.set(generate_chinese_username(length))
                else: cn_r.set(generate_chinese_full_name(smap[cn_style.get()]))
        ctk.CTkButton(cn_f, text="生成", width=130, height=34, font=(_FONT, 13, "bold"),
                       corner_radius=_BTN_RADIUS, command=gen_cn).pack(pady=(12, 8))
        ctk.CTkEntry(cn_f, textvariable=cn_r, width=260, height=46, font=(_FONT, 22, "bold"),
                     justify="center", state="readonly", corner_radius=_BTN_RADIUS).pack(pady=(4, 6))
        ctk.CTkButton(cn_f, text="复制", width=80, height=28, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS,
                       command=lambda: self._copy_clipboard(cn_r.get())).pack()

        # 英文
        en_tab = tv.add("英文姓名")
        en_r = ctk.StringVar(value="")
        en_f = ctk.CTkFrame(en_tab, fg_color="transparent")
        en_f.pack(expand=True, fill="both", padx=50, pady=18)
        def gen_en():
            from generators import generate_english_full_name, generate_username as gen_u
            if True:
                res = generate_english_full_name()
                en_r.set(res["full"])
        ctk.CTkButton(en_f, text="生成英文姓名", width=140, height=34, font=(_FONT, 13, "bold"),
                       corner_radius=_BTN_RADIUS, command=gen_en).pack(pady=(14, 8))
        ctk.CTkEntry(en_f, textvariable=en_r, width=260, height=46, font=(_MONO, 18, "bold"),
                     justify="center", state="readonly", corner_radius=_BTN_RADIUS).pack(pady=(4, 6))
        ctk.CTkButton(en_f, text="复制", width=80, height=28, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS,
                       command=lambda: self._copy_clipboard(en_r.get())).pack()

    # ════════════════════════════════════════
    #  备份与恢复
    # ════════════════════════════════════════
    def _show_backup(self):
        self._clear_content()
        f = ctk.CTkScrollableFrame(self.content_area, corner_radius=12)
        f.pack(expand=True, fill="both", padx=16, pady=16)
        ctk.CTkLabel(f, text="备份与恢复", font=(_FONT, 20, "bold")).pack(pady=(12, 16))

        # ── 导出 ──
        exp = ctk.CTkFrame(f, corner_radius=10)
        exp.pack(fill="x", pady=6)
        ctk.CTkLabel(exp, text="  导出", font=(_FONT, 14, "bold")).pack(anchor="w", padx=14, pady=(10, 4))
        ef = ctk.CTkFrame(exp, fg_color="transparent")
        ef.pack(fill="x", padx=14, pady=4)
        self.export_fmt_var = ctk.StringVar(value="enc")
        ctk.CTkOptionMenu(ef, values=["enc (加密)", "json (明文)", "csv (明文)"],
                          variable=self.export_fmt_var, font=(_FONT, 11), width=140).pack(side="left")
        self.export_path_var = ctk.StringVar(value="backup.enc")
        ctk.CTkEntry(ef, textvariable=self.export_path_var, height=30, font=(_FONT, 11),
                      corner_radius=_BTN_RADIUS).pack(side="left", fill="x", expand=True, padx=6)
        def browse_exp():
            fmt = self.export_fmt_var.get()
            ext = ".enc" if "enc" in fmt else (".json" if "json" in fmt else ".csv")
            fp = filedialog.asksaveasfilename(defaultextension=ext)
            if fp: self.export_path_var.set(fp)
        ctk.CTkButton(ef, text="浏览", width=56, height=30, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS, command=browse_exp).pack(side="left")
        self.export_btn = ctk.CTkButton(exp, text="导出", width=120, height=34,
                                         font=(_FONT, 13, "bold"), corner_radius=_BTN_RADIUS,
                                         command=self._do_export)
        self.export_btn.pack(pady=(6, 12))

        # ── 导入备份 ──
        imp = ctk.CTkFrame(f, corner_radius=10)
        imp.pack(fill="x", pady=6)
        ctk.CTkLabel(imp, text="  导入备份", font=(_FONT, 14, "bold")).pack(anchor="w", padx=14, pady=(10, 4))
        ctk.CTkLabel(imp, text="支持: 加密备份(.enc)、通用CSV、Bitwarden CSV、1Password CSV",
                     font=(_FONT, 10), text_color=("gray40", "gray65")).pack(anchor="w", padx=14)
        ipf = ctk.CTkFrame(imp, fg_color="transparent")
        ipf.pack(fill="x", padx=14, pady=4)
        self.import_path_var = ctk.StringVar(value="")
        ctk.CTkEntry(ipf, textvariable=self.import_path_var, height=30, font=(_FONT, 11),
                      corner_radius=_BTN_RADIUS).pack(side="left", fill="x", expand=True, padx=(0, 6))
        def browse_imp():
            fp = filedialog.askopenfilename(
                filetypes=[("所有支持格式", "*.enc *.csv *.json"),
                           ("加密备份", "*.enc"), ("CSV", "*.csv"), ("JSON", "*.json")])
            if fp: self.import_path_var.set(fp)
        ctk.CTkButton(ipf, text="浏览", width=56, height=30, font=(_FONT, 11),
                       corner_radius=_BTN_RADIUS, command=browse_imp).pack(side="left")
        fmt_frame = ctk.CTkFrame(imp, fg_color="transparent")
        fmt_frame.pack(fill="x", padx=14, pady=2)
        ctk.CTkLabel(fmt_frame, text="CSV格式:", font=(_FONT, 11)).pack(side="left")
        self.import_fmt_var = ctk.StringVar(value="auto")
        for v, t in [("auto", "自动检测"), ("bitwarden", "Bitwarden"), ("1password", "1Password"), ("generic", "通用CSV")]:
            ctk.CTkRadioButton(fmt_frame, text=t, variable=self.import_fmt_var, value=v,
                                font=(_FONT, 10)).pack(side="left", padx=6)
        self.import_btn = ctk.CTkButton(imp, text="导入", width=120, height=34,
                                         font=(_FONT, 13, "bold"), corner_radius=_BTN_RADIUS,
                                         command=self._do_import)
        self.import_btn.pack(pady=(6, 12))

        # ── 浏览器导入 ──
        br = ctk.CTkFrame(f, corner_radius=10)
        br.pack(fill="x", pady=6)
        ctk.CTkLabel(br, text="  从浏览器导入", font=(_FONT, 14, "bold")).pack(anchor="w", padx=14, pady=(10, 4))
        ctk.CTkLabel(br, text="需要先关闭浏览器。支持 Edge、Chrome、Firefox。",
                     font=(_FONT, 10), text_color=("gray40", "gray65")).pack(anchor="w", padx=14)
        bf = ctk.CTkFrame(br, fg_color="transparent")
        bf.pack(pady=(6, 12))
        self.edge_btn = ctk.CTkButton(bf, text="Edge", width=100, height=34, font=(_FONT, 12, "bold"),
                                       corner_radius=_BTN_RADIUS, command=lambda: self._browser_import("edge"))
        self.edge_btn.pack(side="left", padx=4)
        self.chrome_btn = ctk.CTkButton(bf, text="Chrome", width=100, height=34, font=(_FONT, 12, "bold"),
                                         corner_radius=_BTN_RADIUS, command=lambda: self._browser_import("chrome"))
        self.chrome_btn.pack(side="left", padx=4)
        self.ff_btn = ctk.CTkButton(bf, text="Firefox", width=100, height=34, font=(_FONT, 12, "bold"),
                                     corner_radius=_BTN_RADIUS, command=lambda: self._browser_import("firefox"))
        self.ff_btn.pack(side="left", padx=4)

    def _do_export(self):
        records = self.db.get_all_records() if self.db else []
        if not records: messagebox.showinfo("", "没有可导出的记录"); return
        path = self.export_path_var.get().strip()
        if not path: messagebox.showwarning("", "请选择路径"); return
        fmt = "enc" if "enc" in self.export_fmt_var.get() else ("json" if "json" in self.export_fmt_var.get() else "csv")
        self.export_btn.configure(state="disabled")
        self.update()
        def run():
            if fmt == "enc": ok = export_backup(records, self.key, path)
            elif fmt == "json": ok = export_json_plain(records, path)
            else: ok = export_csv(records, path)
            self.after(0, lambda: self.export_btn.configure(state="normal"))
            self.after(0, lambda: messagebox.showinfo("成功" if ok else "失败", f"导出{'完成' if ok else '失败'}"))
        threading.Thread(target=run, daemon=True).start()

    def _do_import(self):
        path = self.import_path_var.get().strip()
        if not path: messagebox.showwarning("", "请选择文件"); return
        self.import_btn.configure(state="disabled"); self.update()
        def run():
            try:
                fmt = self.import_fmt_var.get()
                if path.lower().endswith(".enc"):
                    records = import_backup(path, self.key)
                elif fmt == "bitwarden":
                    from backup import import_bitwarden_csv
                    records = import_bitwarden_csv(path)
                elif fmt == "1password":
                    from backup import import_1password_csv
                    records = import_1password_csv(path)
                elif path.lower().endswith(".csv"):
                    # 自动检测格式
                    from backup import import_bitwarden_csv, import_1password_csv, import_csv
                    records = import_bitwarden_csv(path)
                    if not records: records = import_1password_csv(path)
                    if not records: records = import_csv(path)
                else:
                    records = import_backup(path, self.key)
                self.after(0, lambda: self._on_import_result(records))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("错误", f"导入失败: {e}"))
                self.after(0, lambda: self.import_btn.configure(state="normal"))
        threading.Thread(target=run, daemon=True).start()

    def _on_import_result(self, records):
        self.import_btn.configure(state="normal")
        if not records:
            messagebox.showinfo("", "没有找到可导入的记录"); return
        valid = [r for r in records if isinstance(r, dict) and r.get("site_name") and r.get("password")]
        if not valid:
            messagebox.showinfo("", "没有有效记录"); return
        existing = {(r["site_name"], r["username"]) for r in self.db.get_all_records()} if self.db else set()
        new_recs = [r for r in valid if (r["site_name"], r.get("username", "")) not in existing]
        if not new_recs:
            messagebox.showinfo("", f"{len(valid)} 条记录全部已存在"); return
        if not messagebox.askyesno("确认", f"找到 {len(new_recs)} 条新记录，是否导入？"): return
        count = 0
        for r in new_recs:
            try:
                self.db.add_record(r["site_name"], r.get("username", r["site_name"]),
                    r["password"], r.get("notes"), r.get("url"), r.get("category", "其他"), r.get("expire_at"))
                count += 1
            except Exception: pass
        messagebox.showinfo("完成", f"成功导入 {count} 条记录")

    def _browser_import(self, browser):
        btn_map = {"edge": self.edge_btn, "chrome": self.chrome_btn, "firefox": self.ff_btn}
        name_map = {"edge": "Edge", "chrome": "Chrome", "firefox": "Firefox"}
        btn = btn_map[browser]; name = name_map[browser]
        btn.configure(state="disabled"); self.update()
        def run():
            try:
                if browser == "firefox":
                    from browser_import import import_from_firefox
                    ok, total = import_from_firefox(self.db)
                elif browser == "edge":
                    from browser_import import import_from_edge
                    ok, total = import_from_edge(self.db)
                else:
                    from browser_import import import_from_chrome
                    ok, total = import_from_chrome(self.db)
                self.after(0, lambda: self._on_browser_done(ok, total, btn, name, browser))
            except Exception as e:
                self.after(0, lambda: btn.configure(state="normal"))
                self.after(0, lambda: messagebox.showerror("错误", str(e)))
        threading.Thread(target=run, daemon=True).start()

    def _on_browser_done(self, ok, total, btn, name, browser):
        btn.configure(state="normal")
        if ok == -3:
            messagebox.showinfo("需要手动导出",
                f"Firefox 使用了主密码加密，无法自动读取。\n\n"
                f"请手动操作:\n1. 打开 Firefox → 设置 → 隐私与安全\n"
                f"2. 点击「已保存的登录信息」\n3. 导出为 CSV\n4. 在本工具中导入该 CSV")
        elif ok == -2:
            messagebox.showinfo("需要手动导出",
                f"{name} 使用了新版加密(v20)，无法自动导入。\n请手动导出 CSV 后在本工具中导入。")
        elif ok == -1:
            messagebox.showerror("错误", f"获取 {name} 加密密钥失败，请确保已关闭浏览器。")
        elif ok == 0 and total == 0:
            messagebox.showinfo("", f"未在 {name} 中找到密码。")
        elif ok > 0:
            messagebox.showinfo("完成", f"从 {name} 导入 {ok}/{total} 条")
        else:
            messagebox.showerror("错误", f"从 {name} 导入失败。")

    # ════════════════════════════════════════
    #  安全报告
    # ════════════════════════════════════════
    def _show_security_report(self):
        self._clear_content()
        f = ctk.CTkScrollableFrame(self.content_area, corner_radius=12)
        f.pack(expand=True, fill="both", padx=16, pady=16)
        ctk.CTkLabel(f, text="安全报告", font=(_FONT, 20, "bold")).pack(pady=(12, 16))

        try:
            report = self.db.get_security_report() if self.db else {}
        except Exception as e:
            ctk.CTkLabel(f, text=f"生成失败: {e}", text_color="#e74c3c").pack(pady=20); return

        summary = ctk.CTkFrame(f, corner_radius=10)
        summary.pack(fill="x", pady=6)
        ctk.CTkLabel(summary, text="  概览", font=(_FONT, 14, "bold")).pack(anchor="w", padx=14, pady=(10, 4))
        for label, val, color in [
            ("总记录", str(report.get("total_records", 0)), None),
            ("弱密码", str(report.get("weak_count", 0)), "#e74c3c" if report.get("weak_count") else "#2ecc71"),
            ("过期密码", str(report.get("expired_count", 0)), "#e67e22" if report.get("expired_count") else "#2ecc71"),
            ("重复密码", str(report.get("reused_passwords_count", 0)), "#e67e22" if report.get("reused_passwords_count") else "#2ecc71"),
        ]:
            rf = ctk.CTkFrame(summary, fg_color="transparent")
            rf.pack(fill="x", padx=14, pady=1)
            ctk.CTkLabel(rf, text=f"  {label}:", font=(_FONT, 12)).pack(side="left")
            ctk.CTkLabel(rf, text=val, font=(_FONT, 12, "bold"), text_color=color).pack(side="left", padx=(8, 0))
        ctk.CTkLabel(summary, text="").pack(pady=4)

        for title, items, color in [
            ("弱密码", report.get("weak_passwords", []), "#e74c3c"),
            ("过期密码", report.get("expired_passwords", []), "#e67e22"),
        ]:
            if items:
                sf = ctk.CTkFrame(f, corner_radius=10)
                sf.pack(fill="x", pady=4)
                ctk.CTkLabel(sf, text=f"  {title}", font=(_FONT, 13, "bold"),
                             text_color=color).pack(anchor="w", padx=14, pady=(8, 2))
                for r in items:
                    ctk.CTkLabel(sf, text=f"    {r['site_name']} — {r['username']}",
                                 font=(_FONT, 11)).pack(anchor="w", padx=14, pady=1)
                ctk.CTkLabel(sf, text="").pack(pady=4)

        ctk.CTkButton(f, text="刷新", width=100, height=32, font=(_FONT, 12, "bold"),
                       corner_radius=_BTN_RADIUS, command=self._show_security_report).pack(pady=(12, 8))

    # ════════════════════════════════════════
    #  修改主密码
    # ════════════════════════════════════════
    def _show_change_password_dialog(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("修改主密码"); dlg.geometry("400x310")
        dlg.transient(self); dlg.grab_set()
        f = ctk.CTkFrame(dlg, corner_radius=14)
        f.pack(expand=True, fill="both", padx=20, pady=20)
        ctk.CTkLabel(f, text="修改主密码", font=(_FONT, 16, "bold")).pack(pady=(6, 14))

        old_e = ctk.CTkEntry(f, placeholder_text="当前主密码", show="*", height=34, font=(_FONT, 12), corner_radius=_BTN_RADIUS)
        old_e.pack(fill="x", padx=10, pady=4)
        new_e = ctk.CTkEntry(f, placeholder_text="新主密码 (≥12位)", show="*", height=34, font=(_FONT, 12), corner_radius=_BTN_RADIUS)
        new_e.pack(fill="x", padx=10, pady=4)
        cfm_e = ctk.CTkEntry(f, placeholder_text="确认新主密码", show="*", height=34, font=(_FONT, 12), corner_radius=_BTN_RADIUS)
        cfm_e.pack(fill="x", padx=10, pady=4)
        err = ctk.CTkLabel(f, text="", text_color="#e74c3c", font=(_FONT, 11))
        err.pack(pady=(4, 4))

        def do_change():
            old, new, cfm = old_e.get().strip(), new_e.get().strip(), cfm_e.get().strip()
            if not old or not new or not cfm: err.configure(text="请填写所有字段"); return
            if new != cfm: err.configure(text="两次输入不一致"); return
            ok, msg = self._validate_master_password(new)
            if not ok: err.configure(text=msg); return
            sp, tp = get_vault_paths()
            if not verify_master_password(old, sp.read_bytes(), tp.read_bytes()):
                err.configure(text="当前密码错误"); return
            try:
                new_salt = generate_salt()
                new_key = derive_key(new, new_salt)
                self.db.change_master_password(new_key)
                _, new_payload = init_vault(new)
                sp.write_bytes(new_salt); tp.write_bytes(new_payload)
                if self.key:
                    for i in range(len(self.key)): self.key[i] = 0
                self.key = bytearray(new_key)
                messagebox.showinfo("成功", "主密码已修改（salt 已更新）"); dlg.destroy()
            except Exception as e:
                err.configure(text=f"修改失败: {e}")

        ctk.CTkButton(f, text="确认修改", width=120, height=34, font=(_FONT, 13, "bold"),
                       corner_radius=_BTN_RADIUS, command=do_change).pack(pady=(6, 4))

    def run(self):
        self.mainloop()


def main():
    app = PasswordManagerGUI()
    app.run()

if __name__ == "__main__":
    main()
