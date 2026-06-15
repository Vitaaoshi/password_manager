"""数据库CRUD操作"""
import os
import stat
import sqlite3
import hmac
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path

from config import DB_PATH, DB_DIR, MAX_PASSWORD_HISTORY, PASSWORD_EXPIRY_DAYS, PAGINATION_PAGE_SIZE, CATEGORIES
from crypto_utils import encrypt, decrypt, derive_hmac_key, compute_hmac
from password_strength import check_password_strength


class VaultDB:
    def __init__(self, key: bytes):
        self.key = key
        self.hmac_key = derive_hmac_key(key)
        DB_DIR.mkdir(parents=True, exist_ok=True)
        is_new = not Path(DB_PATH).exists()
        self.conn = sqlite3.connect(str(DB_PATH))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._create_tables()
        self._migrate_schema()
        self.upgrade_record_hmacs()
        if is_new:
            self._restrict_db_permissions()

    @staticmethod
    def _restrict_db_permissions():
        try:
            current = stat.S_IMODE(os.stat(DB_PATH).st_mode)
            restricted = stat.S_IRUSR | stat.S_IWUSR
            if current != restricted:
                os.chmod(DB_PATH, restricted)
        except (OSError, PermissionError):
            pass

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_name_encrypted BLOB NOT NULL,
                username_encrypted BLOB NOT NULL,
                password_encrypted BLOB NOT NULL,
                created_at TEXT NOT NULL,
                notes_encrypted BLOB,
                record_hmac BLOB NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id INTEGER NOT NULL,
                password_encrypted BLOB NOT NULL,
                changed_at TEXT NOT NULL,
                FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("PRAGMA table_info(records)")
        columns = [col[1] for col in cursor.fetchall()]
        if "record_hmac" not in columns:
            cursor.execute("ALTER TABLE records ADD COLUMN record_hmac BLOB")
        self.conn.commit()

    def _migrate_schema(self):
        cursor = self.conn.cursor()
        cursor.execute("PRAGMA table_info(records)")
        columns = [col[1] for col in cursor.fetchall()]
        new_columns = {
            "url_encrypted": "BLOB",
            "category": "TEXT DEFAULT '其他'",
            "expire_at": "TEXT",
            "updated_at": "TEXT",
            "clicked_count": "INTEGER DEFAULT 0",
            "upgraded_at": "TEXT",
            "deleted_at": "TEXT",
        }
        for col, col_type in new_columns.items():
            if col not in columns:
                cursor.execute(f"ALTER TABLE records ADD COLUMN {col} {col_type}")
        self.conn.commit()

    def _record_to_history(self, record_id: int, password_encrypted: bytes):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO password_history (record_id, password_encrypted, changed_at) VALUES (?, ?, ?)",
            (record_id, password_encrypted, datetime.now().isoformat()),
        )
        cursor.execute(
            """DELETE FROM password_history WHERE id IN (
                SELECT id FROM password_history WHERE record_id = ?
                ORDER BY changed_at DESC LIMIT -1 OFFSET ?
            )""",
            (record_id, MAX_PASSWORD_HISTORY),
        )
        self.conn.commit()

    def get_password_history(self, record_id: int) -> list[dict]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM password_history WHERE record_id = ? ORDER BY changed_at DESC LIMIT ?",
            (record_id, MAX_PASSWORD_HISTORY),
        )
        rows = cursor.fetchall()
        if not rows:
            return []
        results = []
        for row in rows:
            try:
                pwd = decrypt(row["password_encrypted"], self.key)
                results.append({"id": row["id"], "password": pwd, "changed_at": row["changed_at"]})
            except Exception:
                continue
        return results

    def rollback_password(self, record_id: int) -> bool:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM password_history WHERE record_id = ? ORDER BY changed_at DESC LIMIT 1",
            (record_id,),
        )
        hist = cursor.fetchone()
        if not hist:
            return False
        cursor.execute("SELECT * FROM records WHERE id = ?", (record_id,))
        row = cursor.fetchone()
        if not row:
            return False
        new_updated_at = datetime.now().isoformat()
        cursor.execute(
            "UPDATE records SET password_encrypted = ?, record_hmac = ?, updated_at = ? WHERE id = ?",
            (
                hist["password_encrypted"],
                self._compute_record_hmac(
                    row["site_name_encrypted"],
                    row["username_encrypted"],
                    hist["password_encrypted"],
                    row["created_at"],
                    row["notes_encrypted"],
                    row["url_encrypted"] if row["url_encrypted"] else b"",
                    row["category"] if row["category"] else "其他",
                    row["expire_at"] if row["expire_at"] else "",
                    updated_at=new_updated_at,
                    clicked_count=row["clicked_count"] or 0,
                ),
                new_updated_at,
                record_id,
            ),
        )
        cursor.execute("DELETE FROM password_history WHERE id = ?", (hist["id"],))
        self.conn.commit()
        return True

    def is_password_reused(self, password: str, exclude_record_id: Optional[int] = None) -> bool:
        cursor = self.conn.cursor()
        query = "SELECT password_encrypted FROM password_history"
        params = []
        if exclude_record_id is not None:
            query += " WHERE record_id != ?"
            params.append(exclude_record_id)
        cursor.execute(query, params)
        for row in cursor.fetchall():
            try:
                pwd = decrypt(row["password_encrypted"], self.key)
                if hmac.compare_digest(pwd, password):
                    return True
            except Exception:
                continue
        return False

    def _compute_record_hmac(self, site_enc, username_enc, password_enc, created_at, notes_enc, url_enc=b"", category="", expire_at="", updated_at="", clicked_count=0, v1_compat=False):
        data = b"|".join([
            site_enc,
            username_enc,
            password_enc,
            created_at.encode("utf-8"),
            notes_enc if notes_enc else b"",
            url_enc if url_enc else b"",
            category.encode("utf-8"),
            expire_at.encode("utf-8"),
        ])
        if not v1_compat:
            # v2: 加入 updated_at 和 clicked_count 防止篡改
            data += b"|" + updated_at.encode("utf-8") + b"|" + str(clicked_count).encode("utf-8")
        return compute_hmac(self.hmac_key, data)

    def add_record(
        self,
        site_name: str,
        username: str,
        password: str,
        notes: Optional[str] = None,
        url: Optional[str] = None,
        category: str = "其他",
        expire_at: Optional[str] = None,
    ) -> int:
        if self.is_password_reused(password):
            print("警告: 此密码与历史记录中的密码相同")

        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        site_enc = encrypt(site_name, self.key)
        username_enc = encrypt(username, self.key)
        password_enc = encrypt(password, self.key)
        notes_enc = encrypt(notes, self.key) if notes else None
        url_enc = encrypt(url, self.key) if url else None
        if category not in CATEGORIES:
            category = "其他"
        record_hmac = self._compute_record_hmac(
            site_enc, username_enc, password_enc, now, notes_enc,
            url_enc if url_enc else b"", category, expire_at or "",
            updated_at=now, clicked_count=0,
        )

        cursor.execute(
            """INSERT INTO records
               (site_name_encrypted, username_encrypted, password_encrypted, created_at,
                notes_encrypted, record_hmac, url_encrypted, category, expire_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (site_enc, username_enc, password_enc, now,
             notes_enc, record_hmac, url_enc, category, expire_at, now),
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_record(self, record_id: int) -> Optional[dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM records WHERE id = ? AND deleted_at IS NULL", (record_id,))
        row = cursor.fetchone()
        if row:
            return self._decrypt_row(row)
        return None

    def search_records(self, site_name: str) -> list[dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM records WHERE deleted_at IS NULL")
        results = []
        keyword = site_name.lower()
        for row in cursor.fetchall():
            try:
                decrypted_site = decrypt(row["site_name_encrypted"], self.key)
                if keyword in decrypted_site.lower():
                    results.append(self._decrypt_row(row))
            except ValueError as e:
                if "完整性校验失败" in str(e):
                    print(f"警告: 记录 ID {row['id']} HMAC 校验失败，已跳过")
                    continue
                raise
            except Exception as e:
                print(f"警告: 记录 ID {row['id']} 解密失败: {e}，已跳过")
                continue
        return results

    def search_enhanced(self, query: str) -> list[dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM records WHERE deleted_at IS NULL")
        results = []
        keyword = query.lower()
        for row in cursor.fetchall():
            try:
                dec = self._decrypt_row(row)
                if (keyword in dec["site_name"].lower() or
                    keyword in dec["username"].lower() or
                    (dec["notes"] and keyword in dec["notes"].lower())):
                    results.append(dec)
            except ValueError as e:
                if "完整性校验失败" in str(e):
                    continue
                raise
            except Exception:
                continue
        return results

    def get_all_records(self) -> list[dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM records WHERE deleted_at IS NULL ORDER BY created_at DESC")
        results = []
        for row in cursor.fetchall():
            try:
                results.append(self._decrypt_row(row))
            except ValueError as e:
                if "完整性校验失败" in str(e):
                    print(f"警告: 记录 ID {row['id']} HMAC 校验失败，已跳过")
                    continue
                raise
            except Exception as e:
                print(f"警告: 记录 ID {row['id']} 解密失败: {e}，已跳过")
                continue
        return results

    def get_records_page(self, page: int = 1, page_size: int = PAGINATION_PAGE_SIZE) -> dict:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM records WHERE deleted_at IS NULL")
        total = cursor.fetchone()["cnt"]
        total_pages = max(1, (total + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))
        offset = (page - 1) * page_size
        cursor.execute("SELECT * FROM records WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT ? OFFSET ?", (page_size, offset))
        records = []
        for row in cursor.fetchall():
            try:
                records.append(self._decrypt_row(row))
            except Exception:
                continue
        return {"records": records, "page": page, "page_size": page_size, "total": total, "total_pages": total_pages}

    def update_record(
        self,
        record_id: int,
        site_name: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        notes: Optional[str] = None,
        url: Optional[str] = None,
        category: Optional[str] = None,
        expire_at: Optional[str] = None,
    ) -> bool:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM records WHERE id = ?", (record_id,))
        row = cursor.fetchone()
        if not row:
            return False

        if password is not None:
            try:
                old_password = decrypt(row["password_encrypted"], self.key)
                if hmac.compare_digest(old_password, password):
                    print("密码未变更")
                else:
                    if self.is_password_reused(password, exclude_record_id=record_id):
                        print("警告: 此密码近期使用过，建议使用不同的密码")
                    self._record_to_history(record_id, row["password_encrypted"])
            except Exception:
                pass

        site_enc = encrypt(site_name, self.key) if site_name is not None else row["site_name_encrypted"]
        username_enc = encrypt(username, self.key) if username is not None else row["username_encrypted"]
        password_enc = encrypt(password, self.key) if password is not None else row["password_encrypted"]
        notes_enc = encrypt(notes, self.key) if notes is not None else row["notes_encrypted"]
        url_enc = encrypt(url, self.key) if url is not None else row["url_encrypted"]
        cat = category if category is not None else (row["category"] or "其他")
        exp = expire_at if expire_at is not None else row["expire_at"]
        created_at = row["created_at"]
        now = datetime.now().isoformat()

        record_hmac = self._compute_record_hmac(
            site_enc, username_enc, password_enc, created_at, notes_enc,
            url_enc if url_enc else b"", cat, exp or "",
            updated_at=now, clicked_count=row["clicked_count"] or 0,
        )

        updates = []
        params = []
        if site_name is not None:
            updates.append("site_name_encrypted = ?"); params.append(site_enc)
        if username is not None:
            updates.append("username_encrypted = ?"); params.append(username_enc)
        if password is not None:
            updates.append("password_encrypted = ?"); params.append(password_enc)
        if notes is not None:
            updates.append("notes_encrypted = ?"); params.append(notes_enc)
        if url is not None:
            updates.append("url_encrypted = ?"); params.append(url_enc)
        if category is not None:
            updates.append("category = ?"); params.append(cat)
        if expire_at is not None:
            updates.append("expire_at = ?"); params.append(exp)

        updates.append("record_hmac = ?"); params.append(record_hmac)
        updates.append("updated_at = ?"); params.append(now)

        if not updates:
            return False
        params.append(record_id)
        cursor.execute(f"UPDATE records SET {', '.join(updates)} WHERE id = ?", params)
        self.conn.commit()
        return cursor.rowcount > 0

    def delete_record(self, record_id: int) -> bool:
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE records SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
            (datetime.now().isoformat(), record_id),
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def increment_clicked(self, record_id: int):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM records WHERE id = ?", (record_id,))
        row = cursor.fetchone()
        if not row:
            return
        new_count = (row["clicked_count"] or 0) + 1
        new_hmac = self._compute_record_hmac(
            row["site_name_encrypted"],
            row["username_encrypted"],
            row["password_encrypted"],
            row["created_at"],
            row["notes_encrypted"],
            row["url_encrypted"] if row["url_encrypted"] else b"",
            row["category"] if row["category"] else "其他",
            row["expire_at"] if row["expire_at"] else "",
            updated_at=row["updated_at"] or row["created_at"],
            clicked_count=new_count,
        )
        cursor.execute(
            "UPDATE records SET clicked_count = ?, record_hmac = ? WHERE id = ?",
            (new_count, new_hmac, record_id),
        )
        self.conn.commit()

    def _decrypt_row(self, row: sqlite3.Row) -> dict:
        record_hmac = row["record_hmac"]
        if record_hmac:
            updated_at = row["updated_at"] or row["created_at"]
            clicked_count = row["clicked_count"] or 0
            # 尝试 v2 HMAC（包含 updated_at 和 clicked_count）
            expected_hmac = self._compute_record_hmac(
                row["site_name_encrypted"],
                row["username_encrypted"],
                row["password_encrypted"],
                row["created_at"],
                row["notes_encrypted"],
                row["url_encrypted"] if row["url_encrypted"] else b"",
                row["category"] if row["category"] else "其他",
                row["expire_at"] if row["expire_at"] else "",
                updated_at=updated_at,
                clicked_count=clicked_count,
            )
            if not hmac.compare_digest(expected_hmac, record_hmac):
                # 回退到 v1 HMAC（不含 updated_at/clicked_count，兼容旧记录）
                expected_hmac_v1 = self._compute_record_hmac(
                    row["site_name_encrypted"],
                    row["username_encrypted"],
                    row["password_encrypted"],
                    row["created_at"],
                    row["notes_encrypted"],
                    row["url_encrypted"] if row["url_encrypted"] else b"",
                    row["category"] if row["category"] else "其他",
                    row["expire_at"] if row["expire_at"] else "",
                    v1_compat=True,
                )
                if not hmac.compare_digest(expected_hmac_v1, record_hmac):
                    raise ValueError(f"记录 ID {row['id']} 完整性校验失败，可能被篡改")

        result = {
            "id": row["id"],
            "site_name": decrypt(row["site_name_encrypted"], self.key),
            "username": decrypt(row["username_encrypted"], self.key),
            "password": decrypt(row["password_encrypted"], self.key),
            "created_at": row["created_at"],
            "notes": decrypt(row["notes_encrypted"], self.key) if row["notes_encrypted"] else None,
            "category": row["category"] or "其他",
            "expire_at": row["expire_at"],
            "updated_at": row["updated_at"],
            "clicked_count": row["clicked_count"] or 0,
        }
        if row["url_encrypted"]:
            result["url"] = decrypt(row["url_encrypted"], self.key)
        else:
            result["url"] = None
        return result

    def change_master_password(self, new_key: bytes):
        """重新加密所有记录和历史记录为新主密钥"""
        old_key = self.key
        cursor = self.conn.cursor()

        # 重新加密 records 表所有加密字段
        cursor.execute("SELECT * FROM records WHERE deleted_at IS NULL")
        rows = cursor.fetchall()
        for row in rows:
            try:
                site_plain = decrypt(row["site_name_encrypted"], old_key)
                user_plain = decrypt(row["username_encrypted"], old_key)
                pwd_plain = decrypt(row["password_encrypted"], old_key)
                notes_plain = decrypt(row["notes_encrypted"], old_key) if row["notes_encrypted"] else None
                url_plain = decrypt(row["url_encrypted"], old_key) if row["url_encrypted"] else None
            except Exception as e:
                print(f"跳过记录 {row['id']}: {e}")
                continue

            new_site = encrypt(site_plain, new_key)
            new_user = encrypt(user_plain, new_key)
            new_pwd = encrypt(pwd_plain, new_key)
            new_notes = encrypt(notes_plain, new_key) if notes_plain else None
            new_url = encrypt(url_plain, new_key) if url_plain else None
            cat = row["category"] or "其他"
            exp = row["expire_at"] or ""
            old_updated_at = row["updated_at"] or row["created_at"]
            new_updated_at = datetime.now().isoformat()
            clicked_count = row["clicked_count"] or 0

            tmp_key = new_key
            orig_hmac_key = self.hmac_key

            # temporarily compute hmac with new key
            self.key = new_key
            self.hmac_key = derive_hmac_key(new_key)
            new_hmac = self._compute_record_hmac(
                new_site, new_user, new_pwd, row["created_at"], new_notes,
                new_url if new_url else b"", cat, exp,
                updated_at=new_updated_at,
                clicked_count=clicked_count,
            )
            self.key = old_key
            self.hmac_key = orig_hmac_key

            cursor.execute(
                """UPDATE records SET
                   site_name_encrypted=?, username_encrypted=?, password_encrypted=?,
                   notes_encrypted=?, url_encrypted=?, record_hmac=?, updated_at=?, upgraded_at=?
                   WHERE id=?""",
                (new_site, new_user, new_pwd, new_notes, new_url, new_hmac, new_updated_at, new_updated_at, row["id"]),
            )

        # 重新加密 password_history 表
        cursor.execute("SELECT * FROM password_history")
        hist_rows = cursor.fetchall()
        for hrow in hist_rows:
            try:
                pwd_plain = decrypt(hrow["password_encrypted"], old_key)
            except Exception:
                continue
            new_pwd_enc = encrypt(pwd_plain, new_key)
            cursor.execute(
                "UPDATE password_history SET password_encrypted=? WHERE id=?",
                (new_pwd_enc, hrow["id"]),
            )

        self.conn.commit()
        self.key = new_key
        self.hmac_key = derive_hmac_key(new_key)

    def get_security_report(self) -> dict:
        weak_passwords = []
        reused_passwords = []
        expired_passwords = []
        total = 0
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM records WHERE deleted_at IS NULL")
        all_passwords = []
        for row in cursor.fetchall():
            try:
                rec = self._decrypt_row(row)
            except Exception:
                continue
            total += 1
            strength = check_password_strength(rec["password"])
            if strength == "弱":
                weak_passwords.append(rec)
            all_passwords.append(rec["password"])
            # 检查过期
            if rec["expire_at"]:
                try:
                    exp_date = datetime.fromisoformat(rec["expire_at"])
                    if datetime.now() > exp_date:
                        expired_passwords.append(rec)
                except (ValueError, TypeError):
                    pass
            elif rec["updated_at"]:
                try:
                    updated = datetime.fromisoformat(rec["updated_at"])
                    if datetime.now() - updated > timedelta(days=PASSWORD_EXPIRY_DAYS):
                        expired_passwords.append(rec)
                except (ValueError, TypeError):
                    pass
            else:
                try:
                    created = datetime.fromisoformat(rec["created_at"])
                    if datetime.now() - created > timedelta(days=PASSWORD_EXPIRY_DAYS):
                        expired_passwords.append(rec)
                except (ValueError, TypeError):
                    pass

        # 查重
        seen = {}
        for i, pwd in enumerate(all_passwords):
            if pwd in seen:
                reused_passwords.append(seen[pwd])
            else:
                seen[pwd] = i

        return {
            "total_records": total,
            "weak_passwords": weak_passwords,
            "weak_count": len(weak_passwords),
            "reused_passwords_count": len(reused_passwords),
            "expired_passwords": expired_passwords,
            "expired_count": len(expired_passwords),
        }

    def upgrade_record_hmacs(self):
        """将 v1 格式的 HMAC 记录升级到 v2（包含 updated_at/clicked_count）

        仅在首次运行时执行（通过 upgraded_at 字段判断）。
        不需要重新加密数据，只需重新计算 HMAC。
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM records WHERE upgraded_at IS NULL AND deleted_at IS NULL")
        rows = cursor.fetchall()
        upgraded = 0
        for row in rows:
            if not row["record_hmac"]:
                continue
            updated_at = row["updated_at"] or row["created_at"]
            clicked_count = row["clicked_count"] or 0

            # 先尝试 v2 — 已经是 v2 则跳过
            expected_v2 = self._compute_record_hmac(
                row["site_name_encrypted"], row["username_encrypted"],
                row["password_encrypted"], row["created_at"],
                row["notes_encrypted"],
                row["url_encrypted"] if row["url_encrypted"] else b"",
                row["category"] if row["category"] else "其他",
                row["expire_at"] if row["expire_at"] else "",
                updated_at=updated_at, clicked_count=clicked_count,
            )
            if hmac.compare_digest(expected_v2, row["record_hmac"]):
                cursor.execute(
                    "UPDATE records SET upgraded_at = ? WHERE id = ?",
                    (datetime.now().isoformat(), row["id"]),
                )
                upgraded += 1
                continue

            # 再验证 v1，如果匹配则升级为 v2
            expected_v1 = self._compute_record_hmac(
                row["site_name_encrypted"], row["username_encrypted"],
                row["password_encrypted"], row["created_at"],
                row["notes_encrypted"],
                row["url_encrypted"] if row["url_encrypted"] else b"",
                row["category"] if row["category"] else "其他",
                row["expire_at"] if row["expire_at"] else "",
                v1_compat=True,
            )
            if hmac.compare_digest(expected_v1, row["record_hmac"]):
                cursor.execute(
                    "UPDATE records SET record_hmac = ?, upgraded_at = ? WHERE id = ?",
                    (expected_v2, datetime.now().isoformat(), row["id"]),
                )
                upgraded += 1
        if upgraded > 0:
            self.conn.commit()

    def get_deleted_records(self) -> list[dict]:
        """获取回收站中的所有记录"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM records WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC")
        results = []
        for row in cursor.fetchall():
            try:
                rec = self._decrypt_row(row)
                rec["deleted_at"] = row["deleted_at"]
                results.append(rec)
            except Exception:
                continue
        return results

    def restore_record(self, record_id: int) -> bool:
        """从回收站恢复记录"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM records WHERE id = ? AND deleted_at IS NOT NULL", (record_id,))
        row = cursor.fetchone()
        if not row:
            return False
        new_updated_at = datetime.now().isoformat()
        new_hmac = self._compute_record_hmac(
            row["site_name_encrypted"], row["username_encrypted"],
            row["password_encrypted"], row["created_at"],
            row["notes_encrypted"],
            row["url_encrypted"] if row["url_encrypted"] else b"",
            row["category"] if row["category"] else "其他",
            row["expire_at"] if row["expire_at"] else "",
            updated_at=new_updated_at,
            clicked_count=row["clicked_count"] or 0,
        )
        cursor.execute(
            "UPDATE records SET deleted_at = NULL, updated_at = ?, record_hmac = ? WHERE id = ?",
            (new_updated_at, new_hmac, record_id),
        )
        self.conn.commit()
        return True

    def permanent_delete(self, record_id: int) -> bool:
        """永久删除记录（不可恢复）"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM password_history WHERE record_id = ?", (record_id,))
        cursor.execute("DELETE FROM records WHERE id = ?", (record_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    def empty_recycle_bin(self) -> int:
        """清空回收站，返回删除的记录数"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM records WHERE deleted_at IS NOT NULL")
        ids = [r["id"] for r in cursor.fetchall()]
        if not ids:
            return 0
        for rid in ids:
            cursor.execute("DELETE FROM password_history WHERE record_id = ?", (rid,))
        cursor.execute("DELETE FROM records WHERE deleted_at IS NOT NULL")
        self.conn.commit()
        return len(ids)

    def cleanup_expired_recycle(self, days: int = 30) -> int:
        """清理回收站中超过指定天数的记录"""
        cursor = self.conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        cursor.execute("SELECT id FROM records WHERE deleted_at IS NOT NULL AND deleted_at < ?", (cutoff,))
        ids = [r["id"] for r in cursor.fetchall()]
        if not ids:
            return 0
        for rid in ids:
            cursor.execute("DELETE FROM password_history WHERE record_id = ?", (rid,))
        cursor.execute("DELETE FROM records WHERE deleted_at IS NOT NULL AND deleted_at < ?", (cutoff,))
        self.conn.commit()
        return len(ids)

    def batch_delete_records(self, record_ids: list[int]) -> int:
        """批量软删除记录"""
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        count = 0
        for rid in record_ids:
            cursor.execute(
                "UPDATE records SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
                (now, rid),
            )
            count += cursor.rowcount
        self.conn.commit()
        return count

    def batch_update_category(self, record_ids: list[int], category: str) -> int:
        """批量更新记录分类"""
        if category not in CATEGORIES:
            category = "其他"
        cursor = self.conn.cursor()
        count = 0
        for rid in record_ids:
            cursor.execute("SELECT * FROM records WHERE id = ? AND deleted_at IS NULL", (rid,))
            row = cursor.fetchone()
            if not row:
                continue
            now = datetime.now().isoformat()
            new_hmac = self._compute_record_hmac(
                row["site_name_encrypted"], row["username_encrypted"],
                row["password_encrypted"], row["created_at"],
                row["notes_encrypted"],
                row["url_encrypted"] if row["url_encrypted"] else b"",
                category,
                row["expire_at"] if row["expire_at"] else "",
                updated_at=now,
                clicked_count=row["clicked_count"] or 0,
            )
            cursor.execute(
                "UPDATE records SET category = ?, record_hmac = ?, updated_at = ? WHERE id = ?",
                (category, new_hmac, now, rid),
            )
            count += cursor.rowcount
        self.conn.commit()
        return count

    def close(self):
        self.conn.close()
