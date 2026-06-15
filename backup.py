"""备份与恢复功能"""
import csv
import json
import hmac
import hashlib
from pathlib import Path
from typing import Optional
from datetime import datetime

from crypto_utils import encrypt, decrypt, derive_backup_key

BACKUP_VERSION = "1.0"
BACKUP_MAGIC = b"PMBAK01\0"  # R7: 8字节魔数，用于文件格式识别
BACKUP_MAGIC_LEN = 8
BACKUP_HMAC_LEN = 32  # SHA-256


def _is_safe_path(path: Path) -> bool:
    """检查备份路径是否在安全范围内，防止路径遍历"""
    try:
        resolved = path.resolve()
        home = Path.home().resolve()
        cwd = Path.cwd().resolve()
        return str(resolved).startswith(str(home)) or str(resolved).startswith(str(cwd))
    except (ValueError, OSError):
        return False


def _compute_backup_hmac(backup_key: bytes, data: bytes) -> bytes:
    """R7: 计算备份文件 HMAC"""
    return hmac.new(backup_key, data, hashlib.sha256).digest()


def _pack_backup(backup_key: bytes, ciphertext: bytes) -> bytes:
    """R7: 打包备份文件: [8字节魔数][32字节HMAC][密文]"""
    file_hmac = _compute_backup_hmac(backup_key, ciphertext)
    return BACKUP_MAGIC + file_hmac + ciphertext


def _unpack_backup(backup_key: bytes, raw: bytes) -> Optional[bytes]:
    """R7: 解包并验证备份文件，成功返回密文，失败返回 None"""
    if len(raw) < BACKUP_MAGIC_LEN + BACKUP_HMAC_LEN:
        return None
    magic = raw[:BACKUP_MAGIC_LEN]
    if magic != BACKUP_MAGIC:
        # 尝试旧版格式（无魔数头，整段为密文）
        return raw
    stored_hmac = raw[BACKUP_MAGIC_LEN:BACKUP_MAGIC_LEN + BACKUP_HMAC_LEN]
    ciphertext = raw[BACKUP_MAGIC_LEN + BACKUP_HMAC_LEN:]
    expected_hmac = _compute_backup_hmac(backup_key, ciphertext)
    if not hmac.compare_digest(stored_hmac, expected_hmac):
        print("备份文件完整性校验失败，文件可能已损坏或被篡改")
        return None
    return ciphertext


def export_backup(records: list[dict], master_key: bytes, backup_path: str) -> bool:
    """导出加密备份文件 - FIXED: 使用派生的独立备份密钥，R7: 添加 HMAC 完整性头"""
    try:
        backup_key = derive_backup_key(master_key)

        backup_data = {
            "version": BACKUP_VERSION,
            "created_at": datetime.now().isoformat(),
            "records": records,
        }
        json_data = json.dumps(backup_data, ensure_ascii=False, indent=2)
        encrypted = encrypt(json_data, backup_key)
        packed = _pack_backup(backup_key, encrypted)

        path = Path(backup_path)
        # FIXED: 路径遍历防护
        if not _is_safe_path(path):
            print(f"导出失败: 路径不合法，禁止写入系统目录: {path}")
            return False
        # FIXED: 检查文件是否已存在，避免静默覆盖
        if path.exists():
            confirm = input(f"文件 {path} 已存在，是否覆盖? (y/n): ").strip().lower()
            if confirm != "y":
                print("已取消导出")
                return False

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(packed)
        return True
    except Exception as e:
        print(f"导出备份失败: {e}")
        return False


def import_backup(backup_path: str, master_key: bytes) -> Optional[list[dict]]:
    """从加密备份文件恢复 - FIXED: 派生独立密钥, R7: 验证 HMAC 完整性"""
    try:
        backup_key = derive_backup_key(master_key)

        path = Path(backup_path)
        # FIXED: 路径遍历防护
        if not _is_safe_path(path):
            print(f"导入失败: 路径不合法: {path}")
            return None
        if not path.exists():
            print("备份文件不存在")
            return None

        raw = path.read_bytes()
        # R7: 解包并验证 HMAC
        encrypted = _unpack_backup(backup_key, raw)
        if encrypted is None:
            return None

        json_data = decrypt(encrypted, backup_key)
        backup_data = json.loads(json_data)

        # FIXED: 版本兼容性检查 - 同主版本号向后兼容
        file_version = backup_data.get("version", "0.0")
        try:
            file_major = int(file_version.split(".")[0])
            current_major = int(BACKUP_VERSION.split(".")[0])
        except (ValueError, IndexError):
            file_major, current_major = 0, int(BACKUP_VERSION.split(".")[0])
        if file_major > current_major:
            print(f"备份文件版本过新: 文件版本={file_version}, 当前版本={BACKUP_VERSION}")
            print("请升级密码管理器后重试")
            return None
        if file_major < current_major:
            print(f"提示: 备份文件来自旧版本({file_version})，部分字段可能缺失，将使用默认值")

        if "records" not in backup_data:
            print("备份文件格式错误")
            return None

        return backup_data["records"]
    except Exception as e:
        print(f"恢复备份失败: {e}")
        return None


def export_json_plain(records: list[dict], output_path: str) -> bool:
    """导出纯文本 JSON（无加密，仅包含明文密码）"""
    try:
        path = Path(output_path)
        if not _is_safe_path(path):
            print(f"导出失败: 路径不合法: {path}")
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        data = []
        for r in records:
            data.append({
                "site_name": r.get("site_name", ""),
                "username": r.get("username", ""),
                "password": r.get("password", ""),
                "url": r.get("url", ""),
                "category": r.get("category", "其他"),
                "notes": r.get("notes", ""),
                "created_at": r.get("created_at", ""),
                "expire_at": r.get("expire_at", ""),
            })
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return True
    except Exception as e:
        print(f"导出 JSON 失败: {e}")
        return False


def import_csv(csv_path: str) -> Optional[list[dict]]:
    """导入 CSV 文件（支持 Edge/Chrome 导出的格式及通用格式）"""
    try:
        path = Path(csv_path)
        if not path.exists():
            print("CSV 文件不存在")
            return None
        if not _is_safe_path(path):
            print(f"导入失败: 路径不合法: {path}")
            return None

        records = []
        with open(str(path), encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            rows = list(reader)
            if not rows:
                return None

            header = [h.strip().lower() for h in rows[0]]

            col = {}
            for name in ("name", "url", "username", "password", "notes", "note"):
                try:
                    col[name] = header.index(name)
                except ValueError:
                    col[name] = -1

            for row in rows[1:]:
                if len(row) < 2:
                    continue
                site_name = row[col["name"]].strip() if col["name"] >= 0 else ""
                url = row[col["url"]].strip() if col["url"] >= 0 else ""
                username = row[col["username"]].strip() if col["username"] >= 0 else ""
                password = row[col["password"]].strip() if col["password"] >= 0 else ""
                notes_col = col["notes"] if col["notes"] >= 0 else col["note"]
                notes = row[notes_col].strip() if notes_col >= 0 else ""
                if not site_name or not password:
                    continue
                records.append({
                    "site_name": site_name,
                    "url": url,
                    "username": username,
                    "password": password,
                    "notes": notes,
                    "category": "其他",
                })
        return records
    except Exception as e:
        print(f"导入 CSV 失败: {e}")
        return None


def import_bitwarden_csv(csv_path: str) -> Optional[list[dict]]:
    """导入 Bitwarden CSV 导出文件

    Bitwarden 导出格式: folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
    """
    try:
        path = Path(csv_path)
        if not path.exists():
            return None
        if not _is_safe_path(path):
            return None

        records = []
        with open(str(path), encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            rows = list(reader)
            if not rows:
                return None

            header = [h.strip().lower() for h in rows[0]]

            col = {}
            for name in ("name", "login_uri", "login_username", "login_password", "notes", "folder", "type"):
                try:
                    col[name] = header.index(name)
                except ValueError:
                    col[name] = -1

            for row in rows[1:]:
                if len(row) < 2:
                    continue
                # 只导入登录类型
                item_type = row[col["type"]].strip() if col["type"] >= 0 else "login"
                if item_type.lower() != "login":
                    continue

                site_name = row[col["name"]].strip() if col["name"] >= 0 else ""
                url = row[col["login_uri"]].strip() if col["login_uri"] >= 0 else ""
                username = row[col["login_username"]].strip() if col["login_username"] >= 0 else ""
                password = row[col["login_password"]].strip() if col["login_password"] >= 0 else ""
                notes = row[col["notes"]].strip() if col["notes"] >= 0 else ""

                if not site_name or not password:
                    continue
                records.append({
                    "site_name": site_name,
                    "url": url,
                    "username": username or site_name,
                    "password": password,
                    "notes": notes,
                    "category": "其他",
                })
        return records
    except Exception as e:
        print(f"导入 Bitwarden CSV 失败: {e}")
        return None


def import_1password_csv(csv_path: str) -> Optional[list[dict]]:
    """导入 1Password CSV 导出文件

    1Password 导出格式可能包含: Title, Url, Username, Password, Notes, Type
    或其他变体
    """
    try:
        path = Path(csv_path)
        if not path.exists():
            return None
        if not _is_safe_path(path):
            return None

        records = []
        with open(str(path), encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            rows = list(reader)
            if not rows:
                return None

            header = [h.strip().lower() for h in rows[0]]

            # 1Password 有多种列名格式，做宽泛匹配
            col = {}
            for target, aliases in {
                "title": ["title", "name"],
                "url": ["url", "website", "login_uri"],
                "username": ["username", "login_username", "login name"],
                "password": ["password", "login_password"],
                "notes": ["notes", "note"],
                "type": ["type"],
            }.items():
                col[target] = -1
                for alias in aliases:
                    try:
                        col[target] = header.index(alias)
                        break
                    except ValueError:
                        continue

            for row in rows[1:]:
                if len(row) < 2:
                    continue
                site_name = row[col["title"]].strip() if col["title"] >= 0 else ""
                url = row[col["url"]].strip() if col["url"] >= 0 else ""
                username = row[col["username"]].strip() if col["username"] >= 0 else ""
                password = row[col["password"]].strip() if col["password"] >= 0 else ""
                notes = row[col["notes"]].strip() if col["notes"] >= 0 else ""

                if not site_name or not password:
                    continue
                records.append({
                    "site_name": site_name,
                    "url": url,
                    "username": username or site_name,
                    "password": password,
                    "notes": notes,
                    "category": "其他",
                })
        return records
    except Exception as e:
        print(f"导入 1Password CSV 失败: {e}")
        return None


def export_csv(records: list[dict], output_path: str) -> bool:
    """导出 CSV（无加密，包含明文密码）"""
    try:
        path = Path(output_path)
        if not _is_safe_path(path):
            print(f"导出失败: 路径不合法: {path}")
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        import csv as csv_module
        with open(str(path), "w", newline="", encoding="utf-8-sig") as f:
            writer = csv_module.writer(f)
            writer.writerow(["site_name", "username", "password", "url", "category", "notes", "created_at", "expire_at"])
            for r in records:
                writer.writerow([
                    r.get("site_name", ""),
                    r.get("username", ""),
                    r.get("password", ""),
                    r.get("url", ""),
                    r.get("category", "其他"),
                    r.get("notes", ""),
                    r.get("created_at", ""),
                    r.get("expire_at", ""),
                ])
        return True
    except Exception as e:
        print(f"导出 CSV 失败: {e}")
        return False
