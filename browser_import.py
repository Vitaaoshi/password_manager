"""从 Edge/Chrome 浏览器导入密码"""
import os
import json
import base64
import sqlite3
import shutil
import tempfile
import ctypes
import ctypes.wintypes
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _decrypt_dpapi(data: bytes) -> Optional[bytes]:
    """用 Windows DPAPI 解密数据"""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    LocalFree = kernel32.LocalFree

    blob_in = DATA_BLOB(len(data), ctypes.cast(data, ctypes.POINTER(ctypes.c_ubyte)))
    blob_out = DATA_BLOB()

    if crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        LocalFree(blob_out.pbData)
        return result
    return None


def _get_edge_encryption_key() -> Optional[bytes]:
    """从 Edge Local State 获取 AES 加密密钥"""
    local_state_path = Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "Edge" / "User Data" / "Local State"
    if not local_state_path.exists():
        return None
    try:
        data = json.loads(local_state_path.read_text(encoding="utf-8"))
        encrypted_key_b64 = data.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key_b64:
            return None
        encrypted_key = base64.b64decode(encrypted_key_b64)
        # 去掉 "DPAPI" 前缀 (5 字节)
        if encrypted_key[:5] == b"DPAPI":
            encrypted_key = encrypted_key[5:]
        return _decrypt_dpapi(encrypted_key)
    except Exception:
        return None


def _decrypt_chromium_password(encrypted_value: bytes, key: bytes) -> Optional[str]:
    """解密 Chromium 加密的密码"""
    try:
        version = encrypted_value[:3]
        if version not in (b"v10", b"v11", b"v20"):
            return None
        nonce = encrypted_value[3:15]
        ciphertext = encrypted_value[15:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        return None


def _check_edge_v20_encryption() -> bool:
    """检查 Edge 是否使用了 v20 应用绑定加密（无法自动导入）"""
    local_state_path = Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "Edge" / "User Data" / "Local State"
    if not local_state_path.exists():
        return False
    try:
        data = json.loads(local_state_path.read_text(encoding="utf-8"))
        oscrypt = data.get("os_crypt", {})
        return bool(oscrypt.get("app_bound_encrypted_key"))
    except Exception:
        return False


def import_from_edge(db) -> tuple[int, int]:
    """从 Edge 浏览器导入密码，返回 (成功数, 总数)"""
    key = _get_edge_encryption_key()
    if key is None:
        return -1, 0

    login_data_path = Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "Edge" / "User Data" / "Default" / "Login Data"
    if not login_data_path.exists():
        return 0, 0

    # 检查 v20 应用绑定加密
    v20_protected = _check_edge_v20_encryption()
    if v20_protected:
        return -2, 0

    # 复制数据库（Edge 可能锁定它）
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp_path = tmp.name
    tmp.close()
    try:
        shutil.copy2(str(login_data_path), tmp_path)
        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        rows = cursor.fetchall()
        conn.close()

        success = 0
        for origin_url, username, pwd_enc in rows:
            if not username or not pwd_enc:
                continue
            password = _decrypt_chromium_password(pwd_enc, key)
            if password is None:
                continue
            # 提取网站名称
            from urllib.parse import urlparse
            parsed = urlparse(origin_url)
            site_name = parsed.netloc or origin_url
            try:
                db.add_record(site_name, username, password, url=origin_url)
                success += 1
            except Exception:
                continue
        return success, len(rows)
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def import_from_chrome(db) -> tuple[int, int]:
    """从 Chrome 浏览器导入密码"""
    key = _get_chrome_encryption_key()
    if key is None:
        return 0, 0

    login_data_path = Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data" / "Default" / "Login Data"
    if not login_data_path.exists():
        return 0, 0

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp_path = tmp.name
    tmp.close()
    try:
        shutil.copy2(str(login_data_path), tmp_path)
        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        rows = cursor.fetchall()
        conn.close()

        success = 0
        for origin_url, username, pwd_enc in rows:
            if not username or not pwd_enc:
                continue
            password = _decrypt_chromium_password(pwd_enc, key)
            if password is None:
                continue
            from urllib.parse import urlparse
            parsed = urlparse(origin_url)
            site_name = parsed.netloc or origin_url
            try:
                db.add_record(site_name, username, password, url=origin_url)
                success += 1
            except Exception:
                continue
        return success, len(rows)
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _get_chrome_encryption_key() -> Optional[bytes]:
    """从 Chrome Local State 获取 AES 加密密钥"""
    local_state_path = Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data" / "Local State"
    if not local_state_path.exists():
        return None
    try:
        data = json.loads(local_state_path.read_text(encoding="utf-8"))
        encrypted_key_b64 = data.get("os_crypt", {}).get("encrypted_key")
        if not encrypted_key_b64:
            return None
        encrypted_key = base64.b64decode(encrypted_key_b64)
        if encrypted_key[:5] == b"DPAPI":
            encrypted_key = encrypted_key[5:]
        return _decrypt_dpapi(encrypted_key)
    except Exception:
        return None


def _get_firefox_profile_dir() -> Optional[Path]:
    """获取 Firefox 默认配置文件目录"""
    try:
        firefox_dir = Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles"
        if not firefox_dir.exists():
            return None
        for profile in firefox_dir.iterdir():
            if profile.is_dir() and profile.name.endswith(".default-release"):
                return profile
            if profile.is_dir() and profile.name.endswith(".default"):
                return profile
        # 回退：返回第一个找到的配置文件
        for profile in firefox_dir.iterdir():
            if profile.is_dir():
                return profile
        return None
    except Exception:
        return None


def import_from_firefox(db) -> tuple[int, int]:
    """从 Firefox 浏览器导入密码（读取 logins.json 明文存储）

    注意: Firefox 默认对密码使用 AES-CBC + PBKDF2 加密，需要 key4.db 解密。
    如果 Firefox 设置了主密码，则无法自动导入。
    此实现尝试读取 logins.json，如果密码是加密的则建议手动导出 CSV。
    """
    profile_dir = _get_firefox_profile_dir()
    if profile_dir is None:
        return -1, 0

    logins_json = profile_dir / "logins.json"
    if not logins_json.exists():
        return 0, 0

    try:
        import json
        data = json.loads(logins_json.read_text(encoding="utf-8"))
        logins = data.get("logins", [])
        if not logins:
            return 0, 0

        # Firefox 的 logins.json 中密码是加密的（base64 + AES-CBC）
        # 没有 key4.db 无法解密，建议用户手动导出
        # 检查是否有明文密码（极少数情况）
        success = 0
        for login in logins:
            hostname = login.get("hostname", "")
            username = login.get("encryptedUsername", "")
            password = login.get("encryptedPassword", "")

            # 如果字段以 base64 编码的加密数据开始，说明是加密的
            if not hostname:
                continue

            # Firefox 的密码都是加密的，无法直接读取
            # 返回特殊代码 -3 表示需要手动导出
            return -3, len(logins)

        return success, len(logins)
    except Exception:
        return -1, 0
