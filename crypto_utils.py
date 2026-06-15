"""加密/解密/密钥派生工具"""
import os
import hashlib
import hmac
import struct
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from config import PBKDF2_ITERATIONS, SALT_LENGTH, KEY_LENGTH, NONCE_LENGTH, DB_DIR


TEST_PLAINTEXT_LENGTH = 32  # R2: 随机测试向量长度


class RateLimiter:
    """R1: 登录速率限制器 - 指数退避（持久化到磁盘）

    策略: 连续失败 3次→1s, 5次→5s, 10次→60s, 15次→300s
    成功认证后重置计数。
    失败次数和时间持久化到磁盘文件，防止重启绕过。
    """

    _RATE_LIMIT_FILE = DB_DIR / "rate_limit.json"

    def __init__(self):
        self._failures = 0
        self._last_fail_time = 0.0
        self._load()

    def _load(self):
        """从磁盘加载速率限制状态"""
        try:
            if self._RATE_LIMIT_FILE.exists():
                import json as _json
                data = _json.loads(self._RATE_LIMIT_FILE.read_text(encoding="utf-8"))
                self._failures = max(0, int(data.get("failures", 0)))
                self._last_fail_time = float(data.get("last_fail_time", 0.0))
        except (ValueError, KeyError, OSError, TypeError):
            self._failures = 0
            self._last_fail_time = 0.0

    def _save(self):
        """将速率限制状态保存到磁盘"""
        try:
            import json as _json
            DB_DIR.mkdir(parents=True, exist_ok=True)
            self._RATE_LIMIT_FILE.write_text(
                _json.dumps({
                    "failures": self._failures,
                    "last_fail_time": self._last_fail_time,
                }),
                encoding="utf-8",
            )
        except OSError:
            pass

    def record_failure(self):
        """记录一次认证失败"""
        import time
        self._failures += 1
        self._last_fail_time = time.time()
        self._save()

    def record_success(self):
        """认证成功，重置计数器"""
        self._failures = 0
        self._save()

    def get_wait_time(self) -> float:
        """根据失败次数计算需要等待的秒数"""
        if self._failures < 3:
            return 0.0
        elif self._failures < 5:
            return 1.0
        elif self._failures < 10:
            return 5.0
        elif self._failures < 15:
            return 60.0
        else:
            return 300.0

    def check_and_wait(self) -> tuple[bool, float]:
        """检查是否需要等待，返回 (是否可继续, 等待秒数)"""
        import time
        wait = self.get_wait_time()
        if wait > 0:
            elapsed = time.time() - self._last_fail_time
            remaining = max(0.0, wait - elapsed)
            if remaining > 0:
                return False, remaining
        return True, 0.0

    def get_failure_count(self) -> int:
        return self._failures


def derive_key(master_password: str, salt: bytes) -> bytes:
    """从主密码派生AES-256密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt(plaintext: str, key: bytes) -> bytes:
    """AES-256-GCM加密"""
    nonce = os.urandom(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ciphertext


def decrypt(encrypted_data: bytes, key: bytes) -> str:
    """AES-256-GCM解密"""
    nonce = encrypted_data[:NONCE_LENGTH]
    ciphertext = encrypted_data[NONCE_LENGTH:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def generate_salt() -> bytes:
    """生成随机盐值"""
    return os.urandom(SALT_LENGTH)


def init_vault(master_password: str) -> tuple[bytes, bytes]:
    """初始化密码库，返回(salt, encrypted_test)
    
    R2: 使用随机测试向量替代固定字符串，防止已知明文攻击。
    test.bin 格式: [4字节明文长度][明文][加密数据(nonce+ciphertext+tag)]
    """
    salt = generate_salt()
    key = derive_key(master_password, salt)
    test_plaintext = os.urandom(TEST_PLAINTEXT_LENGTH)
    encrypted_test = encrypt(test_plaintext.hex(), key)
    # 存储格式: 长度(4字节) + 随机明文 + 加密数据
    payload = struct.pack("<I", TEST_PLAINTEXT_LENGTH) + test_plaintext + encrypted_test
    return salt, payload


def get_test_plaintext_from_payload(payload: bytes) -> tuple[bytes, bytes]:
    """从 payload 中提取随机明文和加密数据"""
    pt_len = struct.unpack("<I", payload[:4])[0]
    test_plaintext = payload[4:4 + pt_len]
    encrypted_test = payload[4 + pt_len:]
    return test_plaintext, encrypted_test


def verify_master_password(master_password: str, salt: bytes, test_payload: bytes) -> bool:
    """验证主密码是否正确
    
    R2: 对比解密结果是否匹配随机测试向量；使用常数时间比较。
    R1: 不在此函数中实现限速，由调用方处理。
    向后兼容: 自动检测新版(v2)随机向量和旧版(v1)"vault_test"格式。
    """
    key = derive_key(master_password, salt)
    # 尝试新版格式 (v2+): [4字节长度][随机明文][加密数据]
    try:
        test_plaintext, encrypted_test = get_test_plaintext_from_payload(test_payload)
        decrypted_hex = decrypt(encrypted_test, key)
        if hmac.compare_digest(decrypted_hex, test_plaintext.hex()):
            return True
    except (InvalidTag, ValueError, UnicodeDecodeError, struct.error, IndexError):
        pass
    # 尝试旧版格式 (v1): 直接加密数据，固定明文 "vault_test"
    try:
        old_test = test_payload  # v1 没有头部，整段是加密数据
        decrypted_old = decrypt(old_test, key)
        return hmac.compare_digest(decrypted_old, "vault_test")
    except (InvalidTag, ValueError, UnicodeDecodeError, IndexError):
        return False


def get_vault_paths() -> tuple[Path, Path]:
    """获取盐值和测试数据文件路径"""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    salt_path = DB_DIR / "salt.bin"
    test_path = DB_DIR / "test.bin"
    return salt_path, test_path


def derive_backup_key(master_key: bytes) -> bytes:
    """从主密钥派生独立的备份密钥 - FIXED: 备份使用独立密钥，隔离风险"""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=None,
        info=b"password_manager_backup_v1",
    )
    return hkdf.derive(master_key)


def derive_hmac_key(master_key: bytes) -> bytes:
    """从主密钥派生独立的 HMAC 密钥 - FIXED: 用于数据库完整性校验"""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=None,
        info=b"password_manager_hmac_v1",
    )
    return hkdf.derive(master_key)


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """计算 HMAC-SHA256 - FIXED: 数据库完整性校验"""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected_hmac: bytes) -> bool:
    """验证 HMAC - FIXED: 常数时间比较防止时序攻击"""
    computed = compute_hmac(key, data)
    return hmac.compare_digest(computed, expected_hmac)