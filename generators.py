"""随机数/密码/用户名生成器"""
import secrets
import string
import math
from typing import Optional

from config import (
    DEFAULT_PASSWORD_LENGTH,
    DEFAULT_CHARSET,
    CHINESE_SURNAMES,
    CHINESE_NAMES,
    CHINESE_DOUBLE_NAMES,
    SPECIAL_CHARS,
    ENGLISH_STYLES,
    ENGLISH_FIRST_NAMES,
    ENGLISH_LAST_NAMES,
    NICKNAME_PREFIXES,
    NICKNAME_SUFFIXES,
    POPULAR_NICKNAMES,
)


def generate_random_number(min_val: int, max_val: int) -> int:
    return secrets.randbelow(max_val - min_val + 1) + min_val


def generate_random_digit_string(length: int) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


def generate_password(
    length: int = DEFAULT_PASSWORD_LENGTH,
    charset_config: Optional[dict] = None,
) -> str:
    if charset_config is None:
        charset_config = DEFAULT_CHARSET.copy()
    charset = ""
    if charset_config.get("uppercase", False):
        charset += string.ascii_uppercase
    if charset_config.get("lowercase", False):
        charset += string.ascii_lowercase
    if charset_config.get("digits", False):
        charset += string.digits
    if charset_config.get("special", False):
        charset += SPECIAL_CHARS
    if not charset:
        charset = string.ascii_letters + string.digits
    return "".join(secrets.choice(charset) for _ in range(length))


# 常见弱密码黑名单（Top 100 常见弱密码，用于强度检测）
_COMMON_WEAK_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
    "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
    "letmein", "football", "shadow", "michael", "login", "starwars",
    "admin", "welcome", "hello", "charlie", "donald", "password1",
    "qwerty123", "aa123456", "access", "flower", "hottie", "loveme",
    "zaq1zaq1", "password123", "test", "guest", "master123", "changeme",
    "abcdef", "000000", "1234", "12345", "123456789", "1234567890",
    "passw0rd", "p@ssword", "p@ssw0rd", "admin123", "root", "toor",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx", "qazwsx",
    "q1w2e3r4", "q1w2e3", "abc123456", "aaaaaa", "121212", "696969",
}

# 键盘序列模式（用于检测键盘连续字符）
_KEYBOARD_SEQUENCES = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321",
    "qazwsxedc", "1qaz2wsx3edc",
]


def _has_keyboard_sequence(password: str, min_len: int = 4) -> int:
    """检测密码中包含的键盘连续序列数量"""
    lower = password.lower()
    count = 0
    for seq in _KEYBOARD_SEQUENCES:
        for i in range(len(seq) - min_len + 1):
            for length in range(min_len, len(seq) - i + 1):
                pattern = seq[i:i + length]
                if pattern in lower:
                    count += 1
                # 也检查反向
                if pattern[::-1] in lower:
                    count += 1
    return count


def _has_repeated_chars(password: str) -> tuple[bool, int]:
    """检测重复字符模式，返回 (是否有重复, 最长连续重复长度)"""
    if not password:
        return False, 0
    max_repeat = 1
    current_repeat = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            current_repeat += 1
            max_repeat = max(max_repeat, current_repeat)
        else:
            current_repeat = 1
    # 3个以上连续相同字符视为弱
    return max_repeat >= 3, max_repeat


def calculate_password_strength(password: str) -> tuple[str, float]:
    """综合评估密码强度，考虑熵值、常见弱密码、键盘序列、重复字符等因素"""
    if not password:
        return "弱", 0.0

    # 检查常见弱密码（不区分大小写）
    if password.lower() in _COMMON_WEAK_PASSWORDS:
        return "弱", 0.0

    # 计算基础字符集大小
    charset_size = 0
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in SPECIAL_CHARS for c in password):
        charset_size += len(SPECIAL_CHARS)
    if charset_size == 0:
        charset_size = 1

    base_entropy = math.log2(charset_size) * len(password)

    # --- 惩罚因子 ---
    penalty = 0.0

    # 惩罚1: 键盘连续序列
    kb_count = _has_keyboard_sequence(password)
    if kb_count > 0:
        penalty += 15.0 * kb_count

    # 惩罚2: 重复字符 (如 aaaaaa)
    has_repeat, max_repeat = _has_repeated_chars(password)
    if has_repeat:
        penalty += 5.0 * (max_repeat - 2)

    # 惩罚3: 纯数字且过短
    if password.isdigit() and len(password) < 10:
        penalty += 25.0

    # 惩罚4: 全相同字符类型（如全小写、全数字）
    unique_types = sum([
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(c in SPECIAL_CHARS for c in password),
    ])
    if unique_types <= 1:
        penalty += 15.0

    # 惩罚5: 唯一字符占比过低（如 aabbaabb 模式）
    unique_ratio = len(set(password)) / len(password)
    if unique_ratio < 0.4 and len(password) > 6:
        penalty += 10.0

    effective_entropy = max(0.0, base_entropy - penalty)

    if effective_entropy < 28:
        return "弱", effective_entropy
    elif effective_entropy < 40:
        return "中", effective_entropy
    elif effective_entropy < 60:
        return "强", effective_entropy
    else:
        return "极强", effective_entropy


def generate_chinese_username(length: Optional[int] = None) -> str:
    """生成中文姓名，length=总字数(2-4)，默认随机"""
    # 预过滤：确保名字池按字数精确匹配
    single_names = [n for n in CHINESE_NAMES if len(n) == 1]
    double_names = [n for n in CHINESE_NAMES if len(n) == 2]
    surname = secrets.choice(CHINESE_SURNAMES)
    if length is None:
        length = secrets.choice([2, 3, 4])
    given_len = length - 1
    if given_len == 1:
        given = secrets.choice(single_names)
    elif given_len == 2:
        given = secrets.choice(double_names if double_names else CHINESE_DOUBLE_NAMES)
    else:
        given = secrets.choice(double_names if double_names else CHINESE_DOUBLE_NAMES) + secrets.choice(single_names)
    return surname + given


def generate_chinese_full_name(variation: str = "classic") -> str:
    """生成中文全名，variation: classic / modern / literary"""
    single_names = [n for n in CHINESE_NAMES if len(n) == 1]
    surname = secrets.choice(CHINESE_SURNAMES)
    if variation == "modern":
        given = secrets.choice(CHINESE_DOUBLE_NAMES)
    elif variation == "literary":
        if secrets.choice([True, False]):
            given = secrets.choice(single_names) + secrets.choice(single_names)
        else:
            given = secrets.choice(CHINESE_DOUBLE_NAMES)
    else:
        if secrets.choice([True, False]):
            given = secrets.choice(single_names)
        else:
            given = secrets.choice(CHINESE_DOUBLE_NAMES)
    return surname + given


def generate_chinese_nickname() -> str:
    """生成中文网名"""
    mode = secrets.choice(["popular", "prefix_suffix", "short"])
    if mode == "popular":
        return secrets.choice(POPULAR_NICKNAMES)
    elif mode == "prefix_suffix":
        prefix = secrets.choice(NICKNAME_PREFIXES)
        suffix = secrets.choice(NICKNAME_SUFFIXES)
        if secrets.choice([True, False]):
            return prefix + suffix
        else:
            joiner = secrets.choice(["的", "的", "", "·", ""])
            if prefix.endswith("的"):
                return prefix + suffix
            return prefix + joiner + suffix
    else:
        return secrets.choice(NICKNAME_PREFIXES) + secrets.choice(NICKNAME_SUFFIXES)


def generate_english_username(
    length: int = 8,
    style: str = "lowercase",
    min_length: int = 6,
    max_length: int = 12,
) -> str:
    """生成英文用户名（非姓名格式）"""
    if style == "lowercase":
        username = "".join(secrets.choice(string.ascii_lowercase) for _ in range(length))
    elif style == "capitalize":
        first = secrets.choice(string.ascii_uppercase)
        rest = "".join(secrets.choice(string.ascii_lowercase) for _ in range(length - 1))
        username = first + rest
    elif style == "with_suffix":
        base_length = length - 3
        base = "".join(secrets.choice(string.ascii_lowercase) for _ in range(max(base_length, 4)))
        suffix = str(secrets.randbelow(900) + 100)
        username = base + suffix
    else:
        username = "".join(secrets.choice(string.ascii_lowercase) for _ in range(length))
    if len(username) < min_length:
        username += "".join(secrets.choice(string.digits) for _ in range(min_length - len(username)))
    return username


def generate_english_full_name() -> dict:
    """生成英文全名，返回 {first, last, full, username}"""
    first = secrets.choice(ENGLISH_FIRST_NAMES)
    last = secrets.choice(ENGLISH_LAST_NAMES)
    sep = secrets.choice([".", "_", "-", ""])
    username = (first + sep + last).lower()
    return {
        "first": first,
        "last": last,
        "full": f"{first} {last}",
        "username": username,
        "email_username": (first[0] + last).lower(),
    }


def generate_username(
    language: str = "chinese",
    length: Optional[int] = None,
    style: str = "lowercase",
    min_length: int = 6,
    max_length: int = 12,
) -> str:
    """生成用户名"""
    if language == "chinese":
        return generate_chinese_username(length)
    else:
        if length is None:
            length = secrets.randbelow(max_length - min_length + 1) + min_length
        return generate_english_username(length, style, min_length, max_length)
