"""密码强度评估包装"""
from generators import calculate_password_strength


def check_password_strength(password: str) -> str:
    """返回密码强度标签: '弱', '中', '强'"""
    strength, _ = calculate_password_strength(password)
    return strength
