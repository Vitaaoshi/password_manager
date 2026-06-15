"""配置常量"""
import os
from pathlib import Path

# 数据库路径
DB_DIR = Path.home() / ".password_manager"
DB_PATH = DB_DIR / "vault.db"

# 加密参数
KDF_VERSION = 1
PBKDF2_ITERATIONS = 600_000
SALT_LENGTH = 16
KEY_LENGTH = 32  # AES-256
NONCE_LENGTH = 12

# 密码生成默认值
DEFAULT_PASSWORD_LENGTH = 16
DEFAULT_CHARSET = {
    "uppercase": True,
    "lowercase": True,
    "digits": True,
    "special": True,
}

# 用户名生成参数
CHINESE_SURNAMES = [
    "王", "李", "张", "刘", "陈", "杨", "赵", "黄", "周", "吴",
    "徐", "孙", "胡", "朱", "高", "林", "何", "郭", "马", "罗",
    "梁", "宋", "郑", "谢", "韩", "唐", "冯", "于", "董", "萧",
    "程", "曹", "袁", "邓", "许", "傅", "沈", "曾", "彭", "吕",
    "苏", "卢", "蒋", "蔡", "贾", "丁", "魏", "薛", "叶", "阎",
    "余", "潘", "杜", "戴", "夏", "钟", "汪", "田", "任", "姜",
    "范", "方", "石", "姚", "谭", "廖", "邹", "熊", "金", "陆",
    "郝", "孔", "白", "崔", "康", "毛", "邱", "秦", "江", "史",
    "顾", "侯", "邵", "孟", "龙", "万", "段", "雷", "钱", "汤",
    "尹", "黎", "易", "常", "武", "乔", "贺", "赖", "龚", "文",
]
CHINESE_NAMES = [
    "伟", "芳", "娜", "敏", "静", "丽", "强", "磊", "军", "洋",
    "勇", "艳", "杰", "娟", "涛", "明", "超", "秀英", "华", "慧",
    "建华", "文", "建国", "国强", "志强", "志明", "小红", "小明",
    "小华", "小丽", "小刚", "小强", "小李", "小王", "小张", "小刘",
    "小陈", "小杨", "小赵", "小黄", "小周", "小吴", "小徐", "小孙",
    "俊", "杰", "勇", "强", "刚", "磊", "峰", "鹏", "伟", "超",
    "浩", "宇", "宁", "静", "欣", "怡", "琳", "莉", "娟", "慧",
    "敏", "艳", "丽", "芳", "秀", "英", "华", "琴", "梅", "兰",
    "雪", "冰", "霜", "露", "晨", "曦", "旭", "阳", "光", "明",
    "志", "意", "诚", "信", "义", "仁", "智", "勇", "礼", "孝",
    "家", "国", "民", "邦", "安", "定", "宁", "泰", "和", "顺",
    "春", "夏", "秋", "冬", "月", "星", "云", "雨", "雪", "风",
    "松", "柏", "竹", "梅", "兰", "菊", "莲", "荷", "芝", "桂",
    "龙", "凤", "麟", "瑞", "祥", "福", "寿", "康", "宁", "安",
]

# 密码历史保留数量
MAX_PASSWORD_HISTORY = 5

# 剪贴板自动清除时间（秒）
CLIPBOARD_CLEAR_SECONDS = 30

# 密码过期天数（默认 90 天提醒）
PASSWORD_EXPIRY_DAYS = 90

# 分类标签
CATEGORIES = ["社交", "金融", "工作", "娱乐", "购物", "教育", "其他"]

# 分页大小
PAGINATION_PAGE_SIZE = 20

# 特殊符号集
SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

# 英文用户名风格
ENGLISH_STYLES = ["lowercase", "capitalize", "with_suffix"]

# 英文名字数据库（真实常见姓名）
ENGLISH_FIRST_NAMES = [
    "James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph", "Thomas", "Charles",
    "Mary", "Patricia", "Jennifer", "Linda", "Barbara", "Elizabeth", "Susan", "Jessica", "Sarah", "Karen",
    "Christopher", "Daniel", "Matthew", "Anthony", "Mark", "Donald", "Steven", "Paul", "Andrew", "Joshua",
    "Emma", "Olivia", "Ava", "Isabella", "Sophia", "Mia", "Charlotte", "Amelia", "Harper", "Evelyn",
    "George", "Edward", "Brian", "Kevin", "Jason", "Jeffrey", "Ryan", "Jacob", "Nicholas", "Eric",
    "Abigail", "Emily", "Ella", "Avery", "Sofia", "Camila", "Aria", "Scarlett", "Victoria", "Madison",
    "Alexander", "Tyler", "Kyle", "Zachary", "Nathan", "Aaron", "Samuel", "Benjamin", "Luke", "Logan",
    "Grace", "Chloe", "Penelope", "Layla", "Riley", "Zoey", "Nora", "Lily", "Eleanor", "Hannah",
    "Henry", "Jack", "Owen", "Dylan", "Lucas", "Mason", "Ethan", "Aiden", "Carter", "Sebastian",
]

ENGLISH_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
    "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
    "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts",
    "Turner", "Phillips", "Evans", "Collins", "Edwards", "Stewart", "Morris", "Murphy", "Cook", "Rogers",
    "Morgan", "Peterson", "Cooper", "Reed", "Bailey", "Bell", "Howard", "Ward", "Cox", "Diaz",
    "Richardson", "Wood", "Watson", "Brooks", "Bennett", "Gray", "James", "Reyes", "Cruz", "Hughes",
    "Price", "Myers", "Long", "Foster", "Sanders", "Ross", "Powell", "Sullivan", "Russell", "Ortiz",
    "Jenkins", "Perry", "Butler", "Barnes", "Fisher", "Henderson", "Coleman", "Simmons", "Patterson", "Jordan",
]

# 中文双字名数据库
CHINESE_DOUBLE_NAMES = [
    "秀英", "建华", "志强", "志明", "小红", "小明", "小华", "小丽", "小刚", "小强",
    "建国", "国强", "国庆", "建军", "建民", "爱华", "爱国", "为民", "和平", "永强",
    "文杰", "文博", "文豪", "文轩", "浩然", "浩宇", "子轩", "子涵", "子豪", "梓涵",
    "梓豪", "梓轩", "梓睿", "一诺", "一鸣", "思远", "思涵", "思琪", "嘉懿", "嘉欣",
    "佳琪", "佳怡", "俊杰", "俊豪", "俊杰", "俊杰", "天佑", "天宇", "宇航", "宇轩",
    "明辉", "明杰", "伟杰", "伟强", "伟华", "海涛", "海燕", "秀兰", "秀珍", "秀芳",
    "玉兰", "玉珍", "玉芳", "桂英", "桂兰", "桂芳", "凤英", "凤兰", "金凤", "银凤",
]

# 中文姓名风格
CHINESE_NAME_STYLES = ["传统型", "现代型", "文艺型"]

# 中文网名前缀（形容词/动词/意境词）
NICKNAME_PREFIXES = [
    "风中", "梦里", "月下", "花间", "云上", "海底", "星空", "雨后", "雪中", "雾里",
    "酷酷的", "萌萌的", "甜甜的", "傻傻的", "乖乖的", "帅帅的", "美美的", "坏坏的",
    "小小", "大大", "老", "小", "大", "阿", "超", "最", "爱", "想",
    "追风", "逐月", "踏雪", "听雨", "望云", "乘风", "破浪", "向阳", "逆光", "追光",
    "快乐", "幸福", "孤单", "寂寞", "忧伤", "浪漫", "温柔", "暴躁", "高冷", "傲娇",
    "吃瓜", "摸鱼", "躺平", "摆烂", "内卷", "划水", "搬砖", "打工", "干饭", "发呆",
    "薄荷", "草莓", "柠檬", "蜜桃", "蓝莓", "西瓜", "芒果", "葡萄", "樱桃", "布丁",
    "森林", "大海", "天空", "星辰", "月亮", "太阳", "微风", "细雨", "闪电", "暴风",
]

# 中文网名后缀（名词/动物/物体/身份）
NICKNAME_SUFFIXES = [
    "追风", "逐月", "少年", "少女", "青年", "先生", "女士", "公子", "仙子", "达人",
    "的仔", "的猫", "的狗", "的鱼", "的鸟", "的兔", "的熊", "的狼", "的虎", "的龙",
    "小熊", "小兔", "小猫", "小狗", "小鱼", "小鸟", "小猪", "小鹿", "小马", "小羊",
    "王子", "公主", "骑士", "精灵", "天使", "恶魔", "巫师", "剑客", "侠客", "浪子",
    "江湖", "天涯", "归人", "过客", "旅人", "行人", "故人", "新人", "旧人", "离人",
    "如风", "如梦", "如烟", "如云", "如水", "如火", "如山", "如海", "如诗", "如画",
    "之心", "之恋", "之约", "之梦", "之旅", "之路", "之光", "之海", "之城", "之国",
    "不二", "唯一", "无双", "无敌", "不凡", "不羁", "不语", "不言", "不弃", "不离",
    "控", "迷", "痴", "狂", "徒", "者", "君", "酱", "桑", "菌",
]

# 完整流行网名库
POPULAR_NICKNAMES = [
    "夜空中最亮的星", "风一样的男子", "天使的翅膀", "蓝色忧郁", "紫色风铃",
    "追梦赤子心", "最初的梦想", "匆匆那年", "那些年", "致青春",
    "我的未来不是梦", "怒放的生命", "飞得更高", "海阔天空", "光辉岁月",
    "晴天娃娃", "彩虹天堂", "月亮代表我的心", "童话", "约定",
    "隐形的翅膀", "最美的太阳", "星星点灯", "水手", "冬天里的一把火",
    "微微一笑很倾城", "何以笙箫默", "三生三世", "十里桃花", "花千骨",
    "盛夏光年", "深海里的星星", "鲸向海", "鸟投林", "风吹麦浪",
    "梦里花落知多少", "挪威的森林", "百年孤独", "活着", "平凡的世界",
    "清风徐来", "水波不兴", "月明星稀", "乌鹊南飞", "山高水长",
    "人间忽晚", "山河已秋", "岁月缝花", "时光煮雨", "素心若雪",
    "城南花已开", "北城别", "西城诀", "南城忆", "东城暖",
    "提笔忘情", "落笔成殇", "执笔写流年", "墨染青衣", "素笺淡墨",
]
