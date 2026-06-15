# Password Manager - 密码管理器

一款基于 Python 的本地密码管理工具，采用 AES-256-GCM 加密存储，提供密码生成、安全管理、浏览器导入等功能。支持 GUI 图形界面和 CLI 命令行两种使用方式。

## 功能特性

### 核心安全

- **AES-256-GCM 加密**：所有敏感数据加密存储，PBKDF2 密钥派生（600,000 次迭代）
- **HKDF 密钥隔离**：主密钥、备份密钥、HMAC 密钥相互独立
- **HMAC-SHA256 完整性校验**：防止数据库字段被篡改，支持 v1/v2 平滑升级
- **速率限制**：指数退避防暴力破解，状态持久化到磁盘防重启绕过
- **主密码策略**：最低 12 位，需包含大小写、数字、特殊符号中至少 3 类

### 密码管理

- 添加、编辑、查看、搜索密码记录
- 分类标签管理（社交、金融、工作、娱乐、购物、教育、其他）
- 密码历史记录（最多保留 5 条）与一键回滚
- 密码过期提醒（默认 90 天）
- 回收站软删除（30 天自动清理）
- 批量删除与批量修改分类

### 密码生成

- 自定义长度（8-64 位）和字符集
- 实时强度评估与熵值计算
- 键盘序列、重复字符等弱密码检测

### 用户名生成

- 中文姓名（2-4 字，传统/现代/文艺风格）
- 中文网名生成
- 英文姓名生成

### 导入导出

- 加密备份导出/导入（.enc）
- JSON/CSV 明文导出
- 浏览器密码导入（Edge、Chrome、Firefox）
- Bitwarden CSV 导入
- 1Password CSV 导入

### 其他

- 安全报告（弱密码、过期密码、重复密码检测）
- 随机数生成器
- 剪贴板自动清除（30 秒）
- 空闲超时自动锁定（5 分钟）
- Ctrl+F 搜索 / Ctrl+L 锁定快捷键

## 系统要求

- **操作系统**：Windows 10/11（浏览器导入功能仅 Windows）
- **Python**：3.11+（源码运行时需要）
- **便携版**：无需安装 Python，直接运行 exe

## 快速开始

### 方式一：便携版 exe（推荐）

1. 从 [Releases](../../releases) 下载 `PasswordManagerGUI.exe`
2. 双击运行，首次使用设置主密码即可

### 方式二：源码运行

```bash
# 克隆项目
git clone https://github.com/your-username/password-manager.git
cd password-manager

# 安装依赖
pip install -r requirements.txt

# 启动 GUI
python gui_main.py

# 或使用命令行模式
python main.py
```

## 项目结构

```
├── gui_main.py            # GUI 入口（CustomTkinter）
├── main.py                # CLI 入口
├── config.py              # 配置常量
├── crypto_utils.py        # 加密/解密/密钥派生
├── db_utils.py            # 数据库 CRUD 操作
├── generators.py          # 密码/用户名生成器
├── backup.py              # 备份恢复与格式导入
├── browser_import.py      # 浏览器密码导入
├── password_strength.py   # 密码强度评估
├── test_all.py            # 测试套件（18 项测试）
├── app_icon.ico           # 应用图标
├── app_icon.png           # 应用图标
├── build_gui.bat          # PyInstaller 打包脚本
├── requirements.txt       # 依赖列表
├── release/               # 打包输出目录
│   └── PasswordManagerGUI.exe
└── screenshots/           # 截图目录
```

## 数据安全

- 所有密码使用 AES-256-GCM 加密后存储于 SQLite 数据库
- 数据库文件位于 `~/.password_manager/vault.db`，权限限制为仅用户可读写
- 主密码不存储，仅保留用于验证的随机测试向量
- 密钥通过 PBKDF2（600,000 次迭代）从主密码派生
- HMAC 完整性校验覆盖所有加密字段，防止篡改

## 从源码打包

```bash
# 安装 PyInstaller
pip install pyinstaller

# 运行打包脚本
build_gui.bat

# 生成的 exe 位于 dist/ 目录
```

## 技术栈

- **加密**：cryptography (AES-GCM, PBKDF2, HKDF)
- **GUI**：CustomTkinter (现代深色主题)
- **数据库**：SQLite3
- **打包**：PyInstaller

## 许可证

[MIT License](LICENSE)
