"""密码管理器主程序"""
import sys
import time
import getpass
import argparse
from pathlib import Path
from typing import Optional

IDLE_TIMEOUT = 300

from config import DB_DIR, DB_PATH, DEFAULT_CHARSET, ENGLISH_STYLES
from crypto_utils import (
    derive_key,
    init_vault,
    verify_master_password,
    get_vault_paths,
    RateLimiter,
)
from db_utils import VaultDB
from generators import (
    generate_random_number,
    generate_random_digit_string,
    generate_password,
    calculate_password_strength,
    generate_username,
)
from backup import export_backup, import_backup, export_json_plain, export_csv


class PasswordManager:
    def __init__(self):
        self.db: Optional[VaultDB] = None
        self.key: Optional[bytearray] = None
        self.rate_limiter = RateLimiter()

    def lock(self):
        if self.key:
            for i in range(len(self.key)):
                self.key[i] = 0
            self.key = None
        if self.db:
            self.db.close()
            self.db = None
        print("\n会话已锁定（超时或手动锁定）")

    def _validate_master_password(self, password: str) -> tuple[bool, str]:
        if len(password) < 12:
            return False, "主密码长度至少12位"
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        categories = sum([has_upper, has_lower, has_digit, has_special])
        if categories < 3:
            return False, "主密码需包含大写、小写、数字、特殊符号中至少3类字符"
        return True, ""

    def authenticate(self) -> bool:
        salt_path, test_path = get_vault_paths()
        if not salt_path.exists() or not test_path.exists():
            print("首次使用，请设置主密码")
            print("要求: 长度≥12，包含大小写、数字、特殊符号中至少3类")
            master_password = getpass.getpass("请设置主密码: ").strip()
            valid, msg = self._validate_master_password(master_password)
            if not valid:
                print(msg)
                return False
            confirm = getpass.getpass("请确认主密码: ").strip()
            if master_password != confirm:
                print("两次输入的密码不一致")
                return False
            salt, test_payload = init_vault(master_password)
            salt_path.write_bytes(salt)
            test_path.write_bytes(test_payload)
            self.key = bytearray(derive_key(master_password, salt))
            print("密码库初始化成功")
            return True
        else:
            ok, remaining = self.rate_limiter.check_and_wait()
            if not ok:
                print(f"认证失败次数过多，请等待 {remaining:.0f} 秒后重试")
                return False
            master_password = getpass.getpass("请输入主密码: ").strip()
            salt = salt_path.read_bytes()
            test_payload = test_path.read_bytes()
            if verify_master_password(master_password, salt, test_payload):
                self.rate_limiter.record_success()
                self.key = bytearray(derive_key(master_password, salt))
                print("认证成功")
                return True
            else:
                self.rate_limiter.record_failure()
                fails = self.rate_limiter.get_failure_count()
                print(f"主密码错误 (连续失败 {fails} 次)")
                return False

    def run(self):
        if not self.authenticate():
            return
        self.db = VaultDB(self.key)
        last_activity = time.time()
        while True:
            if time.time() - last_activity > IDLE_TIMEOUT:
                self.lock()
                print("会话因空闲超时已锁定，请重新认证")
                if not self.authenticate():
                    break
                self.db = VaultDB(self.key)
                last_activity = time.time()
                continue
            self._show_menu()
            choice = input("请选择: ").strip()
            last_activity = time.time()
            if choice == "1":
                self._generate_random_number()
            elif choice == "2":
                self._generate_password()
            elif choice == "3":
                self._generate_username()
            elif choice == "4":
                self._view_records()
            elif choice == "5":
                self._search_records()
            elif choice == "6":
                self._export_backup()
            elif choice == "7":
                self._import_backup()
            elif choice == "0":
                print("再见！")
                break
            else:
                print("无效选择，请重试")
        if self.db:
            self.db.close()

    def _show_menu(self):
        print("\n" + "=" * 40)
        print("        密码管理器")
        print("=" * 40)
        print("1. 生成随机数")
        print("2. 生成随机密码")
        print("3. 生成随机用户名")
        print("4. 查看已保存记录")
        print("5. 搜索记录")
        print("6. 导出备份")
        print("7. 从备份恢复")
        print("0. 退出")
        print("=" * 40)

    def _generate_random_number(self):
        print("\n--- 随机数生成 ---")
        print("1. 指定范围生成随机整数")
        print("2. 生成指定长度的数字串")
        sub_choice = input("请选择: ").strip()
        if sub_choice == "1":
            try:
                min_val = int(input("最小值: "))
                max_val = int(input("最大值: "))
                if min_val > max_val:
                    print("最小值不能大于最大值")
                    return
                result = generate_random_number(min_val, max_val)
                print(f"生成的随机数: {result}")
            except ValueError:
                print("请输入有效的数字")
        elif sub_choice == "2":
            try:
                length = int(input("数字串长度: "))
                if length <= 0:
                    print("长度必须大于0")
                    return
                result = generate_random_digit_string(length)
                print(f"生成的数字串: {result}")
            except ValueError:
                print("请输入有效的数字")
        else:
            print("无效选择")

    def _generate_password(self):
        print("\n--- 随机密码生成 ---")
        try:
            length = int(input(f"密码长度 (默认16): ").strip() or "16")
        except ValueError:
            length = 16
        print("选择字符集 (y/n):")
        charset_config = {}
        charset_config["uppercase"] = input("  大写字母 [Y/n]: ").strip().lower() != "n"
        charset_config["lowercase"] = input("  小写字母 [Y/n]: ").strip().lower() != "n"
        charset_config["digits"] = input("  数字 [Y/n]: ").strip().lower() != "n"
        charset_config["special"] = input("  特殊符号 [Y/n]: ").strip().lower() != "n"
        password = generate_password(length, charset_config)
        strength, entropy = calculate_password_strength(password)
        print(f"\n生成的密码: {password}")
        print(f"密码强度: {strength} (熵值: {entropy:.1f} bits)")
        save = input("\n是否保存此密码? (y/n): ").strip().lower()
        if save == "y":
            self._save_record(password, password)

    def _generate_username(self):
        print("\n--- 随机用户名生成 ---")
        print("1. 中文用户名")
        print("2. 英文用户名")
        sub_choice = input("请选择: ").strip()
        if sub_choice == "1":
            try:
                length = int(input("用户名长度 (2-4, 默认随机): ").strip() or "0")
                length = length if 2 <= length <= 4 else None
            except ValueError:
                length = None
            username = generate_username("chinese", length)
        elif sub_choice == "2":
            print("选择风格:")
            for i, style in enumerate(ENGLISH_STYLES, 1):
                print(f"  {i}. {style}")
            try:
                style_idx = int(input("请选择 (默认1): ").strip() or "1") - 1
                style = ENGLISH_STYLES[style_idx] if 0 <= style_idx < len(ENGLISH_STYLES) else "lowercase"
            except (ValueError, IndexError):
                style = "lowercase"
            try:
                length = int(input("用户名长度 (默认8): ").strip() or "8")
            except ValueError:
                length = 8
            username = generate_username("english", length, style)
        else:
            print("无效选择")
            return
        print(f"\n生成的用户名: {username}")
        save = input("\n是否保存此用户名? (y/n): ").strip().lower()
        if save == "y":
            password = generate_password(16)
            self._save_record(username, password)

    def _save_record(self, username: str, password: str):
        site_name = input("网站/应用名称: ").strip()
        if not site_name:
            print("网站名称不能为空")
            return
        notes = input("备注 (可选): ").strip() or None
        record_id = self.db.add_record(site_name, username, password, notes)
        print(f"记录已保存，ID: {record_id}")

    def _view_records(self):
        records = self.db.get_all_records()
        if not records:
            print("\n暂无保存的记录")
            return
        print(f"\n共 {len(records)} 条记录:")
        print("-" * 60)
        for record in records:
            print(f"ID: {record['id']}")
            print(f"  网站: {record['site_name']}")
            print(f"  用户名: {record['username']}")
            print(f"  密码: {'*' * 8}")
            print(f"  创建时间: {record['created_at']}")
            if record['notes']:
                print(f"  备注: {record['notes']}")
            print("-" * 60)
        action = input("\n输入记录ID查看详情，或按回车返回: ").strip()
        if action:
            try:
                record_id = int(action)
                self._show_record_detail(record_id)
            except ValueError:
                print("无效输入")

    def _show_record_detail(self, record_id: int):
        record = self.db.get_record(record_id)
        if not record:
            print("记录不存在")
            return
        print(f"\n记录详情 (ID: {record['id']}):")
        print(f"  网站: {record['site_name']}")
        print(f"  用户名: {record['username']}")
        show_pwd = input("  显示密码? (y/n): ").strip().lower()
        if show_pwd == "y":
            print(f"  密码: {record['password']}")
        else:
            print(f"  密码: {'*' * 8}")
        print(f"  创建时间: {record['created_at']}")
        if record['notes']:
            print(f"  备注: {record['notes']}")
        print("\n操作:")
        print("1. 编辑")
        print("2. 删除")
        print("0. 返回")
        choice = input("请选择: ").strip()
        if choice == "1":
            self._edit_record(record_id)
        elif choice == "2":
            confirm = input("确认删除? (y/n): ").strip().lower()
            if confirm == "y":
                self.db.delete_record(record_id)
                print("记录已删除")

    def _edit_record(self, record_id: int):
        record = self.db.get_record(record_id)
        if not record:
            print("记录不存在")
            return
        print("\n编辑记录 (直接回车保持原值):")
        site_name = input(f"网站名称 [{record['site_name']}]: ").strip() or None
        username = input(f"用户名 [{record['username']}]: ").strip() or None
        password = input(f"密码 [{'*' * 8}]: ").strip() or None
        notes = input(f"备注 [{record.get('notes', '')}]: ").strip() or None
        if self.db.update_record(record_id, site_name, username, password, notes):
            print("记录已更新")
        else:
            print("更新失败")

    def _search_records(self):
        keyword = input("输入搜索关键词: ").strip()
        if not keyword:
            return
        records = self.db.search_records(keyword)
        if not records:
            print("未找到匹配的记录")
            return
        print(f"\n找到 {len(records)} 条记录:")
        for record in records:
            print(f"  [{record['id']}] {record['site_name']} - {record['username']}")

    def _export_backup(self):
        records = self.db.get_all_records()
        if not records:
            print("没有可导出的记录")
            return
        backup_path = input("备份文件路径 (默认: backup.enc): ").strip() or "backup.enc"
        if export_backup(records, self.key, backup_path):
            print(f"备份已导出到: {backup_path}")
        else:
            print("导出失败")

    def _import_backup(self):
        backup_path = input("备份文件路径: ").strip()
        if not backup_path:
            return
        records = import_backup(backup_path, self.key)
        if not records:
            return
        valid_records = []
        skipped_invalid = 0
        for record in records:
            if not isinstance(record, dict):
                skipped_invalid += 1
                continue
            site_name = record.get("site_name", "").strip()
            username = record.get("username", "").strip()
            password = record.get("password", "")
            if not site_name or not username or not password:
                skipped_invalid += 1
                print(f"跳过无效记录（必填字段缺失）: {record}")
                continue
            valid_records.append(record)
        if skipped_invalid > 0:
            print(f"已跳过 {skipped_invalid} 条无效记录")
        if not valid_records:
            print("没有有效的记录可导入")
            return
        existing = {(r["site_name"], r["username"]) for r in self.db.get_all_records()}
        print(f"找到 {len(valid_records)} 条有效记录")
        confirm = input("是否导入? (y/n): ").strip().lower()
        if confirm != "y":
            return
        count = 0
        skipped_dup = 0
        for record in valid_records:
            key = (record["site_name"], record["username"])
            if key in existing:
                print(f"跳过重复记录: {record['site_name']} - {record['username']}")
                skipped_dup += 1
                continue
            try:
                self.db.add_record(
                    record["site_name"],
                    record["username"],
                    record["password"],
                    record.get("notes"),
                )
                existing.add(key)
                count += 1
            except Exception as e:
                print(f"导入记录失败: {e}")
        result = f"成功导入 {count} 条记录"
        if skipped_dup > 0:
            result += f"，跳过 {skipped_dup} 条重复记录"
        print(result)

    def _cli_add(self, args: argparse.Namespace):
        """CLI: --add"""
        site_name = args.site or input("网站名称: ").strip()
        username = args.username or input("用户名: ").strip()
        password = args.password or getpass.getpass("密码: ").strip()
        notes = args.notes or None
        url = args.url or None
        category = args.category or "其他"
        expire_at = args.expire or None
        record_id = self.db.add_record(site_name, username, password, notes, url, category, expire_at)
        print(f"记录已添加，ID: {record_id}")

    def _cli_search(self, args: argparse.Namespace):
        """CLI: --search"""
        keyword = args.query or input("搜索关键词: ").strip()
        records = self.db.search_enhanced(keyword)
        if not records:
            print("未找到匹配的记录")
            return
        for r in records:
            print(f"[{r['id']}] {r['site_name']} | {r['username']} | 分类: {r.get('category','其他')}")

    def _cli_export(self, args: argparse.Namespace):
        """CLI: --export"""
        records = self.db.get_all_records()
        if not records:
            print("没有可导出的记录")
            return
        fmt = args.format or "enc"
        path = args.output or f"backup.{fmt}"
        if fmt == "enc":
            ok = export_backup(records, self.key, path)
        elif fmt == "json":
            ok = export_json_plain(records, path)
        elif fmt == "csv":
            ok = export_csv(records, path)
        else:
            print(f"不支持的格式: {fmt}")
            return
        if ok:
            print(f"已导出到 {path}")
        else:
            print("导出失败")

    def _cli_report(self, args: argparse.Namespace):
        """CLI: --report"""
        report = self.db.get_security_report()
        print("=" * 50)
        print("安全报告")
        print("=" * 50)
        print(f"总记录数: {report['total_records']}")
        print(f"弱密码数: {report['weak_count']}")
        print(f"过期/长期未改密码数: {report['expired_count']}")
        print(f"重复使用密码数: {report['reused_passwords_count']}")
        if report['weak_passwords']:
            print("\n--- 弱密码 ---")
            for r in report['weak_passwords']:
                print(f"  [{r['id']}] {r['site_name']}")
        if report['expired_passwords']:
            print("\n--- 过期密码 ---")
            for r in report['expired_passwords']:
                print(f"  [{r['id']}] {r['site_name']} (分类: {r.get('category','其他')})")


def main():
    parser = argparse.ArgumentParser(description="密码管理器")
    parser.add_argument("--add", action="store_true", help="添加新记录")
    parser.add_argument("--search", action="store_true", help="搜索记录")
    parser.add_argument("--export", action="store_true", help="导出记录")
    parser.add_argument("--report", action="store_true", help="安全报告")
    parser.add_argument("--site", help="网站名称 (配合 --add)")
    parser.add_argument("--username", help="用户名 (配合 --add)")
    parser.add_argument("--password", help="密码 (配合 --add)")
    parser.add_argument("--notes", help="备注 (配合 --add)")
    parser.add_argument("--url", help="网址 (配合 --add)")
    parser.add_argument("--category", choices=["社交", "金融", "工作", "娱乐", "购物", "教育", "其他"], help="分类 (配合 --add)")
    parser.add_argument("--expire", help="过期日期 YYYY-MM-DD (配合 --add)")
    parser.add_argument("--query", help="搜索关键词 (配合 --search)")
    parser.add_argument("--format", choices=["enc", "json", "csv"], default="enc", help="导出格式 (配合 --export)")
    parser.add_argument("--output", help="导出路径 (配合 --export)")

    args = parser.parse_args()

    has_cli = args.add or args.search or args.export or args.report

    if has_cli:
        manager = PasswordManager()
        try:
            if not manager.authenticate():
                sys.exit(1)
            manager.db = VaultDB(manager.key)
            if args.add:
                manager._cli_add(args)
            elif args.search:
                manager._cli_search(args)
            elif args.export:
                manager._cli_export(args)
            elif args.report:
                manager._cli_report(args)
        finally:
            manager.lock()
    else:
        manager = PasswordManager()
        try:
            manager.run()
        finally:
            manager.lock()


if __name__ == "__main__":
    main()
