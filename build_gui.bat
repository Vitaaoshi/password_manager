@echo off
chcp 65001 >nul
echo === 正在打包密码管理器 (GUI便携版) ===

pyinstaller ^
    --onefile ^
    --windowed ^
    --name PasswordManagerGUI ^
    --icon app_icon.ico ^
    --add-data "config.py;." ^
    --add-data "crypto_utils.py;." ^
    --add-data "db_utils.py;." ^
    --add-data "generators.py;." ^
    --add-data "backup.py;." ^
    --add-data "browser_import.py;." ^
    --add-data "password_strength.py;." ^
    --add-data "app_icon.ico;." ^
    --add-data "app_icon.png;." ^
    --hidden-import customtkinter ^
    --hidden-import cryptography ^
    --hidden-import PIL ^
    --clean ^
    gui_main.py

echo.
if exist dist\PasswordManagerGUI.exe (
    copy dist\PasswordManagerGUI.exe release\PasswordManagerGUI.exe
    echo === 打包完成 ===
    echo 便携版 exe: release\PasswordManagerGUI.exe
) else (
    echo === 打包失败，请检查错误信息 ===
)
pause
