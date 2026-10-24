@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo   wxapkg-gui 打包脚本
echo   产出: dist\wxapkg_gui.exe (界面版)
echo         dist\wxapkg_cli.exe (命令行版)
echo ============================================
echo.

echo [1/3] 检查并安装打包依赖...
python -m pip install --upgrade pyinstaller pycryptodome requests jsmin Pillow --quiet
if errorlevel 1 goto error

echo [2/3] 打包界面版(无控制台窗口)...
python -m PyInstaller --noconfirm --clean --onefile --noconsole --name wxapkg_gui --hidden-import Crypto.Cipher.AES --hidden-import Crypto.Protocol.KDF --hidden-import Crypto.Hash.SHA1 --hidden-import jsmin --exclude-module numpy --exclude-module matplotlib --exclude-module scipy wxapkg_gui.py
if errorlevel 1 goto error

echo [3/3] 打包命令行版(保留控制台输出)...
python -m PyInstaller --noconfirm --clean --onefile --console --name wxapkg_cli --hidden-import Crypto.Cipher.AES --hidden-import Crypto.Protocol.KDF --hidden-import Crypto.Hash.SHA1 --hidden-import jsmin --exclude-module numpy --exclude-module matplotlib --exclude-module scipy wxapkg_gui.py
if errorlevel 1 goto error

echo.
echo ============================================
echo   打包完成
echo   dist\wxapkg_gui.exe  双击启动图形界面
echo   dist\wxapkg_cli.exe  命令行: wxapkg_cli.exe scan / unpack ...
echo ============================================
goto :eof

:error
echo.
echo 打包失败: 请查看上面的报错信息。
echo 常见原因: Python 未加入 PATH、磁盘空间不足、杀毒软件拦截 dist 写入。
exit /b 1