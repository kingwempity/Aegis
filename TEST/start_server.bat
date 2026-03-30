@echo off
echo ========================================
echo   SQL注入漏洞测试环境启动脚本
echo ========================================
echo.
echo 此脚本将：
echo 1. 初始化测试数据库
echo 2. 启动PHP内置服务器
echo 测试地址: http://localhost:8080
echo.
echo 按任意键开始...
pause > nul

cd /d %~dp0

REM 检查PHP是否安装
php --version > nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ❌ 错误：未找到PHP！
    echo 请确保PHP已安装并添加到系统PATH中
    echo.
    echo 下载地址：https://windows.php.net/download
    echo.
    pause
    exit /b 1
)

echo.
echo ✅ 找到PHP，开始初始化数据库...
echo.

REM 初始化数据库
php init_db.php

if %errorlevel% neq 0 (
    echo.
    echo ❌ 数据库初始化失败！
    echo.
    pause
    exit /b 1
)

echo.
echo ✅ 数据库初始化完成，开始启动服务器...
echo.
echo 服务器将在 http://localhost:8080 启动
echo 按 Ctrl+C 停止服务器
echo.

php -S localhost:8080

pause
