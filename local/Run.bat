@echo off
rem --hide运行后隐藏窗口；--single重复运行时激活旧窗口，而非再开一个窗口，--exit退出
rem 可组合，例如--hide与--single合用，首次运行自动隐藏窗口，再次运行显示旧窗口
rem 建议将python.exe发送到桌面快捷方式并加上--hide --single参数
rem 如需开机自动运行，将快捷方式放到开始菜单的启动文件夹
start "WallProxy" "%~dp0python.exe" --hide --single
