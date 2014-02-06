#!/bin/bash

#供用户选择一种工作模式
WPRY_MODE=`dialog --backtitle "Wallproxy 网络智能代理" --menu "工作模式" 13 50 13 "1" "智能代理 可以根据情况选择代理" "2" "全程代理 全程流量通过代理服务器" "3" "取消代理 任何流量都不经过代理" "4" "查看日志 查看Wallproxy输出日志" "5" "关于程序 查看程序的关于信息" --stdout`

case "$WPRY_MODE" in
"1")
    WPRY_PROC=`pgrep -f "python startup.py"`
    kill $WPRY_PROC
    gsettings set org.gnome.system.proxy.http host '127.0.0.1'
    gsettings set org.gnome.system.proxy.http port '8086'
    gsettings set org.gnome.system.proxy.https host '127.0.0.1'
    gsettings set org.gnome.system.proxy.https port '8086'
    gsettings set org.gnome.system.proxy mode 'manual'
    nohup python startup.py&
    dialog --backtitle "Wallproxy 网络智能代理" --msgbox "———————代理设置成功———————\n\n当前模式：智能代理" 8 30
    exit
    ;;
"2")
    WPRY_PROC=`pgrep -f "python startup.py"`
    kill $WPRY_PROC
    gsettings set org.gnome.system.proxy.http host '127.0.0.1'
    gsettings set org.gnome.system.proxy.http port '8087'
    gsettings set org.gnome.system.proxy.https host '127.0.0.1'
    gsettings set org.gnome.system.proxy.https port '8087'
    gsettings set org.gnome.system.proxy mode 'manual'
    nohup python startup.py&
    dialog --backtitle "Wallproxy 网络智能代理" --msgbox "———————代理设置成功———————\n\n当前模式：全程代理" 8 30
    exit
    ;;
"3")
    WPRY_PROC=`pgrep -f "python startup.py"`
    kill $WPRY_PROC
    gsettings set org.gnome.system.proxy.http host ''
    gsettings set org.gnome.system.proxy.http port '0'
    gsettings set org.gnome.system.proxy.https host ''
    gsettings set org.gnome.system.proxy.https port '0'
    gsettings set org.gnome.system.proxy mode 'none'
    dialog --backtitle "Wallproxy 网络智能代理" --msgbox "———————代理取消成功———————\n\n感谢您的使用" 8 30
    exit
    ;;
"4")
    dialog --backtitle "Wallproxy 网络智能代理" --textbox nohup.out 20 80
    exit
    ;;
"5")
    dialog --backtitle "Wallproxy 网络智能代理    --   GUI by www.fcsys.us" --msgbox "应用程序：Wallproxy\n程序版本：v2.1.14\n项目地址：http://code.google.com/p/wallproxy/\n\n拥有属于我们自己的开放式互联网络" 10 50
    exit
    ;;
*)
    dialog --backtitle "Wallproxy 网络智能代理" --msgbox "———————当前操作无效———————\n\n感谢您的使用，再见！" 8 30
    exit
    ;;
esac



