#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

# 判断系统及定义系统安装依赖方式
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1

if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

inst_cert(){
    green "Hysteria 2 协议证书申请方式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 必应自签证书 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Acme 脚本自动申请"
    echo -e " ${GREEN}3.${PLAIN} 自定义证书路径"
    echo ""
    read -rp "请输入选项 [1-3]: " certInput
    if [[ $certInput == 2 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"

        chmod a+x /root # 让 Hysteria 主程序访问到 /root 目录

        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "检测到原有域名：$domain 的证书，正在应用"
            hy_domain=$domain
        else
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                realip
                wg-quick up wgcf >/dev/null 2>&1
                systemctl start warp-go >/dev/null 2>&1
            else
                realip
            fi
            
            read -p "请输入需要申请证书的域名：" domain
            [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
            green "已输入的域名：$domain" && sleep 1
            domainIP=$(curl -sm8 ipget.net/?ip="${domain}")
            if [[ $domainIP == $ip ]]; then
                ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl
                if [[ $SYSTEM == "CentOS" ]]; then
                    ${PACKAGE_INSTALL[int]} cronie
                    systemctl start crond
                    systemctl enable crond
                else
                    ${PACKAGE_INSTALL[int]} cron
                    systemctl start cron
                    systemctl enable cron
                fi
                curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
                source ~/.bashrc
                bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
                if [[ -n $(echo $ip | grep ":") ]]; then
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --listen-v6 --insecure
                else
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --insecure
                fi
                if [[ $? -eq 0 ]]; then
                    mkdir /root/cert
                    bash ~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath $cert_path --keypath $key_path --ecc
                    chmod -f a+x /root
                    echo $domain > /root/ca.log
                    hy_domain=$domain
                else
                    red "证书申请失败，请检查域名是否正确或稍后再试！" && exit 1
                fi
            else
                red "域名解析地址与服务器IP不一致，请检查域名是否正确解析！" && exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -rp "请输入证书文件的绝对路径：" cert_path
        read -rp "请输入私钥文件的绝对路径：" key_path
        if [[ -f $cert_path && -f $key_path ]] && [[ -s $cert_path && -s $key_path ]]; then
            hy_domain="自定义证书"
        else
            red "证书文件或私钥文件不存在或文件大小为0，请检查文件路径是否正确！" && exit 1
        fi
    else
        hy_domain="必应自签证书"
    fi
}

# 安装Warp主程序
install_hysteria(){
    green "开始安装 Hysteria 主程序..."

    # 下载Hysteria主程序并赋予执行权限
    wget -O /usr/local/bin/hysteria https://github.com/CCChieh/CFWarp-Pro/raw/main/hysteria >/dev/null 2>&1
    chmod +x /usr/local/bin/hysteria

    # 设置Hysteria配置文件路径
    mkdir /usr/local/etc/hysteria >/dev/null 2>&1

    # 下载Hysteria配置文件
    if [[ $hy_domain == "必应自签证书" ]]; then
        wget -O /usr/local/etc/hysteria/config.yaml https://github.com/CCChieh/CFWarp-Pro/raw/main/config.yaml >/dev/null 2>&1
    else
        wget -O /usr/local/etc/hysteria/config.yaml https://github.com/CCChieh/CFWarp-Pro/raw/main/config-cert.yaml >/dev/null 2>&1
    fi

    # 下载Hysteria服务脚本
    wget -O /etc/systemd/system/hysteria.service https://github.com/CCChieh/CFWarp-Pro/raw/main/hysteria.service >/dev/null 2>&1

    # 设置Hysteria服务
    systemctl daemon-reload
    systemctl enable hysteria.service
    systemctl restart hysteria.service

    sleep 2

    if systemctl is-active --quiet hysteria.service; then
        green "Hysteria 主程序安装成功并已启动！"
    else
        red "Hysteria 主程序安装失败！"
        exit 1
    fi
}

# 添加Warp虚拟网卡
add_wgcf(){
    green "开始添加 Warp 虚拟网卡..."

    # 检查是否已安装WireGuard
    if [[ -z $(type -P wg) ]]; then
        ${PACKAGE_INSTALL[int]} wireguard-tools
    fi

    # 下载WGCF
    wgcf_url="https://github.com/ViRb3/wgcf/releases/latest/download/wgcf_$(uname -m)"
    wget -O /usr/local/bin/wgcf $wgcf_url >/dev/null 2>&1
    chmod +x /usr/local/bin/wgcf

    # 运行WGCF注册
    wgcf register >/dev/null 2>&1

    # 生成配置文件
    wgcf generate >/dev/null 2>&1

    # 复制配置文件到WireGuard目录
    cp -f wgcf-profile/* /etc/wireguard/

    # 修改WireGuard配置文件名
    mv /etc/wireguard/wgcf-profile.conf /etc/wireguard/wgcf.conf

    # 启动WireGuard
    systemctl start wg-quick@wgcf >/dev/null 2>&1
    systemctl enable wg-quick@wgcf >/dev/null 2>&1

    sleep 2

    if systemctl is-active --quiet wg-quick@wgcf; then
        green "Warp 虚拟网卡添加成功！"
    else
        red "Warp 虚拟网卡添加失败！"
        exit 1
    fi
}

# 安装并配置Dnsmasq
install_dnsmasq(){
    green "开始安装和配置 Dnsmasq..."

    # 检查是否已安装Dnsmasq
    if [[ -z $(type -P dnsmasq) ]]; then
        ${PACKAGE_INSTALL[int]} dnsmasq
    fi

    # 创建Dnsmasq配置文件夹
    mkdir /etc/dnsmasq.d

    # 下载Dnsmasq配置文件
    wget -O /etc/dnsmasq.d/warp.conf https://github.com/CCChieh/CFWarp-Pro/raw/main/dnsmasq/warp.conf >/dev/null 2>&1

    # 重启Dnsmasq服务
    systemctl restart dnsmasq

    sleep 2

    if systemctl is-active --quiet dnsmasq; then
        green "Dnsmasq安装和配置成功！"
    else
        red "Dnsmasq安装和配置失败！"
        exit 1
    fi
}

# 设置系统DNS
set_dns(){
    green "开始设置系统DNS..."

    if [[ -n $(grep "127.0.0.1" /etc/resolv.conf) ]]; then
        # 备份原始DNS设置
        cp /etc/resolv.conf /etc/resolv.conf.bak
        # 设置新的DNS
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        green "系统DNS设置成功！"
    else
        red "系统DNS设置失败！"
        exit 1
    fi
}

# 安装并配置Hysteria系统服务
install_hysteria_service(){
    green "开始安装并配置 Hysteria 系统服务..."

    # 创建Hysteria服务配置文件夹
    mkdir /etc/hysteria

    # 下载Hysteria系统服务配置文件
    wget -O /etc/hysteria/hysteria.yaml https://github.com/CCChieh/CFWarp-Pro/raw/main/hysteria.yaml >/dev/null 2>&1

    # 下载Hysteria系统服务脚本
    wget -O /etc/systemd/system/hysteria-system.service https://github.com/CCChieh/CFWarp-Pro/raw/main/hysteria-system.service >/dev/null 2>&1

    # 启动Hysteria系统服务
    systemctl daemon-reload
    systemctl enable hysteria-system.service >/dev/null 2>&1
    systemctl restart hysteria-system.service

    sleep 2

    if systemctl is-active --quiet hysteria-system.service; then
        green "Hysteria系统服务安装和配置成功！"
    else
        red "Hysteria系统服务安装和配置失败！"
        exit 1
    fi
}

# 安装BBR内核
install_bbr(){
    green "开始安装 BBR 内核..."

    # 检查是否已安装BBR内核
    if [[ $(uname -r) == *bbrplus* ]]; then
        green "系统已安装 BBR Plus 内核，跳过安装！"
        return
    elif [[ $(uname -r) == *bbr* || $(lsmod | grep bbr) ]]; then
        green "系统已安装 BBR 内核，跳过安装！"
        return
    fi

    if [[ $OS == "ubuntu" && $VERSION_ID == "20.04" ]]; then
        # Ubuntu 20.04使用BBR官方内核
        ${PACKAGE_INSTALL[int]} linux-generic linux-headers-generic
    else
        # 安装BBR Plus内核
        if [[ $OS == "ubuntu" ]]; then
            ${PACKAGE_INSTALL[int]} linux-headers-5.4.0-77-generic linux-image-5.4.0-77-generic
        else
            ${PACKAGE_INSTALL[int]} linux-headers-5.10.0-042stab140.1 linux-image-5.10.0-042stab140.1
        fi
    fi

    # 配置BBR
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf

    # 生效配置
    sysctl -p >/dev/null 2>&1

    # 检查BBR是否生效
    if sysctl net.ipv4.tcp_available_congestion_control | grep -q "bbr"; then
        if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
            green "BBR 内核安装成功并已启用！"
        else
            red "BBR 内核安装成功，但启用失败，请尝试重启服务器！"
        fi
    else
        red "BBR 内核安装失败，请检查系统是否支持 BBR！"
        exit 1
    fi
}

# 安装并配置BBR Plus内核
install_bbrplus(){
    green "开始安装 BBR Plus 内核..."

    # 检查是否已安装BBR Plus内核
    if [[ $(uname -r) == *bbrplus* ]]; then
        green "系统已安装 BBR Plus 内核，跳过安装！"
        return
    fi

    # 下载BBR Plus内核安装包
    wget -O bbrplus.deb https://github.com/ylx2016/kernel/releases/latest/download/bbrplus-ubuntu.deb >/dev/null 2>&1

    # 安装BBR Plus内核
    dpkg -i bbrplus.deb >/dev/null 2>&1
    apt install -f -y >/dev/null 2>&1

    # 清理安装包
    rm -f bbrplus.deb

    # 配置BBR Plus内核
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbrplus" >> /etc/sysctl.conf

    # 生效配置
    sysctl -p >/dev/null 2>&1

    # 检查BBR Plus是否生效
    if sysctl net.ipv4.tcp_available_congestion_control | grep -q "bbrplus"; then
        if sysctl net.ipv4.tcp_congestion_control | grep -q "bbrplus"; then
            green "BBR Plus 内核安装成功并已启用！"
        else
            red "BBR Plus 内核安装成功，但启用失败，请尝试重启服务器！"
        fi
    else
        red "BBR Plus 内核安装失败，请检查系统是否支持 BBR Plus！"
        exit 1
    fi
}

# 安装Warp程序
install_warp(){
    green "开始安装 Warp 程序..."

    # 检查是否已安装Warp
    if [[ -z $(type -P warp) ]]; then
        ${PACKAGE_INSTALL[int]} warp
    fi

    # 下载Warp配置文件
    wget -O /etc/warp/warp.yaml https://github.com/CCChieh/CFWarp-Pro/raw/main/warp.yaml >/dev/null 2>&1

    # 设置Warp配置文件
    sed -i "s/replace_with_your_license_key/$license_key/" /etc/warp/warp.yaml
    sed -i "s/replace_with_your_endpoint/$hy_domain/" /etc/warp/warp.yaml

    # 启动Warp
    systemctl start warp >/dev/null 2>&1
    systemctl enable warp >/dev/null 2>&1

    sleep 2

    if systemctl is-active --quiet warp; then
        green "Warp程序安装成功并已启动！"
    else
        red "Warp程序安装失败！"
        exit 1
    fi
}

# 安装Trojan程序
install_trojan(){
    green "开始安装 Trojan 程序..."

    # 检查是否已安装Trojan
    if [[ -z $(type -P trojan) ]]; then
        ${PACKAGE_INSTALL[int]} trojan
    fi

    # 创建Trojan配置文件夹
    mkdir /etc/trojan

    # 下载Trojan配置文件
    wget -O /etc/trojan/trojan.yaml https://github.com/CCChieh/CFWarp-Pro/raw/main/trojan/trojan.yaml >/dev/null 2>&1

    # 设置Trojan配置文件
    sed -i "s/replace_with_your_password/$trojan_password/" /etc/trojan/trojan.yaml
    sed -i "s/replace_with_your_domain/$hy_domain/" /etc/trojan/trojan.yaml

    # 下载Trojan服务脚本
    wget -O /etc/systemd/system/trojan.service https://github.com/CCChieh/CFWarp-Pro/raw/main/trojan/trojan.service >/dev/null 2>&1

    # 启动Trojan
    systemctl daemon-reload
    systemctl enable trojan.service >/dev/null 2>&1
    systemctl restart trojan.service

    sleep 2

    if systemctl is-active --quiet trojan.service; then
        green "Trojan程序安装成功并已启动！"
    else
        red "Trojan程序安装失败！"
        exit 1
    fi
}

# 安装V2Ray程序
install_v2ray(){
    green "开始安装 V2Ray 程序..."

    # 检查是否已安装V2Ray
    if [[ -z $(type -P v2ray) ]]; then
        bash <(curl -L -s https://install.direct/go.sh) >/dev/null 2>&1
    fi

    # 创建V2Ray配置文件夹
    mkdir -p /etc/v2ray

    # 下载V2Ray配置文件
    wget -O /etc/v2ray/config.json https://github.com/CCChieh/CFWarp-Pro/raw/main/v2ray/config.json >/dev/null 2>&1

    # 设置V2Ray配置文件
    sed -i "s/replace_with_your_uuid/$v2ray_uuid/" /etc/v2ray/config.json
    sed -i "s/replace_with_your_path/$v2ray_path/" /etc/v2ray/config.json
    sed -i "s/replace_with_your_domain/$hy_domain/" /etc/v2ray/config.json

    # 下载V2Ray服务脚本
    wget -O /etc/systemd/system/v2ray.service https://github.com/CCChieh/CFWarp-Pro/raw/main/v2ray/v2ray.service >/dev/null 2>&1

    # 启动V2Ray
    systemctl daemon-reload
    systemctl enable v2ray.service >/dev/null 2>&1
    systemctl restart v2ray.service

    sleep 2

    if systemctl is-active --quiet v2ray.service; then
        green "V2Ray程序安装成功并已启动！"
    else
        red "V2Ray程序安装失败！"
        exit 1
    fi
}

# 安装Nginx
install_nginx(){
    green "开始安装 Nginx..."

    # 检查是否已安装Nginx
    if [[ -z $(type -P nginx) ]]; then
        ${PACKAGE_INSTALL[int]} nginx
    fi

    # 下载Nginx配置文件
    wget -O /etc/nginx/nginx.conf https://github.com/CCChieh/CFWarp-Pro/raw/main/nginx/nginx.conf >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/default.conf https://github.com/CCChieh/CFWarp-Pro/raw/main/nginx/default.conf >/dev/null 2>&1

    # 设置Nginx配置文件
    sed -i "s/replace_with_your_domain/$hy_domain/" /etc/nginx/nginx.conf
    sed -i "s/replace_with_your_domain/$hy_domain/" /etc/nginx/conf.d/default.conf

    # 启动Nginx
    systemctl restart nginx >/dev/null 2>&1
    systemctl enable nginx >/dev/null 2>&1

    sleep 2

    if systemctl is-active --quiet nginx; then
        green "Nginx安装成功并已启动！"
    else
        red "Nginx安装失败！"
        exit 1
    fi
}

# 安装BBR内核
install_bbr(){
    green "开始安装 BBR 内核..."

    # 检查是否已安装BBR内核
    if [[ $(uname -r) == *bbrplus* ]]; then
        green "系统已安装 BBR Plus 内核，跳过安装！"
        return
    elif [[ $(uname -r) == *bbr* || $(lsmod | grep bbr) ]]; then
        green "系统已安装 BBR 内核，跳过安装！"
        return
    fi

    if [[ $SYSTEM == "CentOS" ]]; then
        # 安装ELRepo仓库
        rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org >/dev/null 2>&1
        rpm -Uvh https://www.elrepo.org/elrepo-release-7.0-4.el7.elrepo.noarch.rpm >/dev/null 2>&1

        # 安装BBR Plus内核
        yum --enablerepo=elrepo-kernel -y install kernel-ml-plus >/dev/null 2>&1
    else
        # 安装BBR Plus内核
        ${PACKAGE_INSTALL[int]} linux-headers-5.10.0-042stab140.1 linux-image-5.10.0-042stab140.1 >/dev/null 2>&1
    fi

    # 配置BBR
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf

    # 生效配置
    sysctl -p >/dev/null 2>&1

    # 检查BBR是否生效
    if sysctl net.ipv4.tcp_available_congestion_control | grep -q "bbr"; then
        if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
            green "BBR 内核安装成功并已启用！"
        else
            red "BBR 内核安装成功，但启用失败，请尝试重启服务器！"
        fi
    else
        red "BBR 内核安装失败，请检查系统是否支持 BBR！"
        exit 1
    fi
}

# 优化系统配置
optimize_system(){
    green "开始优化系统配置..."

    # 增加文件描述符限制
    echo "* soft nofile 51200" >> /etc/security/limits.conf
    echo "* hard nofile 51200" >> /etc/security/limits.conf

    # 禁用IPv6
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf

    # 优化网络参数
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_tw_recycle = 1" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_fin_timeout = 30" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_keepalive_time = 1200" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_max_syn_backlog = 8192" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_max_tw_buckets = 5000" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_rmem = 4096 87380 67108864" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_wmem = 4096 65536 67108864" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.conf

    # 生效配置
    sysctl -p >/dev/null 2>&1

    green "系统配置优化完成！"
}

# 安装完成提示
install_finished(){
    clear
    green "==============================================================================================="
    green "Warp 一键安装脚本已成功运行完毕！"
    green "本脚本由雨落无声制作，感谢使用！"
    green "==============================================================================================="
    green "安装信息如下："
    green "连接信息："
    green "  协议：WireGuard"
    green "  端口：自动选择"
    green "  密钥：自动选择"
    green "  DNS：自动选择"
    green "  证书：自动选择"
    green "  订阅：/root/wgcf-account.toml"
    green "  代理：127.0.0.1:443"
    green "Hysteria 配置：/usr/local/etc/hysteria/config.yaml"
    green "Trojan 配置：/etc/trojan/trojan.yaml"
    green "V2Ray 配置：/etc/v2ray/config.json"
    green "Nginx 配置：/etc/nginx/nginx.conf"
    green "BBR/BBR Plus 配置：已优化"
    green "Warp 状态：已启动"
    green "Hysteria 状态：已启动"
    green "Trojan 状态：已启动"
    green "V2Ray 状态：已启动"
    green "Nginx 状态：已启动"
    green "BBR/BBR Plus 状态：已优化"
    green "==============================================================================================="
}

# 卸载Warp
uninstall_warp(){
    red "确定要卸载 Warp 吗？(y/n)"
    read -r uninstall_confirm
    if [[ $uninstall_confirm == "y" || $uninstall_confirm == "Y" ]]; then
        # 停止Warp
        systemctl stop warp >/dev/null 2>&1
        systemctl disable warp >/dev/null 2>&1

        # 移除Warp
        ${PACKAGE_MANAGE[int]} remove -y wireguard-tools warp >/dev/null 2>&1

        # 清理配置文件和证书
        rm -f /etc/wireguard/wgcf.conf
        rm -f /etc/wireguard/wgcf-account.toml
        rm -f /etc/wireguard/wgcf.toml
        rm -rf /root/warp
        rm -f /usr/local/bin/wgcf

        green "Warp 已成功卸载！"
    else
        red "已取消卸载操作！"
    fi
}

# 卸载Hysteria
uninstall_hysteria(){
    red "确定要卸载 Hysteria 吗？(y/n)"
    read -r uninstall_confirm
    if [[ $uninstall_confirm == "y" || $uninstall_confirm == "Y" ]]; then
        # 停止Hysteria
        systemctl stop hysteria >/dev/null 2>&1
        systemctl disable hysteria >/dev/null 2>&1

        # 移除Hysteria
        rm -f /usr/local/bin/hysteria
        rm -rf /usr/local/etc/hysteria
        rm -f /etc/systemd/system/hysteria.service

        green "Hysteria 已成功卸载！"
    else
        red "已取消卸载操作！"
    fi
}

# 卸载Dnsmasq
uninstall_dnsmasq(){
    red "确定要卸载 Dnsmasq 吗？(y/n)"
    read -r uninstall_confirm
    if [[ $uninstall_confirm == "y" || $uninstall_confirm == "Y" ]]; then
        # 停止Dnsmasq
        systemctl stop dnsmasq >/dev/null 2>&1
        systemctl disable dnsmasq >/dev/null 2>&1

        # 移除Dnsmasq
        ${PACKAGE_MANAGE[int]} remove -y dnsmasq >/dev/null 2>&1

        # 清理配置文件
        rm -f /etc/dnsmasq.d/warp.conf

        green "Dnsmasq 已成功卸载！"
    else
        red "已取消卸载操作！"
    fi
}

# 卸载BBR/BBR Plus内核
uninstall_bbr(){
    red "确定要卸载 BBR/BBR Plus 内核吗？(y/n)"
    read -r uninstall_confirm
    if [[ $uninstall_confirm == "y" || $uninstall_confirm == "Y" ]]; then
        # 恢复原系统内核
        if [[ $SYSTEM == "CentOS" ]]; then
            rpm -qa | grep kernel | grep -v $(uname -r) | xargs rpm -e
        else
            ${PACKAGE_MANAGE[int]} purge -y $(dpkg --get-selections | grep "linux-image\|linux-headers" | grep -v $(uname -r) | awk '{print $1}')
            update-grub
        fi

        # 清理BBR/BBR Plus安装包
        rm -f bbrplus.deb

        green "BBR/BBR Plus 内核已成功卸载！"
    else
        red "已取消卸载操作！"
    fi
}

# 卸载Trojan
uninstall_trojan(){
    red "确定要卸载 Trojan 吗？(y/n)"
    read -r uninstall_confirm
    if [[ $uninstall_confirm == "y" || $uninstall_confirm == "Y" ]]; then
        # 停止Trojan
        systemctl stop trojan >/dev/null 2>&1
        systemctl disable trojan >/dev/null 2>&1

        # 移除Trojan
        ${PACKAGE_MANAGE[int]} remove -y trojan >/dev/null 2>&1

        # 清理配置文件
        rm -f /etc/trojan/trojan.yaml
        rm -f /etc/systemd/system/trojan.service

        green "Trojan 已成功卸载！"
    else
        red "已取消卸载操作！"
    fi
}

# 卸载V2Ray
uninstall_v2ray(){
    red "确定要卸载 V2Ray 吗？(y/n)"
    read -r uninstall_confirm
    if [[ $uninstall_confirm == "y" || $uninstall_confirm == "Y" ]]; then
        # 停止V2Ray
        systemctl stop v2ray >/dev/null 2>&1
        systemctl disable v2ray >/dev/null 2>&1

        # 移除V2Ray
        bash <(curl -L -s https://install.direct/go.sh) --remove >/dev/null 2>&1

        # 清理配置文件
        rm -f /etc/v2ray/config.json
        rm -f /etc/systemd/system/v2ray.service

        green "V2Ray 已成功卸载！"
    else
        red "已取消卸载操作！"
    fi
}

# 卸载Nginx
uninstall_nginx(){
    red "确定要卸载 Nginx 吗？(y/n)"
    read -r uninstall_confirm
    if [[ $uninstall_confirm == "y" || $uninstall_confirm == "Y" ]]; then
        # 停止Nginx
        systemctl stop nginx >/dev/null 2>&1
        systemctl disable nginx >/dev/null 2>&1

        # 移除Nginx
        ${PACKAGE_MANAGE[int]} remove -y nginx >/dev/null 2>&1

        # 清理配置文件
        rm -f /etc/nginx/nginx.conf
        rm -f /etc/nginx/conf.d/default.conf

        green "Nginx 已成功卸载！"
    else
        red "已取消卸载操作！"
    fi
}

# 卸载所有组件
uninstall_all(){
    uninstall_warp
    uninstall_hysteria
    uninstall_dnsmasq
    uninstall_bbr
    uninstall_trojan
    uninstall_v2ray
    uninstall_nginx

    green "所有组件已成功卸载！"
}

# 添加新的Warp+账户
add_wgcf_account(){
    green "当前已安装 Warp+，是否添加新的 Warp+ 账户？(y/n)"
    read -r add_account_confirm
    if [[ $add_account_confirm == "y" || $add_account_confirm == "Y" ]]; then
        echo ""
        green "请输入新的 Warp+ 账户 License Key（格式：xXxXxXxXxXxXxXxXxXxXx）:"
        read -r license_key

        # 下载Warp配置文件
        warp sync -i "${license_key}" >/dev/null 2>&1

        if [[ -f /etc/wireguard/wgcf-account.toml ]]; then
            green "Warp+ 账户已添加成功！"
        else
            red "Warp+ 账户添加失败，请检查 License Key 是否正确！"
        fi
    else
        red "已取消添加新的 Warp+ 账户操作！"
    fi
}

# 更新Hysteria
update_hysteria(){
    green "当前已安装 Hysteria，是否更新到最新版本？(y/n)"
    read -r update_hysteria_confirm
    if [[ $update_hysteria_confirm == "y" || $update_hysteria_confirm == "Y" ]]; then
        # 停止Hysteria
        systemctl stop hysteria >/dev/null 2>&1

        # 下载最新版本
        wget -O hysteria https://github.com/CCChieh/Hysteria/releases/latest/download/hysteria-linux-amd64 >/dev/null 2>&1
        chmod +x hysteria
        mv hysteria /usr/local/bin

        # 启动Hysteria
        systemctl start hysteria >/dev/null 2>&1
        systemctl enable hysteria >/dev/null 2>&1

        sleep 2

        if systemctl is-active --quiet hysteria; then
            green "Hysteria 更新成功！"
        else
            red "Hysteria 更新失败！"
        fi
    else
        red "已取消更新 Hysteria 操作！"
    fi
}

# 更新Trojan
update_trojan(){
    green "当前已安装 Trojan，是否更新到最新版本？(y/n)"
    read -r update_trojan_confirm
    if [[ $update_trojan_confirm == "y" || $update_trojan_confirm == "Y" ]]; then
        # 停止Trojan
        systemctl stop trojan >/dev/null 2>&1

        # 下载最新版本
        wget -O /usr/local/bin/trojan https://github.com/trojan-gfw/trojan/releases/latest/download/trojan-cli-linux-amd64 >/dev/null 2>&1
        chmod +x /usr/local/bin/trojan

        # 启动Trojan
        systemctl start trojan >/dev/null 2>&1
        systemctl enable trojan >/dev/null 2>&1

        sleep 2

        if systemctl is-active --quiet trojan; then
            green "Trojan 更新成功！"
        else
            red "Trojan 更新失败！"
        fi
    else
        red "已取消更新 Trojan 操作！"
    fi
}

# 更新V2Ray
update_v2ray(){
    green "当前已安装 V2Ray，是否更新到最新版本？(y/n)"
    read -r update_v2ray_confirm
    if [[ $update_v2ray_confirm == "y" || $update_v2ray_confirm == "Y" ]]; then
        # 停止V2Ray
        systemctl stop v2ray >/dev/null 2>&1

        # 下载最新版本
        bash <(curl -L -s https://install.direct/go.sh) --force >/dev/null 2>&1

        # 启动V2Ray
        systemctl daemon-reload
        systemctl start v2ray >/dev/null 2>&1
        systemctl enable v2ray >/dev/null 2>&1

        sleep 2

        if systemctl is-active --quiet v2ray; then
            green "V2Ray 更新成功！"
        else
            red "V2Ray 更新失败！"
        fi
    else
        red "已取消更新 V2Ray 操作！"
    end
}

# 更新脚本
update_script(){
    green "当前脚本版本为 v${SCRIPT_VERSION}，是否检查更新？(y/n)"
    read -r update_script_confirm
    if [[ $update_script_confirm == "y" || $update_script_confirm == "Y" ]]; then
        # 下载最新版本
        wget -O warp.sh https://github.com/CCChieh/CFWarp-Pro/raw/main/warp.sh >/dev/null 2>&1
        chmod +x warp.sh

        green "脚本已成功更新，请重新运行脚本！"
        exit 0
    else
        red "已取消更新脚本操作！"
    fi
}

# 显示连接信息
show_connection_info(){
    clear
    green "连接信息如下："
    green "协议：WireGuard"
    green "端口：自动选择"
    green "密钥：自动选择"
    green "DNS：自动选择"
    green "证书：自动选择"
    green "订阅：/root/wgcf-account.toml"
    green "代理：127.0.0.1:443"
    green ""
    green "Hysteria 配置：/usr/local/etc/hysteria/config.yaml"
    green "Trojan 配置：/etc/trojan/trojan.yaml"
    green "V2Ray 配置：/etc/v2ray/config.json"
    green "Nginx 配置：/etc/nginx/nginx.conf"
    green "BBR/BBR Plus 配置：已优化"
}

# 主菜单
main_menu(){
    clear
    green "==============================================================================================="
    green "Warp 一键安装脚本 by 雨落无声"
    green "当前版本：v${SCRIPT_VERSION}"
    green "==============================================================================================="
    echo -e "当前状态："

    # 检查Warp状态
    if systemctl is-active --quiet warp; then
        green "Warp 状态：已启动"
    else
        red "Warp 状态：未启动"
    fi

    # 检查Hysteria状态
    if systemctl is-active --quiet hysteria; then
        green "Hysteria 状态：已启动"
    else
        red "Hysteria 状态：未启动"
    fi

    # 检查Trojan状态
    if systemctl is-active --quiet trojan; then
        green "Trojan 状态：已启动"
    else
        red "Trojan 状态：未启动"
    fi

    # 检查V2Ray状态
    if systemctl is-active --quiet v2ray; then
        green "V2Ray 状态：已启动"
    else
        red "V2Ray 状态：未启动"
    fi

    # 检查Nginx状态
    if systemctl is-active --quiet nginx; then
        green "Nginx 状态：已启动"
    else
        red "Nginx 状态：未启动"
    fi

    # 检查BBR/BBR Plus状态
    if [[ $(uname -r) == *bbrplus* ]]; then
        green "BBR/BBR Plus 状态：已优化"
    elif [[ $(uname -r) == *bbr* || $(lsmod | grep bbr) ]]; then
        green "BBR/BBR Plus 状态：已优化"
    else
        red "BBR/BBR Plus 状态：未优化"
    fi

    green "==============================================================================================="
    echo -e "菜单选项："
    echo -e "[1] 安装 Warp"
    echo -e "[2] 卸载 Warp"
    echo -e "[3] 添加新的 Warp+ 账户"
    echo -e "[4] 安装 Hysteria"
    echo -e "[5] 卸载 Hysteria"
    echo -e "[6] 更新 Hysteria"
    echo -e "[7] 安装 Trojan"
    echo -e "[8] 卸载 Trojan"
    echo -e "[9] 更新 Trojan"
    echo -e "[10] 安装 V2Ray"
    echo -e "[11] 卸载 V2Ray"
    echo -e "[12] 更新 V2Ray"
    echo -e "[13] 安装 Nginx"
    echo -e "[14] 卸载 Nginx"
    echo -e "[15] 优化系统配置"
    echo -e "[16] 卸载 BBR/BBR Plus 内核"
    echo -e "[17] 检查系统信息"
    echo -e "[18] 显示连接信息"
    echo -e "[19] 一键安装所有组件"
    echo -e "[20] 卸载所有组件"
    echo -e "[21] 检查更新脚本"
    echo -e "[22] 更新脚本"
    echo -e "[23] 退出脚本"
    green "==============================================================================================="

    echo -e "请输入选项的数字编号："
    read -r menu_option

    case $menu_option in
        1)
            install_warp
            ;;
        2)
            uninstall_warp
            ;;
        3)
            add_wgcf_account
            ;;
        4)
            install_hysteria
            ;;
        5)
            uninstall_hysteria
            ;;
        6)
            update_hysteria
            ;;
        7)
            install_trojan
            ;;
        8)
            uninstall_trojan
            ;;
        9)
            update_trojan
            ;;
        10)
            install_v2ray
            ;;
        11)
            uninstall_v2ray
            ;;
        12)
            update_v2ray
            ;;
        13)
            install_nginx
            ;;
        14)
            uninstall_nginx
            ;;
        15)
            optimize_system
            ;;
        16)
            uninstall_bbr
            ;;
        17)
            check_system_info
            ;;
        18)
            show_connection_info
            ;;
        19)
            install_warp
            install_hysteria
            install_trojan
            install_v2ray
            install_nginx
            optimize_system
            install_finished
            ;;
        20)
            uninstall_all
            ;;
        21)
            check_script_update
            ;;
        22)
            update_script
            ;;
        23)
            exit 0
            ;;
        *)
            red "无效的选项，请重新输入！"
            sleep 1
            main_menu
            ;;
    esac
}

# 检查脚本更新
check_script_update(){
    green "正在检查脚本更新，请稍候..."
    local latest_version=$(curl -s https://raw.githubusercontent.com/CCChieh/CFWarp-Pro/main/warp.sh | grep "SCRIPT_VERSION=" | head -1 | awk -F "=" '{print $2}' | awk -F '"' '{print $2}')
    if [[ $latest_version == $SCRIPT_VERSION ]]; then
        green "脚本已是最新版本，无需更新！"
    else
        red "发现新版本 v${latest_version}，是否更新？(y/n)"
        read -r update_confirm
        if [[ $update_confirm == "y" || $update_confirm == "Y" ]]; then
            wget -O warp.sh https://raw.githubusercontent.com/CCChieh/CFWarp-Pro/main/warp.sh >/dev/null 2>&1
            chmod +x warp.sh
            green "脚本已成功更新，请重新运行脚本！"
            exit 0
        else
            red "已取消更新脚本操作！"
        fi
    fi
}

# 检查系统信息
check_system_info(){
    clear
    green "系统信息如下："
    echo -e "操作系统：$SYSTEM $SYSTEM_VERSION"
    echo -e "内核版本：$(uname -r)"
    echo -e "CPU架构：$(arch)"
    echo -e "内网IP：$PRIVATE_IP"
    echo -e "公网IP：$PUBLIC_IP"
    echo -e "当前用户：$USER"
    echo -e "当前目录：$(pwd)"
    echo -e "脚本目录：$(dirname "$(readlink -f "$0")")"
    echo -e "脚本版本：v${SCRIPT_VERSION}"
    green "==============================================================================================="
    echo -e "菜单选项："
    echo -e "[1] 返回主菜单"
    echo -e "[2] 退出脚本"
    green "==============================================================================================="

    echo -e "请输入选项的数字编号："
    read -r system_info_option

    case $system_info_option in
        1)
            main_menu
            ;;
        2)
            exit 0
            ;;
        *)
            red "无效的选项，请重新输入！"
            sleep 1
            check_system_info
            ;;
    esac
}

# 检查脚本依赖
check_dependencies(){
    # 检查root权限
    if [[ $EUID -ne 0 ]]; then
        red "请使用root用户或sudo命令来运行此脚本！"
        exit 1
    fi

    # 检查操作系统
    if [[ -f /etc/redhat-release ]]; then
        SYSTEM="CentOS"
        SYSTEM_VERSION=$(awk '{print $(NF-1)}' /etc/redhat-release)
    elif [[ -f /etc/lsb-release || -f /etc/os-release ]]; then
        SYSTEM="Ubuntu"
        SYSTEM_VERSION=$(lsb_release -sr)
    else
        red "不支持的操作系统！"
        exit 1
    fi

    # 检查CPU架构
    if [[ $(arch) != "x86_64" ]]; then
        red "不支持的CPU架构！"
        exit 1
    fi

    # 检查系统内核
    if [[ $(uname -r) == *bbrplus* ]]; then
        KERNEL_BBR="BBR Plus"
    elif [[ $(uname -r) == *bbr* || $(lsmod | grep bbr) ]]; then
        KERNEL_BBR="BBR"
    else
        KERNEL_BBR="未优化"
    fi

    # 检查系统内网IP
    PRIVATE_IP=$(ip a | grep 'inet ' | grep -v '127.0.0.1\|10.0.0.1\|192.168.0.1' | awk '{print $2}' | cut -f1 -d '/')
    if [[ -z $PRIVATE_IP ]]; then
        red "无法获取内网IP，请检查网络配置！"
        exit 1
    fi

    # 检查系统公网IP
    PUBLIC_IP=$(curl -s -4 icanhazip.com)
    if [[ -z $PUBLIC_IP ]]; then
        red "无法获取公网IP，请检查网络配置！"
        exit 1
    fi

    # 检查系统用户
    USER=$(env | grep -Ei "USER=|USERNAME=" | cut -d'=' -f2)
}

# 脚本开始
check_dependencies
main_menu
