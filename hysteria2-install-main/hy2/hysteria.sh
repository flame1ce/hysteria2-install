#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red() {
    echo -e "\033[31m\033[01m$1\033[0m"
}

green() {
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow() {
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

realip() {
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

inst_cert() {
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
                bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/private.key --fullchain-file /root/cert.crt --ecc
                if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]]; then
                    echo "${domain}" >/root/ca.log
                    green "证书申请成功！"
                    hy_domain=$domain
                else
                    red "证书申请失败，请检查域名是否正确解析到本机IP，并重新执行脚本。"
                    exit 1
                fi
            else
                red "域名解析IP与本机IP不一致，请检查域名DNS是否已经正确解析到本机IP。"
                exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -p "请输入证书文件的绝对路径：" cert_path
        [[ ! -f $cert_path ]] && red "证书文件不存在，请检查路径是否正确！" && exit 1
        read -p "请输入证书私钥文件的绝对路径：" key_path
        [[ ! -f $key_path ]] && red "证书私钥文件不存在，请检查路径是否正确！" && exit 1
        domain=$(openssl x509 -noout -subject -in $cert_path | sed -n '/^subject/s/.*CN=//p')
        [[ -z $domain ]] && red "提取证书域名失败，请确认输入的证书文件是否正确！" && exit 1
        green "已输入的证书域名：$domain" && sleep 1
        hy_domain=$domain
    else
        green "使用默认的必应自签证书"
        cert_path="/usr/share/hysteria2/server.crt"
        key_path="/usr/share/hysteria2/server.key"
        hy_domain="localhost"
    fi
}

gen_hysteria_config() {
    mkdir -p /usr/share/hysteria2 /etc/hysteria2
    cat >/etc/hysteria2/config.yaml <<EOF
listen: 0.0.0.0:8888
verbose: true
refreshrate: 5
ipdb: ipipfree.ipdb
ipdb_watcher: 60
tls:
  enable: true
  certificate: ${cert_path}
  key: ${key_path}
EOF
}

install_hysteria() {
    if [[ -n $(pgrep hysteria2) ]]; then
        yellow "Hysteria 2 已经在运行，请检查！"
    else
        systemctl stop warp-go >/dev/null 2>&1
        wg-quick down wgcf >/dev/null 2>&1
        systemctl disable warp-go >/dev/null 2>&1
        ${PACKAGE_REMOVE[int]} -y caddy
        ${PACKAGE_REMOVE[int]} -y xray
        ${PACKAGE_REMOVE[int]} -y xserv
        ${PACKAGE_REMOVE[int]} -y hysteria2
        ${PACKAGE_REMOVE[int]} -y ipipfree
        ${PACKAGE_REMOVE[int]} -y ipipfree-conf
        ${PACKAGE_REMOVE[int]} -y qrencode
        ${PACKAGE_REMOVE[int]} -y wget
        rm -rf /etc/caddy /etc/ipipfree /usr/share/caddy /usr/share/hysteria2 /usr/share/xray /usr/bin/caddy /usr/bin/hysteria2 /usr/bin/xray /usr/bin/xray-nodog /usr/bin/xray-log /usr/bin/xray-dog /usr/bin/ipipfree /usr/bin/ipipfree-conf /usr/bin/v2ray /usr/bin/v2ctl /usr/bin/xray-nodog /usr/bin/xray-dog /usr/bin/wgcf /usr/local/etc/v2ray /usr/local/etc/wireguard /etc/systemd/system/hysteria2.service /etc/systemd/system/xray.service /root/.acme.sh /root/ipipfree /root/qrcode.png /root/caddy_* /root/client.conf /root/caddy /root/config.json /root/xray.crt /root/xray.key /root/xray_vless.crt /root/xray_vless.key /root/vless /root/vlessn /root/wgcf-account.toml /root/wgcf-profile.conf /etc/caddy /etc/wireguard /etc/xray /etc/hysteria2 /etc/ipipfree /etc/systemd/system/xray@.service
        sed -i '/warp-go/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
        sed -i '/fs.file-max/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
        sed -i '/net.ipv6.conf.all.forwarding/d' /etc/sysctl.conf
        sed -i '/net.ipv6.conf.all.accept_ra/d' /etc/sysctl.conf
        sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
        sysctl -p

        inst_cert
        gen_hysteria_config
        ${PACKAGE_INSTALL[int]} wget
        if [[ $SYSTEM == "CentOS" ]]; then
            ${PACKAGE_INSTALL[int]} socat
        fi
        wget -N --no-check-certificate https://github.com/boypt/hysteria/releases/download/v2.0.9/hysteria2_linux_amd64 -O /usr/bin/hysteria2
        chmod +x /usr/bin/hysteria2
        wget -N --no-check-certificate https://github.com/boypt/hysteria/releases/download/v2.0.9/ipipfree_linux_amd64 -O /usr/bin/ipipfree
        chmod +x /usr/bin/ipipfree
        green "Hysteria 2 安装成功！"
    fi
}

start_hysteria() {
    systemctl start hysteria2.service
    systemctl enable hysteria2.service
    if [[ -n $(systemctl is-active hysteria2.service) ]]; then
        green "Hysteria 2 启动成功！"
    else
        red "Hysteria 2 启动失败！"
    fi
}

show_qr_code() {
    if [[ -n $(pgrep hysteria2) ]]; then
        wg-quick down wgcf >/dev/null 2>&1
        systemctl stop warp-go >/dev/null 2>&1
        qrencode -t ANSIUTF8 -m 10 -n -o - "Hysteria 2 hysteria://${hy_domain}:8888?upauth=${password}" && echo ""
    else
        red "Hysteria 2 未运行，请检查！"
    fi
}

uninstall_hysteria() {
    read -p "确定要卸载 Hysteria 2 吗？(y/n): " uninstall_confirm
    [[ $uninstall_confirm != "y" ]] && red "卸载已取消..." && exit 1
    systemctl stop hysteria2.service
    systemctl disable hysteria2.service
    ${PACKAGE_REMOVE[int]} -y hysteria2
    ${PACKAGE_REMOVE[int]} -y ipipfree
    rm -rf /usr/share/hysteria2 /etc/hysteria2
    rm -f /usr/bin/hysteria2 /usr/bin/ipipfree
    sed -i '/hysteria2/d' /etc/sudoers
    if [[ -n $(pgrep hysteria2) ]]; then
        red "Hysteria 2 卸载失败，请检查！"
    else
        green "Hysteria 2 卸载成功！"
    fi
}

start_menu() {
    clear
    green "========================================"
    green "       Hysteria 2 一键管理脚本"
    green "----------------------------------------"
    green "  系统：$SYSTEM"
    green "========================================"
    echo -e "\n"
    yellow " 1. 安装 Hysteria 2"
    yellow " 2. 启动 Hysteria 2"
    yellow " 3. 生成 Hysteria 2 客户端配置"
    yellow " 4. 卸载 Hysteria 2"
    yellow " 5. 退出脚本"
    echo -e "\n"
    read -rp "请输入数字：" menu_num
    case $menu_num in
    1)
        install_hysteria
        ;;
    2)
        start_hysteria
        ;;
    3)
        show_qr_code
        ;;
    4)
        uninstall_hysteria
        ;;
    5)
        exit 0
        ;;
    *)
        red "请输入正确的数字！"
        ;;
    esac
}

start_menu
