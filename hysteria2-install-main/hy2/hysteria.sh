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
                bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/private.key --fullchain-file /root/cert.crt --ecc
                if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]]; then
                    rm -f /root/ca.log
                    echo $domain > /root/ca.log
                    chmod -f 644 /root/ca.log
                    green "证书申请成功！" && sleep 1
                    hy_domain=$domain
                else
                    red "证书申请失败，请检查网络是否正常或稍后重试！" && exit 1
                fi
            else
                red "域名解析地址与当前 VPS IP 地址不一致，无法申请证书！" && exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -rp "请输入证书文件的绝对路径：" cert_path
        read -rp "请输入证书私钥文件的绝对路径：" key_path
        [[ ! -f $cert_path || ! -f $key_path ]] && red "证书文件或私钥文件不存在，请确认路径是否正确！" && exit 1
        green "已输入的证书文件路径：$cert_path"
        green "已输入的证书私钥文件路径：$key_path"
        hy_domain=""
    else
        cert_path="/etc/ssl/cert.pem"
        key_path="/etc/ssl/private.key"
        hy_domain=""
    fi
}

install(){
    ${PACKAGE_INSTALL[int]} wget sudo socat openssl
    bash <(wget --no-check-certificate -qO- https://github.com/wulabing/5sing/raw/main/warp) 2>&1 | tee warp.log
    if [[ -f /usr/local/bin/wgcf ]]; then
        chmod +x /usr/local/bin/wgcf
    else
        red "warp 申请脚本安装失败，请检查网络是否正常或稍后重试！" && exit 1
    fi

    mkdir -p /etc/wireguard/ >/dev/null 2>&1
    if [[ -f /etc/wireguard/wgcf.conf && -f /etc/wireguard/wgcf-publickey.conf ]]; then
        wgcfProfile=$(wg show wgcf)
        if [[ -n $wgcfProfile ]]; then
            yellow "检测到已存在的 wgcf 配置文件，是否覆盖？（已存在的配置文件将会备份在 /etc/wireguard 目录下，文件名为 wgcf-日期.conf.bak） [Y/N]"
            read -rp "请输入选项 [Y/N]: " isCover
            [[ -z $isCover ]] && isCover="N"
            if [[ $isCover == [Yy] ]]; then
                mv /etc/wireguard/wgcf.conf /etc/wireguard/wgcf-$(date "+%Y-%m-%d").conf.bak
                mv /etc/wireguard/wgcf-publickey.conf /etc/wireguard/wgcf-publickey-$(date "+%Y-%m-%d").conf.bak
            fi
        fi
    fi

    if [[ ! -f /etc/wireguard/wgcf.conf && ! -f /etc/wireguard/wgcf-publickey.conf ]]; then
        mkdir -p /usr/lib/systemd/system >/dev/null 2>&1
        wgcfDeviceName=$(ip addr | grep -w inet | awk '{print $NF}' | grep -v "lo" | head -n 1)
        wgcfIP=$(ip addr | grep -w inet | awk '{print $2}' | grep -v "127.0.0.1" | sed 's/\/.*//')
        wgcfIPV6=$(ip addr | grep -w inet6 | awk '{print $2}' | grep -v "::1/128" | sed 's/\/.*//')
        read -rp "是否需要配置 IPv6 网络数据传输（默认否）[Y/N]: " isIPV6
        [[ -z $isIPV6 ]] && isIPV6="N"
        if [[ $isIPV6 == [Yy] ]]; then
            curl -s6m8 ip.sb -k || { red "系统不支持 IPv6 网络数据传输，无法继续操作！" && exit 1; }
        fi
        read -rp "是否需要开启虚假协议数据传输（默认否）[Y/N]: " isFakeProtocol
        [[ -z $isFakeProtocol ]] && isFakeProtocol="N"
        if [[ $isFakeProtocol == [Yy] ]]; then
            curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2 | grep on || { red "系统不支持虚假协议数据传输，无法继续操作！" && exit 1; }
            wgcfIP=$(curl -s4m8 ip.sb -k)
            wgcfIPV6=$(curl -s6m8 ip.sb -k)
        fi
        if [[ $isIPV6 == [Yy] && $isFakeProtocol == [Yy] ]]; then
            wgcfIPV6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            wgcfStatus=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $wgcfStatus =~ on|plus ]] && [[ $wgcfIP == $ip ]]; then
                realip
                if [[ $wgcfIPV6Status =~ on|plus ]] && [[ $wgcfIPV6 == $ip ]]; then
                    red "未开启虚假协议数据传输（IPv4 和 IPv6），无法继续操作！" && exit 1
                fi
            elif [[ $wgcfIPV6Status =~ on|plus ]] && [[ $wgcfIPV6 == $ip ]]; then
                realip
            fi
        fi
        read -rp "是否需要将 IPv6 网络数据传输标记为指定地区（默认否）[Y/N]: " isRegion
        [[ -z $isRegion ]] && isRegion="N"
        if [[ $isRegion == [Yy] ]]; then
            echo "IP_CIDR=1.0.0.0/24" >>/etc/wireguard/ip-region.conf
        fi
        bash -c "cat > /etc/wireguard/wgcf.conf" <<EOF
# 默认配置文件

[Interface]
PrivateKey = $(wg genkey)
Address = 1.1.1.1/32, 2606:4700:4700::1111/128
DNS = 1.1.1.1, 2606:4700:4700::1111
EOF
        bash -c "cat > /etc/wireguard/wgcf-publickey.conf" <<EOF
# 默认配置文件

[Peer]
PublicKey = $(wg pubkey < /etc/wireguard/wgcf.conf)
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
PersistentKeepalive = 25
EOF
        bash -c "cat > /usr/lib/systemd/system/wgcf.service" <<EOF
[Unit]
Description=Cloudflare Warp Client
Documentation=https://github.com/ventoy/WARP

[Service]
ExecStart=/usr/local/bin/wgcf start
Restart=on-failure
RestartSec=3
User=root
EOF
        bash -c "cat > /usr/lib/systemd/system/wgcf.timer" <<EOF
[Unit]
Description=Run Cloudflare Warp Client on boot
Documentation=https://github.com/ventoy/WARP

[Timer]
OnBootSec=5s
OnUnitActiveSec=1d
AccuracySec=1h
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload
        systemctl enable wgcf.timer
        systemctl start wgcf.timer
        [[ $(systemctl is-enabled wgcf.timer) == "enabled" && $(systemctl is-active wgcf.timer) == "active" ]] && green "warp 已成功安装并启动！" || red "warp 启动失败，请检查日志并手动启动！"
    else
        red "warp 已安装，无需重复操作！"
    fi
    systemctl restart wg-quick@wgcf >/dev/null 2>&1
    [[ $(systemctl is-enabled wg-quick@wgcf) == "enabled" && $(systemctl is-active wg-quick@wgcf) == "active" ]] && green "wgcf 已成功配置并启动！" || red "wgcf 启动失败，请检查日志并手动启动！"
    systemctl enable wg-quick@wgcf >/dev/null 2>&1
}

main(){
    checkSystem
    getData
    preInstall
    install
}

main
