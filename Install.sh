#!/bin/bash

RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

certificate_path=""
private_key_path=""

function configure_dns64() {
    local ipv4_address
    local ipv6_address

    ipv4_address=$(curl -s4 ifconfig.co)
    ipv6_address=$(curl -s6 ifconfig.co)
    
    if [[ -n $ipv4_address ]]; then
        return
    fi

    if [[ -n $ipv6_address ]]; then
        echo "Check that the machine is IPv6 single-stack network, configure DNS64..."
        sed -i '/^nameserver /s/^/#/' /etc/resolv.conf 
        echo "nameserver 2001:67c:2b0::4" >> /etc/resolv.conf
        echo "nameserver 2001:67c:2b0::6" >> /etc/resolv.conf
        echo "DNS64 configuration is complete."
    fi
}

function check_firewall_configuration() {
    local os_name=$(uname -s)
    local firewall

    if [[ $os_name == "Linux" ]]; then
        if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
            firewall="ufw"
        elif command -v ip6tables >/dev/null 2>&1 && ip6tables -S | grep -q "INPUT -j DROP"; then
            firewall="ip6tables"
        elif command -v iptables >/dev/null 2>&1 && iptables -S | grep -q "INPUT -j DROP"; then
            firewall="iptables"
        elif systemctl is-active --quiet netfilter-persistent; then
            firewall="iptables-persistent"
        elif systemctl is-active --quiet iptables.service; then
            firewall="iptables-service"            
        elif command -v firewalld >/dev/null 2>&1 && firewall-cmd --state | grep -q "running"; then
            firewall="firewalld"
        fi
    fi

    if [[ -z $firewall ]]; then
        echo "No firewall configuration detected or firewall is not enabled, skipping firewall configuration."
        return
    fi

    echo "Checking firewall configuration..."
    case $firewall in
        ufw)
            if ! ufw status | grep -q "Status: active" 2>/dev/null; then
                ufw enable > /dev/null 2>&1
            fi

            if ! ufw status | grep -q " $listen_port" 2>/dev/null; then
                ufw allow "$listen_port" > /dev/null 2>&1
            fi

            if ! ufw status | grep -q " $override_port" 2>/dev/null; then
                ufw allow "$override_port" > /dev/null 2>&1
            fi

            if ! ufw status | grep -q " $fallback_port" 2>/dev/null; then
                ufw allow "$fallback_port" > /dev/null 2>&1
            fi
            
            if ! ufw status | grep -q " 80" 2>/dev/null; then
                ufw allow 80 > /dev/null 2>&1
            fi

            echo "Firewall configuration has been updated."
            ;;
        iptables | iptables-persistent | iptables-service)
            if ! iptables -C INPUT -p tcp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p tcp --dport "$listen_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! iptables -C INPUT -p udp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p udp --dport "$listen_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! iptables -C INPUT -p tcp --dport "$override_port" -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p tcp --dport "$override_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! iptables -C INPUT -p udp --dport "$override_port" -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p udp --dport "$override_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! iptables -C INPUT -p tcp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p tcp --dport "$fallback_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! iptables -C INPUT -p udp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p udp --dport "$fallback_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p tcp --dport 80 -j ACCEPT > /dev/null 2>&1
            fi

            if ! iptables -C INPUT -p udp --dport 80 -j ACCEPT >/dev/null 2>&1; then
                iptables -A INPUT -p udp --dport 80 -j ACCEPT > /dev/null 2>&1
            fi

            if ! ip6tables -C INPUT -p tcp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
                ip6tables -A INPUT -p tcp --dport "$listen_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! ip6tables -C INPUT -p udp --dport "$listen_port" -j ACCEPT >/dev/null 2>&1; then
                ip6tables -A INPUT -p udp --dport "$listen_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! ip6tables -C INPUT -p tcp --dport "$override_port" -j ACCEPT >/dev/null 2>&1; then
                ip6tables -A INPUT -p tcp --dport "$override_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! ip6tables -C INPUT -p udp --dport "$override_port" -j ACCEPT >/dev/null 2>&1; then
                ip6tables -A INPUT -p udp --dport "$override_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! ip6tables -C INPUT -p tcp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1; then
                ip6tables -A INPUT -p tcp --dport "$fallback_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! ip6tables -C INPUT -p udp --dport "$fallback_port" -j ACCEPT >/dev/null 2>&1; then
                ip6tables -A INPUT -p udp --dport "$fallback_port" -j ACCEPT > /dev/null 2>&1
            fi

            if ! ip6tables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1; then
                ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT > /dev/null 2>&1
            fi

            if ! ip6tables -C INPUT -p udp --dport 80 -j ACCEPT >/dev/null 2>&1; then
                ip6tables -A INPUT -p udp --dport 80 -j ACCEPT > /dev/null 2>&1
            fi

            if [[ -e /etc/iptables/rules.v4 ]]; then
                iptables-save > /etc/iptables/rules.v4
            elif [[ -e /etc/sysconfig/iptables ]]; then
                iptables-save > /etc/sysconfig/iptables
            fi

            if [[ -e /etc/iptables/rules.v6 ]]; then
                ip6tables-save > /etc/iptables/rules.v6
            elif [[ -e /etc/sysconfig/ip6tables ]]; then
                ip6tables-save > /etc/sysconfig/ip6tables
            fi

            echo "Firewall configuration has been updated."
            ;;
        firewalld)
            if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/tcp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$listen_port/tcp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/udp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$listen_port/udp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$override_port/tcp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$override_port/tcp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$override_port/udp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$override_port/udp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$fallback_port/tcp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$fallback_port/tcp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$fallback_port/udp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$fallback_port/udp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "80/tcp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port=80/tcp --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "80/udp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port=80/udp --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/tcp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$listen_port/tcp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$listen_port/udp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$listen_port/udp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$override_port/tcp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$override_port/tcp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$override_port/udp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$override_port/udp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$fallback_port/tcp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$fallback_port/tcp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "$fallback_port/udp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port="$fallback_port/udp" --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "80/tcp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port=80/tcp --permanent > /dev/null 2>&1
            fi

            if ! firewall-cmd --zone=public --list-ports | grep -q "80/udp" 2>/dev/null; then
                firewall-cmd --zone=public --add-port=80/udp --permanent > /dev/null 2>&1
            fi

            firewall-cmd --reload

            echo "Firewall configuration has been updated."
            ;;
    esac
}

function create_sing_box_folder() {
    local folder="/usr/local/etc/sing-box"
    if [[ ! -d "$folder" ]]; then
        mkdir -p "$folder"
    fi
    touch "$folder/config.json"
}

function create_ssl_folder() {
    local ssl_folder="/etc/ssl/private"
        
    if [[ ! -d "$ssl_folder" ]]; then
        mkdir -p "$ssl_folder"
    fi
}

function create_juicity_folder() {
    local folder="/usr/local/etc/juicity"
    if [[ ! -d "$folder" ]]; then
        mkdir -p "$folder"
    fi
}

function ensure_clash_yaml() {
    local dir="/usr/local/etc/sing-box"
    local clash_yaml="${dir}/clash.yaml"
    if [ ! -e "${clash_yaml}" ]; then
        touch "${clash_yaml}"
    fi
}

function check_config_file_existence() {
    local config_file="/usr/local/etc/sing-box/config.json"
    if [ ! -f "$config_file" ]; then
     echo -e "${RED}sing-box 配置文件不存在，请先搭建节点！${NC}"
      exit 1
    fi
}

function generate_naive_random_filename() {
    local dir="/usr/local/etc/sing-box"
    local filename=""    
    while true; do
        random_value=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 5 | head -n 1)        
        filename="naive_client_${random_value}.json"       
        if [ ! -e "${dir}/${filename}" ]; then
            touch "${dir}/${filename}"
            naive_client_filename="${dir}/${filename}"
            break
        fi
    done
}

function check_sing_box_existence() {
    if [[ -f "/usr/local/bin/sing-box" ]]; then
        return 1
    else
        return 0
    fi
}

function install_sing_box() {
    check_sing_box_existence
    local result=$?
        
    if [[ $result -eq 0 ]]; then
        configure_dns64
        enable_bbr
        select_sing_box_install_option
        configure_sing_box_service
        create_sing_box_folder
        create_ssl_folder
        
    fi    
}

function enable_bbr() {
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "Enable BBR..."
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p > /dev/null
        echo "BBR has been enabled"
    else
        echo "BBR is already enabled, skipping configuration."
    fi
}

function select_sing_box_install_option() {
    while true; do
        echo "请选择 sing-box 的安装方式（默认1）："
        echo "1). 下载安装 sing-box（Latest 版本，推荐使用）"
        echo "2). 下载安装 sing-box（Beta 版本，支持hysteria2）"
        echo "3). 编译安装 sing-box（低配置服务器慎用）"

        local install_option
        read -p "请选择 [1-2]: " install_option
        install_option="${install_option:-1}"

        case $install_option in
            1)
                install_latest_sing_box
                break
                ;;
            2)
                install_Pre_release_sing_box
                break
                ;;                
        
            3)
                install_go
                compile_install_sing_box
                break
                ;;
            *)
                echo -e "${RED}无效的选择，请重新输入！${NC}"
                ;;
        esac
    done
}

function install_go() {
    if ! command -v go &> /dev/null; then
        echo "Downloading Go..."
        local go_arch
        case $(uname -m) in
            x86_64)
                go_arch="amd64"
                ;;
            i686)
                go_arch="386"
                ;;
            aarch64)
                go_arch="arm64"
                ;;
            armv6l)
                go_arch="armv6l"
                ;;
            *)
                echo -e "${RED}不支持的架构: $(uname -m)${NC}"
                exit 1
                ;;
        esac

        local go_version
        go_version=$(curl -sL "https://golang.org/VERSION?m=text" | grep -o 'go[0-9]\+\.[0-9]\+\.[0-9]\+')
        local go_download_url="https://go.dev/dl/$go_version.linux-$go_arch.tar.gz"

        wget -qO- "$go_download_url" | tar -xz -C /usr/local
        echo 'export PATH=$PATH:/usr/local/go/bin' |  tee -a /etc/profile >/dev/null
        source /etc/profile
        go version
        
        echo "Go has been installed."
    else
        echo "Go is already installed, skipping installation."
    fi
}

function compile_install_sing_box() {
    local go_install_command="go install -v -tags \
with_quic,\
with_grpc,\
with_dhcp,\
with_wireguard,\
with_shadowsocksr,\
with_ech,\
with_utls,\
with_reality_server,\
with_acme,\
with_clash_api,\
with_v2ray_api,\
with_gvisor,\
with_lwip \
github.com/sagernet/sing-box/cmd/sing-box@latest"

    echo "Compiling and installing sing-box, please wait..."
    $go_install_command

    if [[ $? -eq 0 ]]; then
        mv ~/go/bin/sing-box /usr/local/bin/
        chmod +x /usr/local/bin/sing-box
        echo "sing-box has been compiled and installed successfully."
    else
        echo -e "${RED}sing-box compilation and installation failed.${NC}"
        exit 1
    fi
}

function install_latest_sing_box() {
    local arch=$(uname -m)
    local url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url

    case $arch in
        x86_64)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-amd64.tar.gz")
            ;;
        armv7l)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-armv7.tar.gz")
            ;;
        aarch64)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-arm64.tar.gz")
            ;;
        amd64v3)
            download_url=$(curl -s $url | grep -o "https://github.com[^\"']*linux-amd64v3.tar.gz")
            ;;
        *)
            echo -e "${RED}不支持的架构：$arch${NC}"
            return 1
            ;;
    esac

    if [ -n "$download_url" ]; then
        echo "Downloading Sing-Box..."
        wget -qO sing-box.tar.gz "$download_url" 2>&1 >/dev/null
        tar -xzf sing-box.tar.gz -C /usr/local/bin --strip-components=1
        rm sing-box.tar.gz
        chmod +x /usr/local/bin/sing-box

        echo "Sing-Box installed successfully."
    else
        echo -e "${RED}Unable to retrieve the download URL for Sing-Box.${NC}"
        return 1
    fi
}

function install_Pre_release_sing_box() {
    local arch=$(uname -m)
    local url="https://api.github.com/repos/SagerNet/sing-box/releases"
    local download_url

    case $arch in
        x86_64)
            download_url=$(curl -s "$url" | jq -r '.[] | select(.prerelease == true) | .assets[] | select(.browser_download_url | contains("linux-amd64.tar.gz")) | .browser_download_url' | head -n 1)
            ;;
        armv7l)
            download_url=$(curl -s "$url" | jq -r '.[] | select(.prerelease == true) | .assets[] | select(.browser_download_url | contains("linux-armv7.tar.gz")) | .browser_download_url' | head -n 1)
            ;;
        aarch64)
            download_url=$(curl -s "$url" | jq -r '.[] | select(.prerelease == true) | .assets[] | select(.browser_download_url | contains("linux-arm64.tar.gz")) | .browser_download_url' | head -n 1)
            ;;
        amd64v3)
            download_url=$(curl -s "$url" | jq -r '.[] | select(.prerelease == true) | .assets[] | select(.browser_download_url | contains("linux-amd64v3.tar.gz")) | .browser_download_url' | head -n 1)
            ;;
        *)
            echo -e "${RED}不支持的架构：$arch${NC}"
            return 1
            ;;
    esac

    if [ -n "$download_url" ]; then
        echo "Downloading Sing-Box..."
        wget -qO sing-box.tar.gz "$download_url" 2>&1 >/dev/null
        tar -xzf sing-box.tar.gz -C /usr/local/bin --strip-components=1
        rm sing-box.tar.gz
        chmod +x /usr/local/bin/sing-box

        echo "Sing-Box installed successfully."
    else
        echo -e "${RED}Unable to get pre-release download link for Sing-Box.${NC}"
        return 1
    fi
}

function install_latest_juicity() {
    local arch=$(uname -m)

    case $arch in
        "arm64")
            arch_suffix="arm64"
            ;;
        "armv5")
            arch_suffix="armv5"
            ;;
        "armv6")
            arch_suffix="armv6"
            ;;
        "armv7")
            arch_suffix="armv7"
            ;;
        "mips")
            arch_suffix="mips32"
            ;;
        "mipsel")
            arch_suffix="mips32le"
            ;;
        "mips64")
            arch_suffix="mips64"
            ;;
        "mips64el")
            arch_suffix="mips64le"
            ;;
        "riscv64")
            arch_suffix="riscv64"
            ;;
        "i686")
            arch_suffix="x86_32"
            ;;
        "x86_64")
            if [ -n "$(grep avx2 /proc/cpuinfo)" ]; then
                arch_suffix="x86_64_v3_avx2"
            else
                arch_suffix="x86_64_v2_sse"
            fi
            ;;
        *)
            echo "Unsupported architecture: $arch"
            return 1
            ;;
    esac

    local github_api_url="https://api.github.com/repos/juicity/juicity/releases/latest"
    local download_url=$(curl -s "$github_api_url" | grep "browser_download_url.*$arch_suffix.zip\"" | cut -d '"' -f 4)
    local temp_dir=$(mktemp -d)
    local install_path="/usr/local/bin/juicity-server"

    echo "Downloading the latest version of juicity-server..."
    wget -P "$temp_dir" "$download_url" >/dev/null 2>&1
    unzip "$temp_dir/*.zip" -d "$temp_dir" >/dev/null 2>&1    
    mv "$temp_dir/juicity-server" "$install_path" >/dev/null 2>&1
    chmod +x /usr/local/bin/juicity-server
    echo "juicity-server has been downloaded."    
    rm -rf "$temp_dir"
}

function get_temp_config_file() {
    temp_file=$(mktemp)
    curl -sSL "https://api.zeroteam.top/warp?format=sing-box" > "$temp_file"
}

function configure_sing_box_service() {
    echo "Configuring sing-box startup service..."
    local service_file="/etc/systemd/system/sing-box.service"

    if [[ -f $service_file ]]; then
        rm "$service_file"
    fi
    
       local service_config='[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target'

        echo "$service_config" >"$service_file"
        echo "sing-box startup service has been configured."
}

function configure_juicity_service() {
    echo "Configuring juicity startup service..."
    local service_file="/etc/systemd/system/juicity.service"

    if [[ -f $service_file ]]; then
        rm "$service_file"
    fi
    
       local service_config='[Unit]
Description=juicity-server Service
Documentation=https://github.com/juicity/juicity
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
Environment=QUIC_GO_ENABLE_GSO=true
ExecStart=/usr/local/bin/juicity-server run -c /usr/local/etc/juicity/config.json --disable-timestamp
Restart=on-failure
LimitNPROC=512
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target'

        echo "$service_config" >"$service_file"
        echo "juicity startup service has been configured."
}

function listen_port() {
    while true; do
        read -p "请输入监听端口 (默认443): " listen_port
        listen_port=${listen_port:-443}

        if [[ $listen_port =~ ^[1-9][0-9]{0,4}$ && $listen_port -le 65535 ]]; then
            echo "监听端口: $listen_port"
            break
        else
            echo -e "${RED}错误：端口范围1-65535，请重新输入！${NC}" >&2
        fi
    done
}

function set_username() {
    read -p "请输入用户名 (默认随机生成): " new_username
    if [[ -z "$new_username" ]]; then
        username=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)
        echo "随机生成的用户名: $username"
    else
        username="$new_username"
        echo "用户名: $username"
    fi
}

function set_password() {
    read -p "请输入密码（默认随机生成）: " password

    if [[ -z "$password" ]]; then
        password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)
        echo "随机生成的密码：$password"
    else
        echo "密码：$password"
    fi
}

function read_up_speed() {
    while true; do
        read -p "请输入上行速率 (默认50): " up_mbps
        up_mbps=${up_mbps:-50}

        if [[ $up_mbps =~ ^[0-9]+$ ]]; then
            echo "上行速率设置成功：$up_mbps Mbps"
            break
        else
            echo -e "${RED}错误：请输入数字作为上行速率！${NC}"
        fi
    done
}

function read_down_speed() {
    while true; do
        read -p "请输入下行速率 (默认100): " down_mbps
        down_mbps=${down_mbps:-100}

        if [[ $down_mbps =~ ^[0-9]+$ ]]; then
            echo "下行速率设置成功：$down_mbps Mbps"
            break
        else
            echo -e "${RED}错误：请输入数字作为下行速率！${NC}"
        fi
    done
}

function generate_uuid() {
    if [[ -n $(command -v uuidgen) ]]; then
        command_name="uuidgen"
    elif [[ -n $(command -v uuid) ]]; then
        command_name="uuid -v 4"
    else
        echo -e "${RED}错误：无法生成UUID，请手动设置！${NC}"
        exit 1
    fi

    while true; do
        read -p "请输入UUID（默认随机生成）: " input_uuid
        if [[ -n $input_uuid ]]; then
            if [[ $input_uuid =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
                uuid=$input_uuid
                break
            else
                echo -e "${RED}无效的UUID格式，请重新输入！${NC}"
            fi
        else
            uuid=$($command_name)
            break
        fi
    done

    echo "生成的UUID：$uuid"
}

function set_short_id() {
    while true; do
        read -p "请输入 short id (默认随机生成): " short_id

        if [[ -z "$short_id" ]]; then
            short_id=$(openssl rand -hex 8)
            break
        elif [[ "$short_id" =~ ^[0-9a-fA-F]{2,16}$ ]]; then
            break
        else
            echo "错误：请输入两到八位的十六进制字符串！"
        fi
    done
}

function override_port() {
    while true; do
        read -p "请输入目标端口 (默认443): " override_port
        override_port=${override_port:-443}

        if [[ $override_port =~ ^[1-9][0-9]{0,4}$ && $override_port -le 65535 ]]; then
            echo "目标端口: $override_port"
            break
        else
            echo -e "${RED}错误：端口范围1-65535，请重新输入！${NC}"
        fi
    done
}

function generate_unique_tag() {
    local config_file="/usr/local/etc/sing-box/config.json"
    while true; do
        random_tag=$(head /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n 1)
        tag_label="${random_tag}-in"

        if ! grep -qE "\"tag\":\\s*\"$tag_label\"(,|$)" "$config_file"; then
            break
        fi
    done
}

function override_address() {
  while true; do
    read -p "请输入目标地址（IP或域名）: " target_address

    if [[ -z "$target_address" ]]; then
      echo -e "${RED}错误：目标地址不能为空！${NC}"
      continue
    fi

    if [[ $target_address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      if [[ $(grep -o '\.' <<< "$target_address" | wc -l) -eq 3 ]]; then
        break
      else
        echo -e "${RED}错误：请输入有效的 IPv4 地址！${NC}"
      fi
    elif [[ $target_address =~ ^[a-fA-F0-9:]+$ ]]; then
      if [[ $(grep -o ':' <<< "$target_address" | wc -l) -ge 2 ]]; then
        break
      else
        echo -e "${RED}错误：请输入有效的 IPv6 地址！${NC}"
      fi
    else
      resolved_ips=$(host -t A "$target_address" | awk '/has address/ { print $4 }')

      if [[ -n "$resolved_ips" ]]; then
        valid_ip=0
        for ip in $resolved_ips; do
          if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            valid_ip=1
            break
          fi
        done
        if [[ $valid_ip -eq 1 ]]; then
          break
        else
          echo -e "${RED}错误：域名未解析为有效的 IPv4 地址，请重新输入！${NC}"
        fi
      else
        echo -e "${RED}错误：请输入有效的 IP 地址或域名！${NC}"
      fi
    fi
  done
}

function generate_private_key_config() {
    local private_key

    while true; do
        read -p "请输入私钥 (默认随机生成私钥): " private_key

        if [[ -z "$private_key" ]]; then
            local keypair_output=$(sing-box generate reality-keypair)
            private_key=$(echo "$keypair_output" | awk -F: '/PrivateKey/{gsub(/ /, "", $2); print $2}')
            echo "$keypair_output" | awk -F: '/PublicKey/{gsub(/ /, "", $2); print $2}' > /tmp/public_key_temp.txt
            break
        fi

        if openssl pkey -inform PEM -noout -text -in <(echo "$private_key") >/dev/null 2>&1; then
            break
        else
            echo -e "${RED}无效的私钥，请重新输入！${NC}" >&2
        fi
    done
    
    echo "$private_key"
}

function generate_server_name() {
    while true; do
        read -p "请输入可用的 serverName 列表 (默认为 nijigen-works.jp): " user_input
        if [[ -z "$user_input" ]]; then
            server_name="nijigen-works.jp"
            break
        else
            server_name="$user_input"
            echo "Verifying server's TLS version support..."

            if command -v openssl >/dev/null 2>&1; then
                local openssl_output=$(timeout 10s openssl s_client -connect "$server_name:443" -tls1_3 2>&1)
                if [[ $openssl_output == *"TLS_AES_256_GCM_SHA384"* || \
                      $openssl_output == *"TLS_AES_128_GCM_SHA256"* || \
                      $openssl_output == *"TLS_CHACHA20_POLY1305_SHA256"* || \
                      $openssl_output == *"TLS_AES_128_CCM_SHA256"* || \
                      $openssl_output == *"TLS_AES_128_CCM_8_SHA256"* ]]; then
                    break
                else
                    echo -e "${RED}该网址不支持 TLS 1.3，请重新输入！${NC}"
                fi
            else
                echo "OpenSSL is not installed, cannot verify TLS support."
                break
            fi
        fi
    done
}

function generate_target_server() {
    while true; do
        read -p "请输入目标网站地址(默认为 nijigen-works.jp): " user_input

        if [[ -z "$user_input" ]]; then
            target_server="nijigen-works.jp"
            break
        else
            target_server="$user_input"
            echo "Verifying server's TLS version support..."

            if command -v openssl >/dev/null 2>&1; then
                local openssl_output=$(timeout 10s openssl s_client -connect "$target_server:443" -tls1_3 2>&1)
                if [[ $openssl_output == *"TLS_AES_256_GCM_SHA384"* || \
                      $openssl_output == *"TLS_AES_128_GCM_SHA256"* || \
                      $openssl_output == *"TLS_CHACHA20_POLY1305_SHA256"* || \
                      $openssl_output == *"TLS_AES_128_CCM_SHA256"* || \
                      $openssl_output == *"TLS_AES_128_CCM_8_SHA256"* ]]; then
                    break
                else
                    echo -e "${RED}该目标网站地址不支持 TLS 1.3，请重新输入！${NC}" 
                fi
            else
                echo "OpenSSL is not installed, cannot verify TLS support."
                break
            fi
        fi
    done
}

function get_local_ip() {
    local local_ip_v4
    local local_ip_v6

    local_ip_v4=$(curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org || curl -s https://ifconfig.co/ip || curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" || curl -s icanhazip.com || curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
    local_ip_v6=$(ip -o -6 addr show scope global | awk '{split($4, a, "/"); print a[1]; exit}')

    if [[ -n "$local_ip_v4" ]]; then
        echo "$local_ip_v4"
    elif [[ -n "$local_ip_v6" ]]; then
        echo "$local_ip_v6"
    else
        echo -e "${RED}无法获取本机IP地址！${NC}"
    fi
}

function get_domain() {
    while true; do
        read -p "请输入域名（关闭Cloudflare代理）： " domain

        local_ip_v4=$(curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org || curl -s https://ifconfig.co/ip || curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" || curl -s icanhazip.com || curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
        local_ip_v6=$(ip -o -6 addr show scope global | awk '{split($4, a, "/"); print a[1]; exit}')

        resolved_ipv4=$(dig +short A "$domain" 2>/dev/null)
        resolved_ipv6=$(dig +short AAAA "$domain" 2>/dev/null)

        if [[ -z $domain ]]; then
            echo -e "${RED}错误：域名不能为空，请重新输入！${NC}"
        else
            if [[ ("$resolved_ipv4" == "$local_ip_v4" && ! -z "$resolved_ipv4") || ("$resolved_ipv6" == "$local_ip_v6" && ! -z "$resolved_ipv6") ]]; then
                break
            else
                if [[ -z "$resolved_ipv4" && -n "$local_ip_v4" ]]; then
                    resolved_ip_v4=$(ping -4 "$domain" -c 1 2>/dev/null | sed '1{s/[^(]*(//;s/).*//;q}')
                    if [[ ("$resolved_ip_v4" == "$local_ip_v4" && ! -z "$resolved_ip_v4") ]]; then
                        break
                    fi
                fi
                if [[ -z "$resolved_ipv6" && -n "$local_ip_v6" ]]; then
                    resolved_ip_v6=$(ping -6 "$domain" -c 1 2>/dev/null | sed '1{s/[^(]*(//;s/).*//;q}')
                    if [[ ("$resolved_ip_v6" == "$local_ip_v6" && ! -z "$resolved_ip_v6") ]]; then
                        break
                    fi
                fi
                echo -e "${RED}错误：域名未绑定本机IP，请重新输入！${NC}"
            fi
        fi
    done
}
   
function get_fake_domain() {
    while true; do
        read -p "请输入伪装网址（默认: www.fan-2000.com）: " fake_domain
        fake_domain=${fake_domain:-"www.fan-2000.com"}

        if curl --output /dev/null --silent --head --fail "$fake_domain"; then
            echo "伪装网址: $fake_domain"
            break
        else
            echo -e "${RED}伪装网址无效或不可用，请重新输入！${NC}"
        fi
    done
}

function set_certificate_and_private_key() {
    while true; do
        read -p "请输入 PEM 证书位置: " certificate_path_input

        if [[ ! -f "$certificate_path_input" ]]; then
            echo -e "${RED}错误：证书文件不存在，请重新输入！${NC}"
            continue
        fi

        certificate_file=$(basename "$certificate_path_input")
        allowed_extensions=("crt" "pem")
        if [[ ! "${allowed_extensions[@]}" =~ "${certificate_file##*.}" ]]; then
            echo -e "${RED}错误：不支持的证书格式，请配置.crt或.pem格式的证书文件！${NC}"
            continue
        fi

        certificate_path="$certificate_path_input" 
        break
    done

    while true; do
        read -p "请输入 PEM 私钥位置: " private_key_path_input

        if [[ ! -f "$private_key_path_input" ]]; then
            echo -e "${RED}错误：私钥文件不存在，请重新输入！${NC}"
            continue
        fi

        private_key_file=$(basename "$private_key_path_input")
        allowed_extensions=("key" "pem")
        if [[ ! "${allowed_extensions[@]}" =~ "${private_key_file##*.}" ]]; then
            echo -e "${RED}错误：不支持的私钥格式，请配置.key或.pem格式的私钥文件！${NC}"
            continue
        fi

        private_key_path="$private_key_path_input"  
        break
    done
}

function apply_certificate() {
    local domain="$1" 
    certificate_path="/etc/ssl/private/"$domain".crt"
    private_key_path="/etc/ssl/private/"$domain".key"
    local has_ipv4=false
    local ca_servers=("letsencrypt" "zerossl")
    local local_ip_v4=$(curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org || curl -s https://ifconfig.co/ip || curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" || curl -s icanhazip.com || curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")

    if [[ -n "$local_ip_v4" ]]; then
        has_ipv4=true
    fi
    
    echo "Requesting a certificate..."        
    curl -s https://get.acme.sh | sh -s email=example@gmail.com 2>&1 | tail -n 1
    alias acme.sh=~/.acme.sh/acme.sh
    
    for ca_server in "${ca_servers[@]}"; do
        echo "Requesting a certificate from $ca_server..."
        ~/.acme.sh/acme.sh --set-default-ca --server "$ca_server"

        if $has_ipv4; then
            result=$(~/.acme.sh/acme.sh --issue -d "$domain" --standalone 2>&1)
        else
            result=$(~/.acme.sh/acme.sh --issue -d "$domain" --standalone --listen-v6 2>&1)
        fi

        if [[ $result == *"log"* || $result == *"debug"* ]]; then
            echo -e "${RED}$result ${NC}"
        fi        

        if [[ $result == *"force"* ]]; then
            if $has_ipv4; then
                ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --force >/dev/null 2>&1
            else
                ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --force --listen-v6 >/dev/null 2>&1
            fi
        fi        

        if [[ $? -eq 0 ]]; then
            echo "Installing the certificate..."
            ~/.acme.sh/acme.sh --install-cert -d "$domain" --ecc --key-file "$private_key_path" --fullchain-file "$certificate_path"
            break 
        else
            echo -e "${RED}Failed to obtain a certificate from $ca_server！${NC}"
        fi
    done
}

function Reapply_certificates() {
    local tls_info_file="/usr/local/etc/sing-box/tls_info.json"
    local has_ipv4=false

    ipv4_address=$(curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org || curl -s https://ifconfig.co/ip || curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" || curl -s icanhazip.com || curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")

    if [ -n "$ipv4_address" ]; then
        has_ipv4=true
    fi
    if ! command -v acme.sh &>/dev/null; then
        curl -s https://get.acme.sh | sh -s email=example@gmail.com
    fi
    alias acme.sh=~/.acme.sh/acme.sh
    ca_servers=("letsencrypt" "zerossl")
    for ca_server in "${ca_servers[@]}"; do
        echo "Setting CA server to $ca_server..."
        ~/.acme.sh/acme.sh --set-default-ca --server "$ca_server"
        jq -c '.[]' "$tls_info_file" | while read -r tls_info; do
            server_name=$(echo "$tls_info" | jq -r '.server_name')
            key_path=$(echo "$tls_info" | jq -r '.key_path')
            certificate_path=$(echo "$tls_info" | jq -r '.certificate_path')
            echo "Requesting certificate for $server_name..."
            if $has_ipv4; then
                ~/.acme.sh/acme.sh --issue -d "$server_name" --standalone
            else
                ~/.acme.sh/acme.sh --issue -d "$server_name" --standalone --listen-v6
            fi
            ~/.acme.sh/acme.sh --install-cert -d "$server_name" --ecc --key-file "$key_path" --fullchain-file "$certificate_path"
            echo "Certificate for $server_name has been applied and installed using $ca_server CA."
        done
    done
    rm -f "$tls_info_file"
}

function generate_private_key() {
    while true; do
        read -p "请输入私钥 (默认随机生成私钥): " private_key

        if [[ -z "$private_key" ]]; then
            local keypair_output=$(sing-box generate reality-keypair)
            private_key=$(echo "$keypair_output" | awk -F: '/PrivateKey/{gsub(/ /, "", $2); print $2}')
            echo "$keypair_output" | awk -F: '/PublicKey/{gsub(/ /, "", $2); print $2}' > /tmp/public_key_temp.txt
            break
        fi

        if openssl pkey -inform PEM -noout -text -in <(echo "$private_key") >/dev/null 2>&1; then
            break
        else
            echo -e "${RED}无效的私钥，请重新输入！${NC}"
        fi
    done    
}

function choose_node_type() {
    while true; do
        read -p "请选择节点类型（默认1）：
1). Vmess+tcp
2). Vmess+ws
3). Vmess+grpc       
4). Vmess+tcp+tls
5). Vmess+ws+tls 
6). Vmess+h2+tls
7). Vmess+grpc+tls                      
请选择 [1-7]: " node_type
        if [ -z "$node_type" ]; then
            node_type="1"
        fi

        case $node_type in
            1)
                transport_removed=true
                tls_enabled=false
                break
                ;;
            2)
                transport_removed=false
                tls_enabled=false
                break
                ;;
            3)
                transport_removed=false
                tls_enabled=false
                break
                ;;
            4)
                transport_removed=true
                tls_enabled=true
                break
                ;; 
            5)
                transport_removed=false
                tls_enabled=true
                break
                ;; 
            6)
                transport_removed=false
                tls_enabled=true
                break
                ;;
            7)
                transport_removed=false
                tls_enabled=true
                break
                ;;                                                                               
            *)
                echo -e "${RED}无效的选择，请重新输入！${NC}"
                ;;
        esac
    done
}

function encryption_method() {
    while true; do
        read -p "请选择加密方式(默认1)：
1). 2022-blake3-chacha20-poly1305
2). 2022-blake3-aes-256-gcm
3). 2022-blake3-aes-128-gcm
4). xchacha20-ietf-poly1305
5). chacha20-ietf-poly1305
6). aes-256-gcm
7). aes-192-gcm
8). aes-128-gcm
请选择[1-8]: " encryption_choice
        encryption_choice=${encryption_choice:-1}

        case $encryption_choice in
            1)
                ss_method="2022-blake3-chacha20-poly1305"
                ss_password=$(sing-box generate rand --base64 32)
                shadowtls_password=$(openssl rand -base64 32)
                break
                ;;
            2)
                ss_method="2022-blake3-aes-256-gcm"
                ss_password=$(sing-box generate rand --base64 32)
                shadowtls_password=$(openssl rand -base64 32)
                break
                ;;                
            3)
                ss_method="2022-blake3-aes-128-gcm"
                ss_password=$(sing-box generate rand --base64 16)
                shadowtls_password=$(openssl rand -base64 16)
                break
                ;;

            4)
                ss_method="xchacha20-ietf-poly1305"
                ss_password=$(sing-box generate rand --base64 16)
                shadowtls_password=$(openssl rand -base64 16)
                break
                ;;
            5)
                ss_method="chacha20-ietf-poly1305"
                ss_password=$(sing-box generate rand --base64 16)
                shadowtls_password=$(openssl rand -base64 16)
                break
                ;;
            6)
                ss_method="aes-256-gcm"
                ss_password=$(sing-box generate rand --base64 16)
                shadowtls_password=$(openssl rand -base64 16)
                break
                ;;
            7)
                ss_method="aes-192-gcm"
                ss_password=$(sing-box generate rand --base64 16)
                shadowtls_password=$(openssl rand -base64 16)
                break
                ;;
            8)
                ss_method="aes-128-gcm"
                ss_password=$(sing-box generate rand --base64 16)
                shadowtls_password=$(openssl rand -base64 16)
                break
                ;;                                                                
            *)
                echo -e "${RED}错误：无效的选择，请重新输入！${NC}"
                ;;
        esac
    done
}

function select_unlocked_items() {
    while true; do
        read -p "请选择要解锁的项目（支持多选）：
1). ChatGPT
2). Netflix
3). Disney+
请选择[1-3]: " choices

        if [[ "$choices" =~ ^[123]+$ ]]; then
            selected=($(echo "$choices" | sed 's/./& /g'))
            break
        else
            echo -e "${RED}错误：无效的选择，请重新输入！${NC}"
        fi
    done
}

function update_geosite_array() {
    for choice in "${selected[@]}"; do
      case $choice in
        1)
          geosite+=("\"openai\"")
          ;;
        2)
          geosite+=("\"netflix\"")
          ;;
        3)
          geosite+=("\"disney\"")
          ;;
        *)
          echo -e "${RED}无效的选择: $choice${NC}"
          ;;
      esac
    done
}

function select_outbound() {
    while true; do
    read -p "请选择出站网络 (默认1)
1). warp-IPv4
2). warp-IPv6
请选择[1-2]: " outbound_choice
      case $outbound_choice in
        1|"")
          outbound="warp-IPv4-out"
          break
          ;;
        2)
          outbound="warp-IPv6-out"
          break
          ;;
        *)
          echo -e "${RED}错误：无效的选项，请重新输入！${NC}"
          ;;
      esac
    done
}

function set_congestion_control() {
    local default_congestion_control="bbr"

    while true; do
        read -p "请选择拥塞控制算法 (默认$default_congestion_control):
1). bbr
2). cubic
3). new_reno
请选择[1-3]: " congestion_control

        case $congestion_control in
            1)
                congestion_control="bbr"
                break
                ;;
            2)
                congestion_control="cubic"
                break
                ;;
            3)
                congestion_control="new_reno"
                break
                ;;
            "")
                congestion_control=$default_congestion_control
                break
                ;;
            *)
                echo -e "${RED}错误：无效的选择，请重新输入！${NC}"
                ;;
        esac
    done
}

function extract_certificate_and_key_paths() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local domain="$1"
    local found_certificate=false
    local found_key=false
    local cert_path
    local key_path

    if [[ ! -f "$config_file" ]]; then
        return 1
    fi

    if grep -q "$domain.crt" "$config_file"; then
        found_certificate=true
        cert_path=$(grep 'certificate_path' "$config_file" | grep "$domain.crt" | head -n 1 | awk -F'"' '{print $4}')
    fi

    if grep -q "$domain.key" "$config_file"; then
        found_key=true
        key_path=$(grep 'key_path' "$config_file" | grep "$domain.key" | head -n 1 | awk -F'"' '{print $4}')
    fi

    if [[ ! -f "$cert_path" ]]; then
        found_certificate=false
        return 2
    fi

    if [[ ! -f "$key_path" ]]; then
        found_key=false
        return 2
    fi

    certificate_path="$cert_path"
    private_key_path="$key_path"

    return 0
}

function ask_certificate_option() {
    local certificate_option
    while true; do
        read -p "请选择证书来源 (默认1)：
1). 自动申请证书
2). 自定义证书路径
3). 自动设置证书路径(仅适用于已使用本脚本申请过证书）
请选择[1-3]: " certificate_option
        certificate_option=${certificate_option:-1}

        case $certificate_option in
            1)
                echo "You have chosen to automatically request a certificate."
                check_firewall_configuration
                apply_certificate "$domain"
                break
                ;;
            2)
                echo "You have chosen to use your own certificate."
                check_firewall_configuration
                set_certificate_and_private_key
                break
                ;;
            3)
                echo "You have chosen to automatically configure the certificate."
                check_firewall_configuration
                extract_certificate_and_key_paths "$domain"
                if [[ $? -eq 2 ]]; then
                    echo -e "${RED}错误：未找到证书文件，请重新选择！${NC}"
                    continue
                fi
                break
                ;;            
            *)
                echo -e "${RED}错误：无效的选择，请重新输入！${NC}"
                ;;
        esac
    done
}

function select_flow_type() {
    while true; do
        read -p "请选择节点类型 (默认1)：
1). vless+vision+reality
2). vless+h2+reality
3). vless+grpc+reality
请选择[1-2]: " flow_option

        case $flow_option in
            "" | 1)
                flow_type="xtls-rprx-vision"
                transport_removed=true
                break
                ;;
            2)
                flow_type=""
                transport_removed=false
                break
                ;;
            3)
                flow_type=""
                transport_removed=false
                break
                ;;                
            *)
                echo -e "${RED}错误的选项，请重新输入！${NC}" >&2
                ;;
        esac
    done
}

function prompt_setup_type() {
    while true; do
        read -p "请选择节点类型（默认1）：
1). trojan+tcp+tls
2). trojan+ws+tls
3). trojan+H2C+tls       
4). trojan+gRPC+tls
请选择 [1-4]: " setup_type
        if [ -z "$setup_type" ]; then
            setup_type="1"
        fi

        case $setup_type in
            1)
                transport_removed=true
                break
                ;;
            2)
                transport_removed=false
                break
                ;;
            3)
                transport_removed=false
                break
                ;;
            4)
                transport_removed=false
                break
                ;;                                
            *)
                echo -e "${RED}无效的选择，请重新输入！${NC}"
                ;;
        esac
    done
}

function add_multiple_shadowtls_users() {
    local add_multiple_users="Y"
    
    while [[ $add_multiple_users == [Yy] ]]; do
        read -p "是否添加多用户？(Y/N，默认为N): " add_multiple_users

        if [[ $add_multiple_users == [Yy] ]]; then
            add_shadowtls_user
        fi
    done
}

function configure_short_ids() {
    local current_length=7 

    while true; do
        read -p "是否继续添加 short id？(Y/N，默认N): " choice
        choice=${choice,,}  
        
        if [[ "$choice" == "y" ]]; then
            set_short_id
            if [[ "$current_length" -ge 2 ]]; then
                current_length=$((current_length - 1))
                short_ids+=$',\n            "'$(openssl rand -hex "$current_length")'"'
            else
                break
            fi
        elif [[ "$choice" == "n" || -z "$choice" ]]; then
            break
        else
            echo -e "${RED}错误：请输入 'Y' 或 'N'！${NC}"
        fi
    done
    short_ids=${short_ids%,}
}

function tuic_multiple_users() {
    users="[
        {
          \"name\": \"$username\",
          \"uuid\": \"$uuid\",
          \"password\": \"$password\"
        }"

    while true; do
        read -p "是否继续添加用户？(Y/N，默认N): " -e add_multiple_users

        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi

        if [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            set_username
            set_password
            generate_uuid
            users+=",
        {
          \"name\": \"$username\",
          \"uuid\": \"$uuid\",
          \"password\": \"$password\"
        }"
        elif [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            break
        else
            echo -e "${RED}无效的输入，请重新输入！${NC}"
        fi
    done

    users+=$'\n      ]'
}

function naive_multiple_users() {
    users="[
        {
          \"username\": \"$username\",
          \"password\": \"$password\"
        }"

    while true; do
        read -p "是否继续添加用户？(Y/N，默认N): " -e add_multiple_users

        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi

        if [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            set_username
            set_password
            users+=",
        {
          \"username\": \"$username\",
          \"password\": \"$password\"
        }"
        elif [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            break
        else
            echo -e "${RED}无效的输入，请重新输入！${NC}"
        fi
    done

    users+=$'\n      ]'
}

function vmess_multiple_users() {
    users="[
        {
          \"uuid\": \"$uuid\",
          \"alterId\": 0
        }"

    while true; do
        read -p "是否继续添加用户？(Y/N，默认N): " -e add_multiple_users

        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi

        if [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            generate_uuid
            users+=",
        {
          \"uuid\": \"$uuid\",
          \"alterId\": 0
        }"
        elif [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            break
        else
            echo -e "${RED}无效的输入，请重新输入！${NC}"
        fi
    done

    users+=$'\n      ]'
}

function socks_multiple_users() {
    users="[
        {
          \"username\": \"$username\",
          \"password\": \"$password\"
        }"

    while true; do
        read -p "是否继续添加用户？(Y/N，默认N): " -e add_multiple_users

        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi

        if [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            set_username
            set_password
            users+=",
        {
          \"username\": \"$username\",
          \"password\": \"$password\"
        }"
        elif [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            break
        else
            echo -e "${RED}无效的输入，请重新输入！${NC}"
        fi
    done

    users+=$'\n      ]'
}

function hysteria_multiple_users() {
    users="[
        {
          \"name\": \"$username\",
          \"auth_str\": \"$password\"
        }"

    while true; do
        read -p "是否继续添加用户？(Y/N，默认N): " -e add_multiple_users

        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi

        if [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            set_username
            set_password
            users+=",
        {
          \"name\": \"$username\",
          \"auth_str\": \"$password\"
        }"
        elif [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            break
        else
            echo -e "${RED}无效的输入，请重新输入！${NC}"
        fi
    done

    users+=$'\n      ]'
}

function hy2_multiple_users() {
    users="[
        {
          \"name\": \"$username\",
          \"password\": \"$password\"
        }"

    while true; do
        read -p "是否继续添加用户？(Y/N，默认N): " -e add_multiple_users

        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi

        if [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            set_username
            set_password
            users+=",
        {
          \"name\": \"$username\",
          \"password\": \"$password\"
        }"
        elif [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            break
        else
            echo -e "${RED}无效的输入，请重新输入！${NC}"
        fi
    done

    users+=$'\n      ]'
}

function add_shadowtls_user() {
    local user_password=""
    if [[ $encryption_choice == 1 || $encryption_choice == 2 ]]; then
        user_password=$(openssl rand -base64 32)
    elif [[ $encryption_choice == 3 || $encryption_choice == 4 || $encryption_choice == 5 || $encryption_choice == 6 || $encryption_choice == 7 || $encryption_choice == 8 ]]; then
        user_password=$(openssl rand -base64 16)
    fi

    local new_user=$(set_username)
    new_user=${new_user##*: }

    if [[ -n "$users" ]]; then
        users+=","
    fi

    users+="
        {
          \"name\": \"$new_user\",
          \"password\": \"$user_password\"
        }"

    echo "用户名: $new_user"
    echo "ShadowTLS 密码: $user_password"
}

function trojan_multiple_users() {
    users="[
        {
          \"password\": \"$password\"
        }"

    while true; do
        read -p "是否继续添加用户？(Y/N，默认N): " -e add_multiple_users

        if [[ -z "$add_multiple_users" ]]; then
            add_multiple_users="N"
        fi

        if [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then
            set_password
            users+=",
        {
          \"password\": \"$password\"
        }"
        elif [[ "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            break
        else
            echo -e "${RED}无效的输入，请重新输入！${NC}"
        fi
    done

    users+=$'\n      ]'
}

function generate_vmess_transport_config() {    
    if [[ $node_type == 2 || $node_type == 5 ]]; then
        read -p "请输入 ws 路径 (默认随机生成): " transport_path_input
        transport_path=${transport_path_input:-/$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)}
        if [[ ! "$transport_path" =~ ^/ ]]; then
            transport_path="/$transport_path"
        fi
        transport_config="
      \"transport\": {
        \"type\": \"ws\",
        \"path\": \"$transport_path\",
        \"max_early_data\": 2048,
        \"early_data_header_name\": \"Sec-WebSocket-Protocol\"
      },"
    elif [[ $node_type == 1 || $node_type == 4  ]]; then
        transport_config=""
    elif [[ $node_type == 3 || $node_type == 7 ]]; then
        service_name=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)
        transport_config="
      \"transport\": {
        \"type\": \"grpc\",
        \"service_name\": \"$service_name\"
      },"
    elif [[ $node_type == 6 ]]; then
        transport_config="
      \"transport\": {
        \"type\": \"http\"
      },"
    fi
}

function prompt_and_generate_transport_config() {    
    if [[ $setup_type == 2 ]]; then
        read -p "请输入 ws 路径 (默认随机生成): " transport_path_input
        transport_path=${transport_path_input:-/$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)}
        if [[ ! "$transport_path" =~ ^/ ]]; then
            transport_path="/$transport_path"
        fi
        transport_config="
      \"transport\": {
        \"type\": \"ws\",
        \"path\": \"$transport_path\",
        \"max_early_data\": 2048,
        \"early_data_header_name\": \"Sec-WebSocket-Protocol\"
      },"
    elif [[ $setup_type == 1 ]]; then
        transport_config=""
    elif [[ $setup_type == 3 ]]; then
        transport_config="
      \"transport\": {
        \"type\": \"http\"
      },"
    elif [[ $setup_type == 4 ]]; then
        service_name=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)
        transport_config="
      \"transport\": {
        \"type\": \"grpc\",
        \"service_name\": \"$service_name\"
      },"
    fi
}

function generate_vless_transport_config() {    
    if [[ $flow_option == 1 ]]; then
        transport_config=""
    elif [[ $flow_option == 2 ]]; then
        transport_config="
      \"transport\": {
        \"type\": \"http\"
      },"
    elif [[ $flow_option == 3 ]]; then
        service_name=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)
        transport_config="
      \"transport\": {
        \"type\": \"grpc\",
        \"service_name\": \"$service_name\"
      },"
    fi
}

function generate_tls_config() {    
    if [ "$node_type" -ge 4 ] && [ "$node_type" -le 7 ]; then
        tls_enabled=true
        get_domain
        ask_certificate_option                
    else
        tls_enabled=false
    fi

    if [ "$tls_enabled" = true ]; then
        tls_config=",
      \"tls\": {
        \"enabled\": true,
        \"server_name\": \"$domain\",
        \"certificate_path\": \"$certificate_path\",
        \"key_path\": \"$private_key_path\"
      }"
    else
        tls_config=""
    fi
}

function extract_tls_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    jq '[.inbounds[].tls | {server_name: .server_name, certificate_path: .certificate_path, key_path: .key_path}]' "$config_file" > /usr/local/etc/sing-box/tls_info.json
}

function extract_variables_and_cleanup() {
    server=$(jq -r '.server' "$temp_file")
    server_port=$(jq -r '.server_port' "$temp_file")
    local_address_ipv4=$(jq -r '.local_address[0]' "$temp_file")
    local_address_ipv6=$(jq -r '.local_address[1]' "$temp_file")
    private_key=$(jq -r '.private_key' "$temp_file")
    peer_public_key=$(jq -r '.peer_public_key' "$temp_file")
    reserved=$(jq -c '.reserved' "$temp_file")
    mtu=$(jq -r '.mtu' "$temp_file")
    rm "$temp_file"
}

function log_outbound_config() {
  local config_file="/usr/local/etc/sing-box/config.json"
  if ! grep -q '"log": {' "$config_file" || ! grep -q '"route": {' "$config_file"  || ! grep -q '"inbounds": \[' "$config_file" || ! grep -q '"outbounds": \[' "$config_file"; then
    echo -e '{\n  "log": {\n  },\n  "route": {\n  },\n  "inbounds": [\n  ],\n  "outbounds": [\n  ]\n}' > "$config_file"
    sed -i '/"log": {/!b;n;c\    "disabled": false,\n    "level": "info",\n    "timestamp": true\n  },' "$config_file"
    sed -i '/"route": {/!b;n;c\    "rules": [\n    ]\n  },' "$config_file"
    sed -i '/"outbounds": \[/!b;n;c\    {\n      "type": "direct",\n      "tag": "direct"\n    }\n  ]' "$config_file"
  fi
}

function modify_format_inbounds_and_outbounds() {
    file_path="/usr/local/etc/sing-box/config.json"
    start_line_inbounds=$(grep -n '"inbounds": \[' "$file_path" | cut -d: -f1)
    start_line_outbounds=$(grep -n '"outbounds": \[' "$file_path" | cut -d: -f1)

    if [ -n "$start_line_inbounds" ]; then
        line_to_modify_inbounds=$((start_line_inbounds - 3))
        if [ "$line_to_modify_inbounds" -ge 1 ]; then
            sed -i "$line_to_modify_inbounds s/,//" "$file_path"
        fi
    fi

    if [ -n "$start_line_outbounds" ]; then
        line_to_modify_outbounds_1=$((start_line_outbounds - 2))
        line_to_modify_outbounds_2=$((start_line_outbounds - 1))

        if [ "$line_to_modify_outbounds_1" -ge 1 ]; then
            sed -i "$line_to_modify_outbounds_1 s/.*/    }/" "$file_path"
            sed -i "$line_to_modify_outbounds_2 s/.*/  ],/" "$file_path"
        fi
    fi
}

function generate_Direct_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v target_address="$target_address" -v override_port="$override_port" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"direct\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"sniff_timeout\": \"300ms\","; print "      \"proxy_protocol\": false,"; print "      \"override_address\": \"" target_address "\","; print "      \"override_port\": " override_port; print "    },"; found_inbounds=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_ss_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v ss_method="$ss_method" -v ss_password="$ss_password" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"method\": \"" ss_method "\","; print "      \"password\": \"" ss_password "\""; print "    },"; found_inbounds=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_vmess_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    choose_node_type  
    listen_port
    generate_uuid
    vmess_multiple_users     
    generate_vmess_transport_config
    generate_tls_config
    local cert_path="$certificate_path"
    local key_path="$private_key_path" 
    check_firewall_configuration
    local found_rules=0
    local found_inbounds=0              
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" -v transport_config="$transport_config" -v tls_config="$tls_config" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"vmess\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true," transport_config ""; print "      \"users\": " users "" tls_config ""; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
} 

function generate_socks_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag
    listen_port
    set_username
    set_password    
    socks_multiple_users    
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"socks\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"users\": " users ""; print "    },"; found_inbounds=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_naive_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag      
    listen_port
    set_username
    set_password    
    naive_multiple_users
    get_domain    
    ask_certificate_option
    local cert_path="$certificate_path"
    local key_path="$private_key_path"  
    local found_rules=0
    local found_inbounds=0    
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" -v domain="$domain" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"naive\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"users\": " users ","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" domain "\","; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\""; print "      }"; print "    },"; found_inbounds=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_tuic_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag  
    listen_port
    set_username
    set_password
    generate_uuid
    tuic_multiple_users    
    set_congestion_control
    get_domain
    ask_certificate_option
    local cert_path="$certificate_path"
    local key_path="$private_key_path"   
    local found_rules=0
    local found_inbounds=0    
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" -v congestion_control="$congestion_control" -v domain="$domain" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"tuic\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"users\": " users ","; print "      \"congestion_control\": \"" congestion_control "\","; print "      \"auth_timeout\": \"3s\","; print "      \"zero_rtt_handshake\": false,"; print "      \"heartbeat\": \"10s\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" domain "\","; print "        \"alpn\": ["; print "          \"h3\""; print "        ],"; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\""; print "      }"; print "    },"; found_inbounds=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_Hysteria_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag    
    listen_port
    read_up_speed
    read_down_speed
    set_username
    set_password    
    hysteria_multiple_users 
    get_domain   
    ask_certificate_option
    local cert_path="$certificate_path"
    local key_path="$private_key_path"
    local found_rules=0
    local found_inbounds=0   
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v users="$users" -v domain="$domain" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"hysteria\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"up_mbps\": " up_mbps ","; print "      \"down_mbps\": " down_mbps ","; print "      \"users\": " users ","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" domain "\","; print "        \"alpn\": ["; print "          \"h3\""; print "        ],"; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\""; print "      }"; print "    },"; found_inbounds=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_shadowtls_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local users=""
    local tag_label
    generate_unique_tag
    tag_label1="$tag_label" 
    generate_unique_tag
    tag_label2="$tag_label"  
    listen_port
    encryption_method
    add_shadowtls_user
    add_multiple_shadowtls_users
    generate_target_server
    local found_rules=0
    local found_inbounds=0
    awk -v tag_label1="$tag_label1" -v tag_label2="$tag_label2" -v listen_port="$listen_port" -v users="$users" -v target_server="$target_server" -v ss_method="$ss_method" -v ss_password="$ss_password" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label1 "\"],"; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"shadowtls\","; print "      \"tag\": \"" tag_label1 "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"version\": 3,"; print "      \"users\": [" users ""; print "      ],"; print "      \"handshake\": {"; print "        \"server\": \"" target_server "\","; print "        \"server_port\": 443"; print "      },"; print "      \"strict_mode\": true,"; print "      \"detour\": \"" tag_label2 "\""; print "    },"; print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" tag_label2 "\","; print "      \"listen\": \"127.0.0.1\","; print "      \"network\": \"tcp\","; print "      \"method\": \"" ss_method "\","; print "      \"password\": \"" ss_password "\""; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_juicity_config() {
    local config_file="/usr/local/etc/juicity/config.json"
    local users="" 
    listen_port
    generate_uuid
    set_password
    users="\"$uuid\": \"$password\""
    set_congestion_control
    get_domain 
    ask_certificate_option
    local cert_path="$certificate_path"
    local key_path="$private_key_path"

    echo "{
    \"listen\": \":$listen_port\",
    \"users\": {
$users
    },
    \"certificate\": \"$certificate_path\",
    \"private_key\": \"$private_key_path\",
    \"congestion_control\": \"$congestion_control\",
    \"log_level\": \"info\"
}" > "$config_file"
}

function generate_reality_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag    
    select_flow_type 
    listen_port   
    generate_uuid
    generate_server_name
    generate_target_server
    generate_private_key
    set_short_id
    configure_short_ids
    generate_vless_transport_config    
    local found_rules=0
    local found_inbounds=0    
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v uuid="$uuid" -v flow_type="$flow_type" -v transport_config="$transport_config" -v server_name="$server_name" -v target_server="$target_server" -v private_key="$private_key" -v short_id="$short_id" -v short_ids="$short_ids" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"vless\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"users\": ["; print "        {"; print "          \"uuid\": \"" uuid "\","; print "          \"flow\": \"" flow_type "\""; print "        }"; print "      ], " transport_config; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\","; print "        \"reality\": {"; print "          \"enabled\": true,"; print "          \"handshake\": {"; print "            \"server\": \"" target_server "\","; print "            \"server_port\": 443"; print "          },"; print "          \"private_key\": \"" private_key "\","; print "          \"short_id\": ["; print "            \"" short_id "\"" short_ids; print "          ]"; print "        }"; print "      }"; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_Hy2_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local tag_label
    generate_unique_tag      
    listen_port
    read_up_speed
    read_down_speed
    set_username
    set_password    
    hy2_multiple_users
    get_fake_domain
    get_domain   
    ask_certificate_option
    local cert_path="$certificate_path"
    local key_path="$private_key_path"
    local found_rules=0
    local found_inbounds=0      
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v users="$users" -v fake_domain="$fake_domain" -v domain="$domain" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"hysteria2\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"up_mbps\": " up_mbps ","; print "      \"down_mbps\": " down_mbps ","; print "      \"users\": " users ","; print "      "; print "      \"ignore_client_bandwidth\": false,"; print "      \"masquerade\": \"https://" fake_domain "\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" domain "\","; print "        \"alpn\": ["; print "          \"h3\""; print "        ],"; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\""; print "      }"; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_trojan_config() {
    local config_file="/usr/local/etc/sing-box/config.json"    
    local tag_label
    generate_unique_tag
    prompt_setup_type  
    listen_port
    set_password
    trojan_multiple_users
    prompt_and_generate_transport_config         
    get_domain 
    ask_certificate_option
    local cert_path="$certificate_path"
    local key_path="$private_key_path"   
    local found_rules=0
    local found_inbounds=0              
    awk -v tag_label="$tag_label" -v listen_port="$listen_port" -v users="$users" -v domain="$domain" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" -v transport_config="$transport_config" '
        /"rules": \[/{found_rules=1}
        /"inbounds": \[/{found_inbounds=1}
        {print}
        found_rules && /"rules": \[/{print "      {"; print "        \"inbound\": [\"" tag_label "\"],"; print "        \"outbound\": \"direct\""; print "      },"; found_rules=0}
        found_inbounds && /"inbounds": \[/{print "    {"; print "      \"type\": \"trojan\","; print "      \"tag\": \"" tag_label "\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true," transport_config ""; print "      \"users\": " users ","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" domain "\","; print "        \"alpn\": ["; print "          \"h2\","; print "          \"http/1.1\""; print "        ],"; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\""; print "      }"; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
} 
  
function update_route_file() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local geosite_list=$(IFS=,; echo "${geosite[*]}") 
    local geosite_formatted=$(sed 's/,/,\\n          /g' <<< "$geosite_list") 

    sed -i '/"rules": \[/!b;a\
      {\
        "geosite": [\
          '"$geosite_formatted"'\
        ],\
        "outbound": "'"$1"'"\
      },' "$config_file"
}

function update_outbound_file() {
    local config_file="/usr/local/etc/sing-box/config.json"
    awk -v server="$server" -v server_port="$server_port" -v local_address_ipv4="$local_address_ipv4" -v local_address_ipv6="$local_address_ipv6" -v private_key="$private_key" -v peer_public_key="$peer_public_key" -v reserved="$reserved" -v mtu="$mtu" '
        {
            if ($0 ~ /"outbounds": \[/) {
                print $0
                for (i=1; i<=4; i++) {
                    getline
                    if (i == 4) {
                        print "" $0 ","
                    } else {
                        print $0
                    }
                }
                print "    {"; print "      \"type\": \"direct\","; print "      \"tag\": \"warp-IPv4-out\","; print "      \"detour\": \"wireguard-out\","; print "      \"domain_strategy\": \"ipv4_only\""; print "    },"; print "    {"; print "      \"type\": \"direct\","; print "      \"tag\": \"warp-IPv6-out\","; print "      \"detour\": \"wireguard-out\","; print "      \"domain_strategy\": \"ipv6_only\""; print "    },"; print "    {"; print "      \"type\": \"wireguard\","; print "      \"tag\": \"wireguard-out\","; print "      \"server\": \"" server "\","; print "      \"server_port\": " server_port ","; print "      \"system_interface\": false,"; print "      \"interface_name\": \"wg0\","; print "      \"local_address\": ["; print "        \"" local_address_ipv4 "\","; print "        \"" local_address_ipv6 "\"" ; print "      ],"; print "      \"private_key\": \"" private_key "\","; print "      \"peer_public_key\": \"" peer_public_key "\","; print "      \"reserved\": " reserved ","; print "      \"mtu\": " mtu; print "    }"
            } else {
                print $0
            }
        }
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
    echo "warp配置完成。"
}

function write_phone_client_file() {
  local dir="/usr/local/etc/sing-box"
  local phone_client="${dir}/phone_client.json"
  if [ ! -s "${phone_client}" ]; then
    awk 'BEGIN { print "{"; print "  \"log\": {"; print "    \"disabled\": false,  "; print "    \"level\": \"warn\","; print "    \"timestamp\": true"; print "  },"; print "  \"dns\": {"; print "    \"servers\": ["; print "      {"; print "        \"tag\": \"google\","; print "        \"address\": \"https://1.1.1.1/dns-query\","; print "        \"address_resolver\": \"local\","; print "        \"detour\": \"auto\""; print "      },"; print "      {"; print "        \"tag\": \"local\","; print "        \"address\": \"https://223.5.5.5/dns-query\","; print "        \"detour\": \"direct\""; print "      },"; print "      {"; print "        \"tag\": \"block\","; print "        \"address\": \"rcode://success\""; print "      }"; print "    ],"; print "    \"rules\": ["; print "      {"; print "        \"geosite\": \"category-ads-all\","; print "        \"server\": \"block\","; print "        \"disable_cache\": true"; print "      },"; print "      {"; print "        \"geosite\": \"cn\","; print "        \"source_geoip\": ["; print "          \"cn\","; print "          \"private\""; print "        ],"; print "        \"server\": \"local\""; print "      },"; print "      {"; print "        \"outbound\": \"any\","; print "        \"server\": \"local\""; print "      }"; print "    ],"; print "    \"strategy\": \"ipv4_only\""; print "  },"; print "  \"route\": {"; print "    \"rules\": ["; print "      {"; print "        \"protocol\": \"dns\","; print "        \"outbound\": \"dns-out\""; print "      },"; print "      {"; print "        \"geosite\": \"category-ads-all\","; print "        \"outbound\": \"block\""; print "      },"; print "      {"; print "        \"geosite\": \"cn\","; print "        \"geoip\": ["; print "          \"cn\","; print "          \"private\""; print "        ],"; print "        \"outbound\": \"direct\""; print "      }"; print "    ],"; print "    \"auto_detect_interface\": true"; print "  },"; print "  \"inbounds\": ["; print "    {"; print "      \"type\": \"tun\","; print "      \"tag\": \"tun-in\","; print "      \"inet4_address\": \"172.19.0.1/30\","; print "      \"inet6_address\": \"fdfe:dcba:9876::1/126\","; print "      \"mtu\": 9000,"; print "      \"auto_route\": true,"; print "      \"strict_route\": true,"; print "      \"stack\": \"gvisor\","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": false"; print "    }"; print "  ],"; print "  \"outbounds\": ["; print "    {"; print "      \"type\": \"urltest\","; print "      \"tag\": \"auto\","; print "      \"outbounds\": ["; print "      ],"; print "      \"url\": \"https://www.gstatic.com/generate_204\","; print "      \"interval\": \"1m\","; print "      \"tolerance\": 50,"; print "      \"interrupt_exist_connections\": false"; print "    },"; print "    {"; print "      \"type\": \"selector\","; print "      \"tag\": \"select\","; print "      \"outbounds\": ["; print "        \"auto\""; print "      ],"; print "      \"default\": \"auto\","; print "      \"interrupt_exist_connections\": false"; print "    },"; print "    {"; print "      \"type\": \"direct\","; print "      \"tag\": \"direct\""; print "    },"; print "    {"; print "      \"type\": \"block\","; print "      \"tag\": \"block\""; print "    },"; print "    {"; print "      \"type\": \"dns\","; print "      \"tag\": \"dns-out\""; print "    }"; print "  ]"; print "}" }' > "${phone_client}"
  fi    
}

function write_win_client_file() {
  local dir="/usr/local/etc/sing-box"
  local win_client="${dir}/win_client.json"
  if [ ! -s "${win_client}" ]; then
    awk 'BEGIN { print "{"; print "  \"log\": {"; print "    \"disabled\": false,  "; print "    \"level\": \"warn\","; print "    \"timestamp\": true"; print "  },"; print "  \"dns\": {"; print "    \"servers\": ["; print "      {"; print "        \"tag\": \"google\","; print "        \"address\": \"https://1.1.1.1/dns-query\","; print "        \"address_resolver\": \"local\","; print "        \"detour\": \"auto\""; print "      },"; print "      {"; print "        \"tag\": \"local\","; print "        \"address\": \"https://223.5.5.5/dns-query\","; print "        \"detour\": \"direct\""; print "      },"; print "      {"; print "        \"tag\": \"block\","; print "        \"address\": \"rcode://success\""; print "      }"; print "    ],"; print "    \"rules\": ["; print "      {"; print "        \"geosite\": \"category-ads-all\","; print "        \"server\": \"block\","; print "        \"disable_cache\": true"; print "      },"; print "      {"; print "        \"geosite\": \"cn\","; print "        \"source_geoip\": ["; print "          \"cn\","; print "          \"private\""; print "        ],"; print "        \"server\": \"local\""; print "      },"; print "      {"; print "        \"outbound\": \"any\","; print "        \"server\": \"local\""; print "      }"; print "    ],"; print "    \"strategy\": \"ipv4_only\""; print "  },"; print "  \"route\": {"; print "    \"rules\": ["; print "      {"; print "        \"protocol\": \"dns\","; print "        \"outbound\": \"dns-out\""; print "      },"; print "      {"; print "        \"geosite\": \"category-ads-all\","; print "        \"outbound\": \"block\""; print "      },"; print "      {"; print "        \"geosite\": \"cn\","; print "        \"geoip\": ["; print "          \"cn\","; print "          \"private\""; print "        ],"; print "        \"outbound\": \"direct\""; print "      }"; print "    ],"; print "    \"auto_detect_interface\": true"; print "  },"; print "  \"inbounds\": ["; print "    {"; print "      \"type\": \"mixed\","; print "      \"tag\": \"mixed-in\","; print "      \"listen\": \"::\","; print "      \"listen_port\": 1080,"; print "      \"sniff\": true,"; print "      \"set_system_proxy\": false"; print "    }"; print "  ],"; print "  \"outbounds\": ["; print "    {"; print "      \"type\": \"urltest\","; print "      \"tag\": \"auto\","; print "      \"outbounds\": ["; print "      ],"; print "      \"url\": \"https://www.gstatic.com/generate_204\","; print "      \"interval\": \"1m\","; print "      \"tolerance\": 50,"; print "      \"interrupt_exist_connections\": false"; print "    },"; print "    {"; print "      \"type\": \"selector\","; print "      \"tag\": \"select\","; print "      \"outbounds\": ["; print "        \"auto\""; print "      ],"; print "      \"default\": \"auto\","; print "      \"interrupt_exist_connections\": false"; print "    },"; print "    {"; print "      \"type\": \"direct\","; print "      \"tag\": \"direct\""; print "    },"; print "    {"; print "      \"type\": \"block\","; print "      \"tag\": \"block\""; print "    },"; print "    {"; print "      \"type\": \"dns\","; print "      \"tag\": \"dns-out\""; print "    }"; print "  ]"; print "}" }' > "${win_client}"
  fi    
}

function write_clash_yaml() {
  local dir="/usr/local/etc/sing-box"
  local clash_yaml="${dir}/clash.yaml"
  local api_pass=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 16) 
  if [ ! -s "${clash_yaml}" ]; then
    awk -v api_pass="$api_pass" 'BEGIN { print "mixed-port: 10801"; print "redir-port: 7892"; print "tproxy-port: 7893"; print "allow-lan: true"; print "bind-address: \"*\""; print "find-process-mode: strict"; print "mode: rule"; print "geox-url:"; print "  geoip: \"https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat\""; print "  geosite: \"https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat\""; print "  mmdb: \"https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb\""; print "log-level: debug"; print "ipv6: true"; print "external-controller: 0.0.0.0:9093"; print "secret: \"" api_pass "\""; print "tcp-concurrent: true"; print "interface-name: en0"; print "global-client-fingerprint: chrome"; print "profile:"; print "  store-selected: false"; print "  store-fake-ip: true"; print "tun:"; print "  enable: true"; print "  stack: system"; print "  dns-hijack:"; print "    - 0.0.0.0:53"; print "  auto-detect-interface: true"; print "  auto-route: false"; print "  mtu: 9000"; print "  strict-route: true"; print "ebpf:"; print "  auto-redir:"; print "    - eth0"; print "  redirect-to-tun:"; print "    - eth0"; print "sniffer:"; print "  enable: true"; print "  override-destination: false"; print "  sniff:"; print "    TLS:"; print "      ports: [443, 8443]"; print "    HTTP:"; print "      ports: [80, 8080-8880]"; print "      override-destination: true"; print "  force-domain:"; print "    - +.v2ex.com"; print "tunnels:"; print "  - tcp/udp,127.0.0.1:6553,114.114.114.114:53,Proxy"; print "  - network: [tcp, udp]"; print "    address: 127.0.0.1:7777"; print "    target: target.com"; print "    proxy: Proxy"; print "dns:"; print "  enable: true"; print "  prefer-h3: true"; print "  listen: 0.0.0.0:53"; print "  ipv6: true"; print "  ipv6-timeout: 300"; print "  default-nameserver:"; print "    - 114.114.114.114"; print "    - 8.8.8.8"; print "    - tls://1.12.12.12:853"; print "    - tls://223.5.5.5:853"; print "    - system"; print "  enhanced-mode: fake-ip"; print "  fake-ip-range: 198.18.0.1/16"; print "  nameserver:"; print "    - https://dns.alidns.com/dns-query"; print "    - https://223.5.5.5/dns-query"; print "    - https://doh.pub/dns-query"; print "    - https://dns.alidns.com/dns-query#h3=true"; print "    - quic://dns.adguard.com:784"; print "  fallback:"; print "    - tls://dns.google"; print "    - https://1.1.1.1/dns-query"; print "    - https://cloudflare-dns.com/dns-query"; print "    - https://dns.google/dns-query"; print "  fallback-filter:"; print "    geoip: true"; print "    geoip-code: CN"; print "    geosite:"; print "      - gfw"; print "    ipcidr:"; print "      - 240.0.0.0/4"; print "    domain:"; print "      - \"+.google.com\""; print "      - \"+.facebook.com\""; print "      - \"+.youtube.com\""; print "  nameserver-policy:"; print "    \"geosite:cn,private,apple\":"; print "      - https://doh.pub/dns-query"; print "      - https://dns.alidns.com/dns-query"; print "    \"geosite:category-ads-all\": rcode://success"; print "    \"www.baidu.com,+.google.cn\": [223.5.5.5, https://dns.alidns.com/dns-query]"; print "proxies:"; print "proxy-groups:"; print "  - name: Proxy"; print "    type: select"; print "    proxies:"; print "      - auto"; print "  - name: auto"; print "    type: url-test"; print "    proxies:"; print "    url: \"https://cp.cloudflare.com/generate_204\""; print "    interval: 300"; print "rule-providers:"; print "  reject:"; print "    type: http"; print "    behavior: domain"; print "    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt\""; print "    path: ./ruleset/reject.yaml"; print "    interval: 86400"; print "  icloud:"; print "    type: http"; print "    behavior: domain"; print "    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt\""; print "    path: ./ruleset/icloud.yaml"; print "    interval: 86400"; print "  apple:"; print "    type: http"; print "    behavior: domain"; print "    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt\""; print "    path: ./ruleset/apple.yaml"; print "    interval: 86400"; print "  direct:"; print "    type: http"; print "    behavior: domain"; print "    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt\""; print "    path: ./ruleset/direct.yaml"; print "    interval: 86400"; print "  private:"; print "    type: http"; print "    behavior: domain"; print "    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt\""; print "    path: ./ruleset/private.yaml"; print "    interval: 86400"; print "  gfw:"; print "    type: http"; print "    behavior: domain"; print "    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt\""; print "    path: ./ruleset/gfw.yaml"; print "    interval: 86400"; print "  tld-not-cn:"; print "    type: http"; print "    behavior: domain"; print "    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt\""; print "    path: ./ruleset/tld-not-cn.yaml"; print "    interval: 86400"; print "  cncidr:"; print "    type: http"; print "    behavior: ipcidr"; print "    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt\""; print "    path: ./ruleset/cncidr.yaml"; print "    interval: 86400"; print "  lancidr:"; print "    type: http"; print "    behavior: ipcidr"; print "    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt\""; print "    path: ./ruleset/lancidr.yaml"; print "    interval: 86400"; print "  applications:"; print "    type: http"; print "    behavior: classical"; print "    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt\""; print "    path: ./ruleset/applications.yaml"; print "    interval: 86400"; print "rules:"; print "  - RULE-SET,applications,DIRECT"; print "  - DOMAIN,clash.razord.top,DIRECT"; print "  - DOMAIN,yacd.haishan.me,DIRECT"; print "  - DOMAIN-SUFFIX,services.googleapis.cn,DIRECT"; print "  - DOMAIN-SUFFIX,xn--ngstr-lra8j.com,DIRECT"; print "  - RULE-SET,private,DIRECT"; print "  - RULE-SET,reject,REJECT"; print "  - RULE-SET,icloud,DIRECT"; print "  - RULE-SET,apple,DIRECT"; print "  - RULE-SET,direct,DIRECT"; print "  - RULE-SET,lancidr,DIRECT"; print "  - RULE-SET,cncidr,DIRECT"; print "  - GEOIP,LAN,DIRECT"; print "  - GEOIP,CN,DIRECT"; print "  - MATCH,Proxy"; }' > "${clash_yaml}"
    sed -i'' -e '/^      - "+\.google\.com"/s/"/'\''/g' "${clash_yaml}"
    sed -i'' -e '/^      - "+\.facebook\.com"/s/"/'\''/g' "${clash_yaml}"
    sed -i'' -e '/^      - "+\.youtube\.com"/s/"/'\''/g' "${clash_yaml}" 
  fi
}

function write_naive_client_file() {
    local naive_client_file="$naive_client_filename"
    awk -v naive_client_file="$naive_client_file" 'BEGIN { print "{"; print "  \"listen\":  \"socks://127.0.0.1:1080\","; print "  \"proxy\": \"https://username:password@server_name:listen_port\""; print "}" }' > "$naive_client_file"
}

function generate_shadowsocks_win_client_config() {
  local win_client_file="/usr/local/etc/sing-box/win_client.json"
  local proxy_name
  
  while true; do
    proxy_name="socks-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$win_client_file"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v ss_method="$ss_method" -v ss_password="$ss_password" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"method\": \"" ss_method "\", "; print "      \"password\": \"" ss_password "\", "; print "      \"multiplex\": {"; print "        \"enabled\": true,"; print "        \"protocol\": \"smux\","; print "        \"max_connections\": 4,"; print "        \"min_streams\": 4,"; print "        \"max_streams\": 0"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" > "$win_client_file.tmp"
  mv "$win_client_file.tmp" "$win_client_file"
}

function generate_shadowsocks_phone_client_config() {
  local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
  local proxy_name
  
  while true; do
    proxy_name="ss-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$phone_client_file"; then
      break
    fi
  done 
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v ss_method="$ss_method" -v ss_password="$ss_password" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"method\": \"" ss_method "\", "; print "      \"password\": \"" ss_password "\", "; print "      \"multiplex\": {"; print "        \"enabled\": true,"; print "        \"protocol\": \"smux\","; print "        \"max_connections\": 4,"; print "        \"min_streams\": 4,"; print "        \"max_streams\": 0"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" > "$phone_client_file.tmp"
  mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_shadowsocks_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="ss-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
      if ! grep -q "name: $proxy_name" "$filename"; then
        break
      fi
  done
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v ss_method="$ss_method" -v ss_password="$ss_password" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: ss"; print "    server:", local_ip; print "    port:", listen_port; print "    cipher:", ss_method; print "    password:", "\"" ss_password "\""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_tuic_phone_client_config() {
  local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
  local proxy_name
  
  while true; do
    proxy_name="tuic-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$phone_client_file"; then
      break
    fi
  done 
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" -v password="$password" -v congestion_control="$congestion_control" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"tuic\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_name "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" uuid "\", "; print "      \"password\": \"" password "\", "; print "      \"congestion_control\": \""congestion_control"\","; print "      \"udp_relay_mode\": \"native\","; print "      \"zero_rtt_handshake\": false,"; print "      \"heartbeat\": \"10s\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" > "$phone_client_file.tmp"
  mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_tuic_win_client_config() {
  local win_client_file="/usr/local/etc/sing-box/win_client.json"
  local proxy_name
  
  while true; do
    proxy_name="tuic-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$win_client_file"; then
      break
    fi
  done 
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" -v password="$password" -v congestion_control="$congestion_control" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"tuic\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_name "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" uuid "\", "; print "      \"password\": \"" password "\", "; print "      \"congestion_control\": \""congestion_control"\","; print "      \"udp_relay_mode\": \"native\","; print "      \"zero_rtt_handshake\": false,"; print "      \"heartbeat\": \"10s\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" > "$win_client_file.tmp"
  mv "$win_client_file.tmp" "$win_client_file"
}

function generate_tuic_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="tuic-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
      if ! grep -q "name: $proxy_name" "$filename"; then
        break
      fi
  done
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" -v password="$password" -v congestion_control="$congestion_control" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    server:", server_name; print "    port:", listen_port; print "    type: tuic"; print "    uuid:", uuid; print "    password:", password; print "    alpn: [h3]"; print "    request-timeout: 8000"; print "    udp-relay-mode: native"; print "    congestion-controller:", congestion_control; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_socks_win_client_config() {
  local win_client_file="/usr/local/etc/sing-box/win_client.json"
  local proxy_name
  
  while true; do
    proxy_name="socks-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$win_client_file"; then
      break
    fi
  done
  
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v username="$username" -v password="$password" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"socks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"username\": \"" username "\", "; print "      \"password\": \"" password "\" "; print "    },";}
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }
    {print}' "$win_client_file" > "$win_client_file.tmp"    
  mv "$win_client_file.tmp" "$win_client_file"
}

function generate_socks_phone_client_config() {
  local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
  local proxy_name
  
  while true; do
    proxy_name="socks-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$phone_client_file"; then
      break
    fi
  done
  
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v username="$username" -v password="$password" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"socks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"username\": \"" username "\", "; print "      \"password\": \"" password "\" "; print "    },";}
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }
    {print}' "$phone_client_file" > "$phone_client_file.tmp" 
  mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_socks_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="socks-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
      if ! grep -q "name: $proxy_name" "$filename"; then
        break
      fi
  done
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v username="$username" -v password="$password" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: socks5"; print "    server:", local_ip; print "    port:", listen_port; print "    username:", username; print "    password:", password; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_Hysteria_win_client_config() {
  local win_client_file="/usr/local/etc/sing-box/win_client.json"
  local proxy_name
  
  while true; do
    proxy_name="Hysteria-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$win_client_file"; then
      break
    fi
  done  
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v auth_str="$auth_str" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"hysteria\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_name "\", "; print "      \"server_port\": " listen_port ","; print "      \"up_mbps\": " up_mbps ", "; print "      \"down_mbps\": " down_mbps ", "; print "      \"auth_str\": \""auth_str"\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" > "$win_client_file.tmp"
  mv "$win_client_file.tmp" "$win_client_file"
}

function generate_Hysteria_phone_client_config() {
  local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
  local proxy_name
  
  while true; do
    proxy_name="Hysteria-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$phone_client_file"; then
      break
    fi
  done 
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v auth_str="$auth_str" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"hysteria\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_name "\", "; print "      \"server_port\": " listen_port ","; print "      \"up_mbps\": " up_mbps ", "; print "      \"down_mbps\": " down_mbps ", "; print "      \"auth_str\": \""auth_str"\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" > "$phone_client_file.tmp"
  mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_Hysteria_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="hysteria-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v auth_str="$auth_str" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: hysteria"; print "    server:", server_name; print "    port:", listen_port; print "    auth-str:", auth_str; print "    alpn:"; print "      - h3"; print "    protocol: udp"; print "    up: \"" up_mbps " Mbps\""; print "    down: \"" down_mbps " Mbps\""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_vmess_win_client_config() {
  local win_client_file="/usr/local/etc/sing-box/win_client.json"
  local proxy_name
  local server_name_in_config=$(jq -r '.inbounds[0].tls.server_name' "$config_file")

  while true; do
    proxy_name="vmess-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$win_client_file"; then
      break
    fi
  done  
  
  if [ "$server_name_in_config" != "null" ]; then
    awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" -v transport_config="$transport_config" '
      /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vmess\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_name "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" uuid "\"," transport_config " "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\" "; print "      },"; print "      \"security\": \"auto\","; print "      \"alter_id\": 0,"; print "      \"packet_encoding\": \"xudp\" "; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }
    {print}' "$win_client_file" > "$win_client_file.tmp"
  else
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v uuid="$uuid" -v transport_config="$transport_config" '
      /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vmess\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" uuid "\"," transport_config " "; print "      \"security\": \"auto\","; print "      \"alter_id\": 0,"; print "      \"packet_encoding\": \"xudp\" "; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }
    {print}' "$win_client_file" > "$win_client_file.tmp"       
  fi
  mv "$win_client_file.tmp" "$win_client_file"
}

function generate_vmess_phone_client_config() {
  local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
  local proxy_name
  local server_name_in_config=$(jq -r '.inbounds[0].tls.server_name' "$config_file")

  while true; do
    proxy_name="vmess-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$phone_client_file"; then
      break
    fi
  done 
  
  if [ "$server_name_in_config" != "null" ]; then
    awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" -v transport_config="$transport_config" '
      /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vmess\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_name "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" uuid "\"," transport_config " "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\" "; print "      },"; print "      \"security\": \"auto\","; print "      \"alter_id\": 0,"; print "      \"packet_encoding\": \"xudp\" "; print "    },";}       
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }     
    {print}' "$phone_client_file" > "$phone_client_file.tmp"  
  else
    awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v uuid="$uuid" -v transport_config="$transport_config" '
      /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vmess\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" uuid "\"," transport_config " "; print "      \"security\": \"auto\","; print "      \"alter_id\": 0,"; print "      \"packet_encoding\": \"xudp\" "; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }      
    {print}' "$phone_client_file" > "$phone_client_file.tmp"
  fi
  mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_vmess_tcp_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="vmess-tcp-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v uuid="$uuid" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", uuid; print "    alterId: 0"; print "    cipher: auto"; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_vmess_tcp_tls_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="vmess-tcp-tls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", server_name; print "    port:", listen_port; print "    uuid:", uuid; print "    alterId: 0"; print "    cipher: auto"; print "    tls: true"; print "    servername: " server_name; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_vmess_ws_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="vmess-ws-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v uuid="$uuid" -v transport_path="$transport_path" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", uuid; print "    alterId: 0"; print "    cipher: auto"; print "    network: ws"; print "    ws-opts:"; print "      path: " transport_path; print "      max-early-data: 2048"; print "      early-data-header-name: Sec-WebSocket-Protocol"; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_vmess_ws_tls_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="vmess-ws-tls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" -v transport_path="$transport_path" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", server_name; print "    port:", listen_port; print "    uuid:", uuid; print "    alterId: 0"; print "    cipher: auto"; print "    network: ws"; print "    tls: true"; print "    servername:", server_name; print "    ws-opts:"; print "      path: " transport_path; print "      max-early-data: 2048"; print "      early-data-header-name: Sec-WebSocket-Protocol"; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_vmess_grpc_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="vmess-grpc-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v listen_port="$listen_port" -v uuid="$uuid" -v transport_service_name="$transport_service_name" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", uuid; print "    alterId: 0"; print "    cipher: auto"; print "    network: grpc"; print "    grpc-opts:"; print "      grpc-service-name:", "\"" transport_service_name "\""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_vmess_grpc_tls_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="vmess-grpc-tls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" -v transport_service_name="$transport_service_name" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vmess"; print "    server:", server_name; print "    port:", listen_port; print "    uuid:", uuid; print "    alterId: 0"; print "    cipher: auto"; print "    network: grpc"; print "    tls: true"; print "    servername:", server_name; print "    grpc-opts:"; print "      grpc-service-name:", "\"" transport_service_name "\""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_Hysteria2_phone_client_config() {
  local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
  local proxy_name
  
  while true; do
    proxy_name="Hysteria2-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$phone_client_file"; then
      break
    fi
  done  
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v password="$password" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"hysteria2\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_name "\", "; print "      \"server_port\": " listen_port ","; print "      \"up_mbps\": " up_mbps ", "; print "      \"down_mbps\": " down_mbps ", "; print "      \"password\": \"" password "\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]"; print "      }"; print "    },";} 
   /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" > "$phone_client_file.tmp"
  mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_Hysteria2_win_client_config() {
  local win_client_file="/usr/local/etc/sing-box/win_client.json"
  local proxy_name
  
  while true; do
    proxy_name="Hysteria2-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$win_client_file"; then
      break
    fi
  done  
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v password="$password" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"hysteria2\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_name "\", "; print "      \"server_port\": " listen_port ","; print "      \"up_mbps\": " up_mbps ", "; print "      \"down_mbps\": " down_mbps ", "; print "      \"password\": \"" password "\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h3\""; print "        ]"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" > "$win_client_file.tmp"
  mv "$win_client_file.tmp" "$win_client_file"
}

function generate_Hysteria2_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="hysteria2-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v password="$password" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: hysteria2"; print "    server:", server_name; print "    port:", listen_port; print "    password:", password; print "    alpn:"; print "      - h3"; print "    skip-cert-verify: false"; print "    up: \"" up_mbps " Mbps\""; print "    down: \"" down_mbps " Mbps\""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_vless_win_client_config() {
  local win_client_file="/usr/local/etc/sing-box/win_client.json"
  local proxy_name
  
  while true; do
    proxy_name="vless-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$win_client_file"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" -v flow_type="$flow_type" -v public_key="$public_key" -v short_id="$short_id" -v transport_config="$transport_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vless\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" uuid "\", "; print "      \"flow\": \"" flow_type "\"," transport_config ""; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"utls\": {"; print "          \"enabled\": true,"; print "          \"fingerprint\": \"chrome\""; print "        },"; print "        \"reality\": {"; print "          \"enabled\": true,"; print "          \"public_key\": \"" public_key "\","; print "          \"short_id\": \"" short_id "\""; print "        }"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" > "$win_client_file.tmp"  
  mv "$win_client_file.tmp" "$win_client_file"
}

function generate_vless_phone_client_config() {
  local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
  local proxy_name
  
  while true; do
    proxy_name="vless-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$phone_client_file"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" -v flow_type="$flow_type" -v public_key="$public_key" -v short_id="$short_id" -v transport_config="$transport_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"vless\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"uuid\": \"" uuid "\", "; print "      \"flow\": \"" flow_type "\"," transport_config ""; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"utls\": {"; print "          \"enabled\": true,"; print "          \"fingerprint\": \"chrome\""; print "        },"; print "        \"reality\": {"; print "          \"enabled\": true,"; print "          \"public_key\": \"" public_key "\","; print "          \"short_id\": \"" short_id "\""; print "        }"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" > "$phone_client_file.tmp"  
  mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_vless_reality_vision_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="vless-reality-vision-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" -v public_key="$public_key" -v short_id="$short_id" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vless"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", uuid; print "    network: tcp"; print "    udp: true"; print "    tls: true"; print "    flow: xtls-rprx-vision"; print "    servername:", server_name; print "    reality-opts:"; print "      public-key:", public_key; print "      short-id:", short_id; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_vless_reality_grpc_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="vless-reality-grpc-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v local_ip="$local_ip" -v server_name="$server_name" -v listen_port="$listen_port" -v uuid="$uuid" -v public_key="$public_key" -v short_id="$short_id" -v transport_service_name="$transport_service_name" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: vless"; print "    server:", local_ip; print "    port:", listen_port; print "    uuid:", uuid; print "    network: grpc"; print "    udp: true"; print "    tls: true"; print "    flow: "; print "    servername:", server_name; print "    reality-opts:"; print "      public-key:", public_key; print "      short-id:", short_id; print "    grpc-opts:"; print "      grpc-service-name:", "\"" transport_service_name "\""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_trojan_phone_client_config() {
  local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
  local proxy_name
  
  while true; do
    proxy_name="trojan-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$phone_client_file"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v password="$password" -v transport_config="$transport_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"trojan\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_name "\", "; print "      \"server_port\": " listen_port ","; print "      \"password\": \"" password "\"," transport_config " "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h2\","; print "          \"http/1.1\""; print "        ]"; print "      }"; print "    },";} 
   /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" > "$phone_client_file.tmp"  
  mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_trojan_win_client_config() {
  local win_client_file="/usr/local/etc/sing-box/win_client.json"
  local proxy_name
  
  while true; do
    proxy_name="trojan-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$win_client_file"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v password="$password" -v transport_config="$transport_config" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"trojan\","; print "      \"tag\": \"" proxy_name "\","; print "      \"server\": \"" server_name "\", "; print "      \"server_port\": " listen_port ","; print "      \"password\": \"" password "\"," transport_config " "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\", "; print "        \"alpn\": ["; print "          \"h2\","; print "          \"http/1.1\""; print "        ]"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" > "$win_client_file.tmp"  
  mv "$win_client_file.tmp" "$win_client_file"
}

function generate_trojan_tcp_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="trojan-tcp-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v password="$password" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: trojan"; print "    server:", server_name; print "    port:", listen_port; print "    password:", password; print "    udp: true"; print "    sni:", server_name; print "    alpn:"; print "      - h2"; print "      - http/1.1"; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_trojan_ws_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="trojan-ws-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v password="$password" -v transport_path="$transport_path" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: trojan"; print "    server:", server_name; print "    port:", listen_port; print "    password:", "\"" password "\""; print "    network: ws"; print "    sni:", server_name; print "    udp: true"; print "    ws-opts:"; print "      path:", transport_path; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_trojan_grpc_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="trojan-grpc-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v server_name="$server_name" -v listen_port="$listen_port" -v password="$password" -v transport_service_name="$transport_service_name" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: trojan"; print "    server:", server_name; print "    port:", listen_port; print "    password:", "\"" password "\""; print "    network: grpc"; print "    sni:", server_name; print "    udp: true"; print "    grpc-opts:"; print "      grpc-service-name:", "\"" transport_service_name "\""; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_shadowtls_win_client_config() {
  local win_client_file="/usr/local/etc/sing-box/win_client.json"
  local proxy_name
  local shadowtls_out
  
while true; do
  proxy_name="shadowtls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
  shadowtls_out="stl-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
  if ! grep -q "name: $proxy_name" "$win_client_file" && ! grep -q "name: $shadowtls_out" "$win_client_file" && [ "$proxy_name" != "$shadowtls_out" ]; then
    break
  fi
done
  awk -v shadowtls_out="$shadowtls_out" -v proxy_name="$proxy_name" -v method="$method" -v ss_password="$ss_password" -v local_ip="$local_ip" -v listen_port="$listen_port" -v shadowtls_password="$shadowtls_password" -v user_input="$user_input" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"method\": \"" method "\", "; print "      \"password\": \"" ss_password "\","; print "      \"detour\": \"" shadowtls_out "\", "; print "      \"multiplex\": {"; print "        \"enabled\": true,"; print "        \"max_connections\": 4,"; print "        \"min_streams\": 4 "; print "      }"; print "    },"; print "    {"; print "      \"type\": \"shadowtls\","; print "      \"tag\": \"" shadowtls_out "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"version\": 3, "; print "      \"password\": \""shadowtls_password"\", "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" user_input "\", "; print "        \"utls\": {"; print "          \"enabled\": true,"; print "          \"fingerprint\": \"chrome\" "; print "        }"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$win_client_file" > "$win_client_file.tmp"
  mv "$win_client_file.tmp" "$win_client_file"
}

function generate_shadowtls_phone_client_config() {
  local phone_client_file="/usr/local/etc/sing-box/phone_client.json"
  local proxy_name
  local shadowtls_out
    
  while true; do
    proxy_name="shadowtls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    shadowtls_out="stl-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
  if ! grep -q "name: $proxy_name" "$phone_client_file" && ! grep -q "name: $shadowtls_out" "$phone_client_file" && [ "$proxy_name" != "$shadowtls_out" ]; then
      break
    fi
  done 
  awk -v shadowtls_out="$shadowtls_out" -v proxy_name="$proxy_name" -v method="$method" -v ss_password="$ss_password" -v local_ip="$local_ip" -v listen_port="$listen_port" -v shadowtls_password="$shadowtls_password" -v user_input="$user_input" '
    /^  "outbounds": \[/ {print; getline; print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"" proxy_name "\","; print "      \"method\": \"" method "\", "; print "      \"password\": \"" ss_password "\","; print "      \"detour\": \"" shadowtls_out "\", "; print "      \"multiplex\": {"; print "        \"enabled\": true,"; print "        \"max_connections\": 4,"; print "        \"min_streams\": 4 "; print "      }"; print "    },"; print "    {"; print "      \"type\": \"shadowtls\","; print "      \"tag\": \"" shadowtls_out "\","; print "      \"server\": \"" local_ip "\", "; print "      \"server_port\": " listen_port ","; print "      \"version\": 3, "; print "      \"password\": \""shadowtls_password"\", "; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" user_input "\", "; print "        \"utls\": {"; print "          \"enabled\": true,"; print "          \"fingerprint\": \"chrome\" "; print "        }"; print "      }"; print "    },";} 
    /^      "outbounds": \[/ {print; getline; if ($0 ~ /^      \],$/) {print "        \"" proxy_name "\""} else {print "        \"" proxy_name "\", "} }    
    {print}' "$phone_client_file" > "$phone_client_file.tmp"
  mv "$phone_client_file.tmp" "$phone_client_file"
}

function generate_shadowtls_yaml() {
  local filename="/usr/local/etc/sing-box/clash.yaml"
  local proxy_name
  while true; do
    proxy_name="shadowtls-$(head /dev/urandom | tr -dc '0-9' | head -c 4)"
    if ! grep -q "name: $proxy_name" "$filename"; then
      break
    fi
  done
  awk -v proxy_name="$proxy_name" -v method="$method" -v ss_password="$ss_password" -v local_ip="$local_ip" -v listen_port="$listen_port" -v shadowtls_password="$shadowtls_password" -v user_input="$user_input" '/^proxies:$/ {print; print "  - name: " proxy_name; print "    type: ss"; print "    server:", local_ip; print "    port:", listen_port; print "    cipher:", method; print "    password:", "\"" ss_password "\""; print "    plugin: shadow-tls"; print "    plugin-opts:"; print "      host: \"" user_input "\""; print "      password:", "\"" shadowtls_password "\""; print "      version: 3"; next} /- name: Proxy/ { print; flag_proxy=1; next } flag_proxy && flag_proxy++ == 3 { print "      - " proxy_name } /- name: auto/ { print; flag_auto=1; next } flag_auto && flag_auto++ == 3 { print "      - " proxy_name } 1' "$filename" > temp_file && mv temp_file "$filename"
}

function generate_naive_win_client_config() {
    local naive_client_file="$naive_client_filename"
    local username="$1"
    local password="$2"
    local listen_port="$3"
    local server_name="$4"
    sed -i "s/username/$username/" "$naive_client_file"
    sed -i "s/password/$password/" "$naive_client_file"
    sed -i "s/listen_port/$listen_port/" "$naive_client_file"
    sed -i "s/server_name/$server_name/" "$naive_client_file"
    echo "电脑端配置文件已保存至$naive_client_file，请下载后使用！"
}

function display_naive_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt" 
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local users=$(jq -r '.inbounds[0].users[] | "\(.username)                                \(.password)"' "$config_file")  
    echo -e "${CYAN}NaiveProxy 节点配置信息：${NC}"  | tee -a "$output_file"
    echo -e "${CYAN}================================================================${NC}"  | tee -a "$output_file"
    echo "服务器地址: $server_name"  | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"  | tee -a "$output_file"        
    echo "监听端口: $listen_port"  | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "用 户 名                                  密  码"  | tee -a "$output_file"
    echo "----------------------------------------------------------------"  | tee -a "$output_file"
    echo "$users"  | tee -a "$output_file" 
    echo -e "${CYAN}================================================================${NC}"  | tee -a "$output_file"
    echo "配置信息已保存至 $output_file" 
}

function generate_naive_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local naive_client_file="$naive_client_filename"  
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local users=$(jq -r '.inbounds[0].users[] | "\(.username)                                \(.password)"' "$config_file")   
    IFS=$'\n'
    for user_info in $users; do
        local username=$(echo "$user_info" | awk '{print $1}')
        local password=$(echo "$user_info" | awk '{print $2}')        
        generate_naive_random_filename
        write_naive_client_file
        generate_naive_win_client_config "$username" "$password" "$listen_port" "$server_name"        
    done
    unset IFS
}

function display_Direct_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"    
    local local_ip
    local_ip=$(get_local_ip)
    local override_address=$(jq -r '.inbounds[0].override_address' "$config_file")
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local override_port=$(jq -r '.inbounds[0].override_port' "$config_file")  
    echo -e "${CYAN}Direct 节点配置信息：${NC}" | tee -a "$output_file"
    echo -e "${CYAN}================================================================${NC}"  | tee -a "$output_file"
    echo "中转地址: $local_ip" | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "监听端口: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "目标地址: $override_address" | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "目标端口: $override_port" | tee -a "$output_file"
    echo -e "${CYAN}================================================================${NC}"  | tee -a "$output_file"
    echo "配置信息已保存至 $output_file"        
}

function display_juicity_config() {
    local config_file="/usr/local/etc/juicity/config.json"
    local output_file="/usr/local/etc/juicity/output.txt"  
    local listen_port=$(jq -r '.listen' "$config_file" | sed 's/\://')
    local UUIDS=$(jq -r '.users | to_entries[] | "UUID: \(.key)\t密码: \(.value)"' "$config_file")
    local congestion_control=$(jq -r '.congestion_control' "$config_file")  
    echo -e "${CYAN}juicity 节点配置信息：${NC}"  | tee -a "$output_file"     
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file"  
    echo "监听端口: $listen_port"  | tee -a "$output_file" 
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"  
    echo "UUID和密码:"  | tee -a "$output_file" 
    echo "$UUIDS"  | tee -a "$output_file" 
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "拥塞控制算法: $congestion_control"  | tee -a "$output_file" 
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file" 
    echo "配置信息已保存至 $output_file"    
}

function display_tuic_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"   
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")     
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local users=$(jq -r '.inbounds[0].users[] | "\(.name)     \(.uuid)     \(.password)"' "$config_file")
    local congestion_control=$(jq -r '.inbounds[0].congestion_control' "$config_file")
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")    
    echo -e "${CYAN}TUIC 节点配置信息：${NC}"  | tee -a "$output_file"     
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file"  
    echo "服务器地址: $server_name"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"      
    echo "监听端口: $listen_port"  | tee -a "$output_file" 
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"  
    echo "用户密码列表:"  | tee -a "$output_file" 
    echo "------------------------------------------------------------------"  | tee -a "$output_file"
    echo "  用户名                    UUID                           密码"  | tee -a "$output_file" 
    echo "------------------------------------------------------------------"  | tee -a "$output_file" 
    echo "$users"  | tee -a "$output_file" 
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "拥塞控制算法: $congestion_control"  | tee -a "$output_file" 
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "ALPN: $alpn"  | tee -a "$output_file"     
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file" 
    echo "配置信息已保存至 $output_file" 
}

function display_tuic_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml" 
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json" 
    local win_client_file="/usr/local/etc/sing-box/win_client.json"     
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")     
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local users=$(jq -r '.inbounds[0].users[] | "\(.name)     \(.uuid)     \(.password)"' "$config_file")
    local congestion_control=$(jq -r '.inbounds[0].congestion_control' "$config_file")
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")    
    local IFS=$'\n'
    local user_array=($(echo "$users"))
    unset IFS
    for user_info in "${user_array[@]}"; do
        IFS=' ' read -r username uuid password <<< "$user_info"
        write_phone_client_file
        write_win_client_file        
        generate_tuic_win_client_config "$uuid" "$password"
        generate_tuic_phone_client_config "$uuid" "$password"
        ensure_clash_yaml
        write_clash_yaml
        generate_tuic_yaml
    done
    echo "手机端配置文件已保存至$phone_client_file，请下载后使用！"
    echo "电脑端配置文件已保存至$win_client_file，请下载后使用！"
    echo "Clash配置文件已保存至 $clash_file ,请下载使用！" 
}

function display_Shadowsocks_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"        
    local local_ip
    local_ip=$(get_local_ip)
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local ss_method=$(jq -r '.inbounds[0].method' "$config_file")
    local ss_password=$(jq -r '.inbounds[0].password' "$config_file")  
    echo -e "${CYAN}Shadowsocks 节点配置信息：${NC}"  | tee -a "$output_file"
    echo -e "${CYAN}================================================================${NC}"  | tee -a "$output_file"
    echo "服务器地址: $local_ip"  | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "监听端口: $listen_port"  | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "加密方式: $ss_method"  | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "密码: $ss_password"  | tee -a "$output_file"
    echo -e "${CYAN}================================================================${NC}"  | tee -a "$output_file"
    echo "配置信息已保存至 $output_file"  
}

function display_Shadowsocks_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml" 
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json" 
    local win_client_file="/usr/local/etc/sing-box/win_client.json"         
    local local_ip
    local_ip=$(get_local_ip)
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local ss_method=$(jq -r '.inbounds[0].method' "$config_file")
    local ss_password=$(jq -r '.inbounds[0].password' "$config_file")  
    write_phone_client_file
    write_win_client_file
    generate_shadowsocks_win_client_config
    generate_shadowsocks_phone_client_config
    ensure_clash_yaml
    write_clash_yaml
    generate_shadowsocks_yaml 
    echo "手机端配置文件已保存至$phone_client_file，请下载后使用！"
    echo "电脑端配置文件已保存至$win_client_file，请下载后使用！"
    echo "Clash配置文件已保存至 $clash_file ,请下载使用！"  
}

function display_socks_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"        
    local local_ip
    local_ip=$(get_local_ip)   
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")         
    local users=$(jq -r '.inbounds[0].users[] | "\(.username)                \(.password)"' "$config_file") 
    echo -e "${CYAN}SOCKS 节点配置信息：${NC}"  | tee -a "$output_file"     
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file"  
    echo "服务器地址: $local_ip"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"      
    echo "监听端口: $listen_port"  | tee -a "$output_file" 
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"  
    echo "用户密码列表:"  | tee -a "$output_file" 
    echo "------------------------------------------------------------------"  | tee -a "$output_file"
    echo "  用户名                    密码"  | tee -a "$output_file" 
    echo "------------------------------------------------------------------"  | tee -a "$output_file" 
    echo "$users"  | tee -a "$output_file" 
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file" 
    echo "配置信息已保存至 $output_file"    
}

function display_socks_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml" 
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json" 
    local win_client_file="/usr/local/etc/sing-box/win_client.json"           
    local local_ip
    local_ip=$(get_local_ip)   
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")         
    local users=$(jq -r '.inbounds[0].users[] | "\(.username)                \(.password)"' "$config_file") 
    local IFS=$'\n'
    local user_array=($(echo "$users"))
    unset IFS
    for user_info in "${user_array[@]}"; do
        IFS=' ' read -r username password <<< "$user_info"
        write_phone_client_file
        write_win_client_file        
        generate_socks_win_client_config "$username" "$password"
        generate_socks_phone_client_config "$username" "$password"
        ensure_clash_yaml
        write_clash_yaml
        generate_socks_yaml         
    done
    echo "手机端配置文件已保存至$phone_client_file，请下载后使用！"
    echo "电脑端配置文件已保存至$win_client_file，请下载后使用！"
    echo "Clash配置文件已保存至 $clash_file ,请下载使用！"   
}

function display_Hysteria_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"        
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")      
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")
    echo -e "${CYAN}Hysteria 节点配置信息：${NC}"  | tee -a "$output_file"
    echo -e "${CYAN}======================================================================================${NC}"  | tee -a "$output_file" 
    echo "服务器地址：$server_name"  | tee -a "$output_file"
    echo -e "${CYAN}--------------------------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "监听端口：$listen_port"  | tee -a "$output_file"
    echo -e "${CYAN}--------------------------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "上行速度：${up_mbps}Mbps"  | tee -a "$output_file"
    echo -e "${CYAN}--------------------------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "下行速度：${down_mbps}Mbps"  | tee -a "$output_file"
    echo -e "${CYAN}--------------------------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "ALPN：$alpn"  | tee -a "$output_file"
    echo -e "${CYAN}--------------------------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "用户密码："
    local user_count=$(echo "$users" | jq length)    
    for ((i = 0; i < user_count; i++)); do
        local auth_str=$(echo "$users" | jq -r ".[$i].auth_str")
        echo "用户$i: $auth_str"  | tee -a "$output_file"
    done
    echo -e "${CYAN}======================================================================================${NC}"  | tee -a "$output_file" 
    echo "配置信息已保存至 $output_file"   
}

function display_Hysteria_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml" 
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json" 
    local win_client_file="/usr/local/etc/sing-box/win_client.json"         
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")      
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")
    local user_count=$(echo "$users" | jq length)     
    for ((i = 0; i < user_count; i++)); do
        local auth_str=$(echo "$users" | jq -r ".[$i].auth_str")
        write_phone_client_file
        write_win_client_file
        generate_Hysteria_win_client_config "$auth_str"
        generate_Hysteria_phone_client_config "$auth_str"
        ensure_clash_yaml
        write_clash_yaml
        generate_Hysteria_yaml          
    done
    echo "手机端配置文件已保存至$phone_client_file，请下载后使用！"
    echo "电脑端配置文件已保存至$win_client_file，请下载后使用！"
    echo "Clash配置文件已保存至 $clash_file ,请下载使用！"    
}

function display_Hy2_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"         
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")      
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")
    echo -e "${CYAN}Hysteria2 节点配置信息：${NC}"  | tee -a "$output_file"
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file" 
    echo "服务器地址：$server_name"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "监听端口：$listen_port"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "上行速度：${up_mbps}Mbps"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "下行速度：${down_mbps}Mbps"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "ALPN：$alpn"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "用户密码："
    local user_count=$(echo "$users" | jq length)
    for ((i = 0; i < user_count; i++)); do
        local password=$(echo "$users" | jq -r ".[$i].password")
        echo "用户$i: $password"  | tee -a "$output_file"
    done
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file" 
    echo "配置信息已保存至 $output_file"       
}

function display_Hy2_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml"  
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json" 
    local win_client_file="/usr/local/etc/sing-box/win_client.json"          
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")      
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")
    local user_count=$(echo "$users" | jq length)    
    for ((i = 0; i < user_count; i++)); do
        local password=$(echo "$users" | jq -r ".[$i].password")
        write_phone_client_file
        write_win_client_file
        generate_Hysteria2_win_client_config "$password"
        generate_Hysteria2_phone_client_config "$password"
        ensure_clash_yaml
        write_clash_yaml
        generate_Hysteria2_yaml          
    done
    echo "手机端配置文件已保存至$phone_client_file，请下载后使用！"
    echo "电脑端配置文件已保存至$win_client_file，请下载后使用！"
    echo "Clash配置文件已保存至 $clash_file ,请下载使用！"   
}

function display_reality_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"          
    local local_ip
    local_ip=$(get_local_ip)       
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local users=$(jq -r '.inbounds[0].users[].uuid' "$config_file")
    local flow_type=$(jq -r '.inbounds[0].users[0].flow' "$config_file")
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    local target_server=$(jq -r '.inbounds[0].tls.reality.handshake.server' "$config_file")
    local short_ids=$(jq -r '.inbounds[0].tls.reality.short_id[]' "$config_file")
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")    
    local public_key=$(cat /tmp/public_key_temp.txt)
    if [[ "$flow_type" == "xtls-rprx-vision" ]]; then
        transport_type="tcp"
    fi
    echo -e "${CYAN}Vless+Reality 节点配置信息：${NC}" | tee -a "$output_file"
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file"
    echo "服务器地址: $local_ip" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "监听端口: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "用户 UUID：  $users" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "流控类型: $flow_type" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    if [ "$transport_type" == "grpc" ]; then
        echo "传输协议: $transport_type" | tee -a "$output_file"
        echo "grpc-service-name: $transport_service_name" | tee -a "$output_file"
    elif [ "$transport_type" == "null" ]; then
        echo "传输协议: tcp" | tee -a "$output_file"
    else
        echo "传输协议: $transport_type" | tee -a "$output_file"
    fi
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "ServerName: $server_name" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "目标网站地址: $target_server" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "Short ID:" | tee -a "$output_file"
    echo "$short_ids" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "PublicKey: $public_key" | tee -a "$output_file"
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file"
    echo "配置信息已保存至 $output_file"     
}

function display_reality_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json" 
    local clash_file="/usr/local/etc/sing-box/clash.yaml" 
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json" 
    local win_client_file="/usr/local/etc/sing-box/win_client.json"          
    local local_ip
    local_ip=$(get_local_ip)       
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local users=$(jq -r '.inbounds[0].users[].uuid' "$config_file")
    local flow_type=$(jq -r '.inbounds[0].users[0].flow' "$config_file")
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    local target_server=$(jq -r '.inbounds[0].tls.reality.handshake.server' "$config_file")
    local short_ids=$(jq -r '.inbounds[0].tls.reality.short_id[]' "$config_file")
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")    
    local public_key=$(cat /tmp/public_key_temp.txt)
    for short_id in $short_ids; do   
        write_phone_client_file
        write_win_client_file
        generate_vless_win_client_config "$short_id"
        generate_vless_phone_client_config "$short_id"
        if [ "$transport_type" == "grpc" ]; then       
            ensure_clash_yaml
            write_clash_yaml
            generate_vless_reality_grpc_yaml
        elif [ "$transport_type" == "http" ]; then
            :
        else
            ensure_clash_yaml
            write_clash_yaml
            generate_vless_reality_vision_yaml
        fi              
    done
    if [ "$transport_type" != "http" ]; then
        echo "Clash配置文件已保存至 $clash_file，请下载使用！"
    fi    
    echo "手机端配置文件已保存至$phone_client_file，请下载后使用！"
    echo "电脑端配置文件已保存至$win_client_file，请下载后使用！"          
}

function display_vmess_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"         
    local local_ip
    local_ip=$(get_local_ip)
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local UUIDS=($(jq -r '.inbounds[0].users[].uuid' "$config_file"))
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local transport_path=$(jq -r '.inbounds[0].transport.path' "$config_file")  
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")   
    echo -e "${CYAN}Vmess 节点配置信息：${NC}"  | tee -a "$output_file"
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file"    
    if [ -n "$server_name" ] && [ "$server_name" != "null" ]; then
        echo "服务器地址: $server_name"  | tee -a "$output_file"
    else
        echo "服务器地址: $local_ip"  | tee -a "$output_file"
    fi    
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "监听端口: $listen_port"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"    
    for ((i = 0; i < ${#UUIDS[@]}; i++)); do
        local uuid="${UUIDS[i]}"
        echo -e "密码 $i: $uuid"  | tee -a "$output_file"
    done    
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"    
    if [ "$transport_type" != "null" ]; then
        echo "传输协议: $transport_type"  | tee -a "$output_file"
        if [ "$transport_type" == "ws" ]; then
            echo "路径: $transport_path"  | tee -a "$output_file"
        elif [ "$transport_type" == "grpc" ]; then
            echo "grpc-service-name: $transport_service_name"  | tee -a "$output_file"
        fi
    else
        echo "传输协议: tcp"  | tee -a "$output_file"
    fi
       
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file"
    echo "配置信息已保存至 $output_file"  
}

function display_vmess_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml" 
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json" 
    local win_client_file="/usr/local/etc/sing-box/win_client.json"          
    local local_ip
    local_ip=$(get_local_ip)
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local UUIDS=($(jq -r '.inbounds[0].users[].uuid' "$config_file"))
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local transport_path=$(jq -r '.inbounds[0].transport.path' "$config_file")  
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")   
    local show_clash_message=true

    for ((i = 0; i < ${#UUIDS[@]}; i++)); do
        local uuid="${UUIDS[i]}" 
        write_phone_client_file
        write_win_client_file
        generate_vmess_win_client_config
        generate_vmess_phone_client_config
        if [ "$server_name" == "null" ] && [ "$transport_type" == "null" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_tcp_yaml
        elif [ "$server_name" == "null" ] && [ "$transport_type" == "ws" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_ws_yaml
        elif [ "$server_name" == "null" ] && [ "$transport_type" == "grpc" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_grpc_yaml
        elif [ -n "$server_name" ] && [ "$server_name" != "null" ] && [ "$transport_type" == "null" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_tcp_tls_yaml
        elif [ -n "$server_name" ] && [ "$server_name" != "null" ] && [ "$transport_type" == "ws" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_ws_tls_yaml
        elif [ -n "$server_name" ] && [ "$server_name" != "null" ] && [ "$transport_type" == "grpc" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_vmess_grpc_tls_yaml
        elif [ -n "$server_name" ] && [ "$server_name" != "null" ] && [ "$transport_type" == "http" ]; then
            show_clash_message=false
        fi               
    done
    if [ "$transport_type" == "http" ]; then
        echo "手机端配置文件已保存至$phone_client_file，请下载后使用！"
        echo "电脑端配置文件已保存至$win_client_file，请下载后使用！"
    fi

    if [ "$transport_type" != "http" ] && [ "$show_clash_message" = true ]; then
        echo "手机端配置文件已保存至$phone_client_file，请下载后使用！"
        echo "电脑端配置文件已保存至$win_client_file，请下载后使用！"    
        echo "Clash配置文件已保存至 $clash_file，请下载使用！"
    fi
}

function display_trojan_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"          
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local passwords=($(jq -r '.inbounds[0].users[].password' "$config_file"))
    local alpn=$(jq -r '.inbounds[0].tls.alpn | join(", ")' "$config_file")
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local transport_path=$(jq -r '.inbounds[0].transport.path' "$config_file")
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")    
    echo -e "${CYAN}trojan 节点配置信息：${NC}"  | tee -a "$output_file"
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file" 
    echo "服务器地址: $server_name"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "监听端口: $listen_port"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    for ((i = 0; i < ${#passwords[@]}; i++)); do
        local password="${passwords[i]}" 
        echo -e "密码 $i: $password"  | tee -a "$output_file"
    done    
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    if [ "$transport_type" != "null" ]; then
        echo "传输协议: $transport_type"  | tee -a "$output_file"
        if [ "$transport_type" == "ws" ]; then
            echo "路径: $transport_path"  | tee -a "$output_file"
        elif [ "$transport_type" == "grpc" ]; then
            echo "grpc-service-name: $transport_service_name"  | tee -a "$output_file"
        fi
    else
        echo "传输协议: tcp"  | tee -a "$output_file"
    fi
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file"
    echo "配置信息已保存至 $output_file"
}

function display_trojan_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml" 
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json" 
    local win_client_file="/usr/local/etc/sing-box/win_client.json"          
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local passwords=($(jq -r '.inbounds[0].users[].password' "$config_file"))
    local alpn=$(jq -r '.inbounds[0].tls.alpn | join(", ")' "$config_file")
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local transport_path=$(jq -r '.inbounds[0].transport.path' "$config_file")
    local transport_service_name=$(jq -r '.inbounds[0].transport.service_name' "$config_file")    
    for ((i = 0; i < ${#passwords[@]}; i++)); do
        local password="${passwords[i]}" 
        write_phone_client_file
        write_win_client_file
        generate_trojan_win_client_config
        generate_trojan_phone_client_config

        if [ "$transport_type" == "ws" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_trojan_ws_yaml
        elif [ "$transport_type" == "grpc" ]; then
            ensure_clash_yaml
            write_clash_yaml
            generate_trojan_grpc_yaml
        elif [ "$transport_type" == "http" ]; then
            :
        else
            ensure_clash_yaml
            write_clash_yaml
            generate_trojan_tcp_yaml
        fi       
    done
    if [ "$transport_type" != "http" ]; then
        echo "Clash配置文件已保存至 $clash_file，请下载使用！"
    fi    
    echo "手机端配置文件已保存至$phone_client_file，请下载后使用！"
    echo "电脑端配置文件已保存至$win_client_file，请下载后使用！"    
}

function display_shadowtls_config_info() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"         
    local local_ip
    local_ip=$(get_local_ip)    
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")       
    local shadowtls_passwords=$(jq -r '.inbounds[0].users[] | "\(.password)"' "$config_file")
    local user_input=$(jq -r '.inbounds[0].handshake.server' "$config_file")
    local ss_password=$(jq -r '.inbounds[1].password' "$config_file")  
    local method=$(jq -r '.inbounds[1].method' "$config_file")     
    echo -e "${CYAN}ShadowTLS 节点配置信息：${NC}" | tee -a "$output_file"
    echo -e "${CYAN}================================================================${NC}" | tee -a "$output_file"
    echo "服务器地址: $local_ip" | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "监听端口: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "加密方式: $method" | tee -a "$output_file"    
    echo -e "${CYAN}----------------------------------------------------------------${NC}" | tee -a "$output_file"   
    echo "ShadowTLS 密码:" | tee -a "$output_file" 
    echo "$shadowtls_passwords" | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Shadowsocks 密码: $ss_password" | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "握手服务器地址: $user_input" | tee -a "$output_file"
    echo -e "${CYAN}================================================================${NC}" | tee -a "$output_file"
    echo "配置信息已保存至 $output_file"      
}

function display_shadowtls_config_files() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local clash_file="/usr/local/etc/sing-box/clash.yaml" 
    local phone_client_file="/usr/local/etc/sing-box/phone_client.json" 
    local win_client_file="/usr/local/etc/sing-box/win_client.json"          
    local local_ip
    local_ip=$(get_local_ip)    
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")       
    local shadowtls_passwords=$(jq -r '.inbounds[0].users[] | "\(.password)"' "$config_file")
    local user_input=$(jq -r '.inbounds[0].handshake.server' "$config_file")
    local ss_password=$(jq -r '.inbounds[1].password' "$config_file")  
    local method=$(jq -r '.inbounds[1].method' "$config_file")     
    local IFS=$'\n'
    local shadowtls_password=($(echo "$shadowtls_passwords"))
    unset IFS
    for shadowtls_password in "${shadowtls_password[@]}"; do
        IFS=' ' read -r password <<< "$shadowtls_password"
        write_phone_client_file
        write_win_client_file
        generate_shadowtls_win_client_config "$shadowtls_password"
        generate_shadowtls_phone_client_config "$shadowtls_password"
        ensure_clash_yaml
        write_clash_yaml
        generate_shadowtls_yaml          
    done
    echo "手机端配置文件已保存至$phone_client_file，请下载后使用！"
    echo "电脑端配置文件已保存至$win_client_file，请下载后使用！"
    echo "Clash配置文件已保存至 $clash_file ,请下载使用！"   
}

function view_saved_config() {
    local config_paths=(
        "/usr/local/etc/sing-box/output.txt"
        "/usr/local/etc/juicity/output.txt"
    )

    local found=false
    for path in "${config_paths[@]}"; do
        if [[ -f "$path" ]]; then
            echo "配置信息文件 ($path):"
            cat "$path"
            found=true
        fi
    done

    if [[ "$found" == false ]]; then
        echo "未找到保存的配置信息文件！"
    fi
}

function check_and_restart_services() {
    if [ -f "/etc/systemd/system/sing-box.service" ]; then
        systemctl restart sing-box.service
        systemctl status --no-pager sing-box.service
    fi

    if [ -f "/etc/systemd/system/juicity.service" ]; then
        systemctl restart juicity.service
        systemctl status --no-pager juicity.service
    fi    
}

function uninstall_sing_box() {
    echo "开始卸载 sing-box..."
    systemctl stop sing-box
    systemctl disable sing-box
    rm -rf /usr/local/bin/sing-box
    rm -rf /usr/local/etc/sing-box
    rm -rf /etc/systemd/system/sing-box.service
    rm -rf /etc/ssl/private/*.crt 
    rm -rf /etc/ssl/private/*.key 
    systemctl daemon-reload
    echo "sing-box 卸载完成。"
}

function uninstall_juicity() {
    echo "开始卸载 juicity..."
    systemctl stop juicity.service
    systemctl disable juicity.service
    rm -rf /etc/systemd/system/juicity.service
    rm -rf /usr/local/etc/juicity
    rm -rf /usr/local/bin/juicity-server
    echo "juicity 卸载完成。"
}

function update_proxy_tool() {
    if [ -e /usr/local/bin/juicity-server ]; then
        install_latest_juicity
    fi    

    if [ -e /usr/local/bin/sing-box ]; then
        select_sing_box_install_option
    fi
}

function uninstall() {
    local uninstall_sing_box=false
    local uninstall_juicity=false

    if [[ -f "/etc/systemd/system/sing-box.service" ]] || [[ -f "/usr/local/bin/sing-box" ]] || [[ -d "/usr/local/etc/sing-box/" ]]; then
        uninstall_sing_box=true
    fi    

    if [[ -f "/etc/systemd/system/juicity.service" ]] || [[ -f "/usr/local/bin/juicity-server" ]] || [[ -d "/usr/local/etc/juicity/" ]]; then
        uninstall_juicity=true
    fi

    if [[ "$uninstall_sing_box" == true ]]; then
        uninstall_sing_box
    fi

    if [[ "$uninstall_juicity" == true ]]; then
        uninstall_juicity
    fi    
}

function check_wireguard_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    
    if grep -q "wireguard" "$config_file"; then
        echo -e "${RED}Warp 已安装，请勿重复安装！${NC}"
        exit 1
    fi
}

function juicity_install() {
    configure_dns64
    enable_bbr
    create_juicity_folder
    create_ssl_folder   
    install_latest_juicity
    generate_juicity_config
    configure_juicity_service
    systemctl daemon-reload
    systemctl enable juicity.service
    systemctl start juicity.service
    systemctl restart juicity.service
    display_juicity_config
}

function Direct_install() {
    install_sing_box
    log_outbound_config    
    listen_port
    override_address
    override_port
    generate_Direct_config
    modify_format_inbounds_and_outbounds
    check_firewall_configuration 
    systemctl daemon-reload   
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_Direct_config
}

function Shadowsocks_install() {
    install_sing_box
    log_outbound_config    
    listen_port
    encryption_method
    generate_ss_config
    modify_format_inbounds_and_outbounds
    check_firewall_configuration 
    systemctl daemon-reload   
    systemctl enable sing-box   
    systemctl start sing-box
    systemctl restart sing-box
    display_Shadowsocks_config_info
    display_Shadowsocks_config_files
}

function socks_install() {
    install_sing_box
    log_outbound_config    
    generate_socks_config
    modify_format_inbounds_and_outbounds
    check_firewall_configuration 
    systemctl daemon-reload   
    systemctl enable sing-box   
    systemctl start sing-box
    systemctl restart sing-box
    display_socks_config_info
    display_socks_config_files
}

function NaiveProxy_install() {
    install_sing_box 
    log_outbound_config        
    generate_naive_config
    modify_format_inbounds_and_outbounds    
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_naive_config_info
    generate_naive_config_files
}

function tuic_install() {
    install_sing_box 
    log_outbound_config    
    generate_tuic_config
    modify_format_inbounds_and_outbounds    
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_tuic_config_info
    display_tuic_config_files
}

function Hysteria_install() {
    install_sing_box  
    log_outbound_config    
    generate_Hysteria_config
    modify_format_inbounds_and_outbounds    
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_Hysteria_config_info
    display_Hysteria_config_files
}

function shadowtls_install() {
    install_sing_box 
    log_outbound_config 
    generate_shadowtls_config
    modify_format_inbounds_and_outbounds    
    check_firewall_configuration      
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_shadowtls_config_info
    display_shadowtls_config_files
}

function reality_install() {
    install_sing_box 
    log_outbound_config         
    generate_reality_config 
    modify_format_inbounds_and_outbounds     
    check_firewall_configuration              
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_reality_config_info
    display_reality_config_files
}

function Hysteria2_install() {
    install_sing_box  
    log_outbound_config    
    generate_Hy2_config
    modify_format_inbounds_and_outbounds    
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_Hy2_config_info
    display_Hy2_config_files
}

function trojan_install() {
    install_sing_box 
    log_outbound_config
    generate_trojan_config 
    modify_format_inbounds_and_outbounds                              
    systemctl daemon-reload      
    systemctl enable sing-box 
    systemctl start sing-box
    systemctl restart sing-box
    display_trojan_config_info
    display_trojan_config_files
}

function vmess_install() {
    install_sing_box
    log_outbound_config    
    generate_vmess_config
    modify_format_inbounds_and_outbounds     
    systemctl daemon-reload   
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_vmess_config_info
    display_vmess_config_files
}

function wireguard_install() {
    check_wireguard_config
    check_config_file_existence
    select_unlocked_items
    geosite=()
    update_geosite_array
    select_outbound
    update_route_file "$outbound"
    get_temp_config_file
    extract_variables_and_cleanup
    update_outbound_file
    systemctl restart sing-box
}

function Update_certificate() {
    extract_tls_info
    Reapply_certificates
} 

function main_menu() {
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo -e "║ ${CYAN}作者${NC}： Mr. xiao                                                        ║"
echo -e "║ ${CYAN}项目地址${NC}: https://github.com/TinrLin                                   ║"
echo -e "║ ${CYAN}Telegram 群组${NC}: https://t.me/mrxiao758                                  ║"
echo -e "║ ${CYAN}YouTube频道${NC}: https://youtube.com/@Mr_xiao502                           ║"
echo "╠════════════════════════════════════════════════════════════════════════╣"
echo "║ 请选择要执行的操作：                                                   ║"
echo -e "║${CYAN} [1]${NC}  Socks                         ${CYAN} [2]${NC}   Direct                       ║"
echo -e "║${CYAN} [3]${NC}  Vmess                         ${CYAN} [4]${NC}   Vless                        ║"
echo -e "║${CYAN} [5]${NC}  TUIC                          ${CYAN} [6]${NC}   Juicity                      ║"
echo -e "║${CYAN} [7]${NC}  Trojan                        ${CYAN} [8]${NC}   Hysteria                     ║"
echo -e "║${CYAN} [9]${NC}  Hysteria2                     ${CYAN} [10]${NC}  ShadowTLS                    ║"
echo -e "║${CYAN} [11]${NC} NaiveProxy                    ${CYAN} [12]${NC}  Shadowsocks                  ║"
echo -e "║${CYAN} [13]${NC} WireGuard                     ${CYAN} [14]${NC}  查看节点信息                 ║"
echo -e "║${CYAN} [15]${NC} 更新内核                      ${CYAN} [16]${NC}  重启服务                     ║"
echo -e "║${CYAN} [17]${NC} 更新证书                      ${CYAN} [18]${NC}  卸载                         ║"
echo -e "║${CYAN} [0]${NC}  退出                                                              ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"

    local choice
    read -p "请选择 [0-15]: " choice

    case $choice in
        1)
            socks_install
            ;;
        2)
            Direct_install
            ;;  
        3)
            vmess_install
            ;;                      
        4)
            reality_install
            ;;
        5)
            tuic_install
            ;;
        6)
            juicity_install
            ;;                
        7)
            trojan_install
            ;;
        8)
            Hysteria_install
            ;;
        9)
            Hysteria2_install
            ;;
        10)
            shadowtls_install
            ;; 
        11)
            NaiveProxy_install
            ;;  
        12)
            Shadowsocks_install
            ;;
        13)
            wireguard_install
            ;;                                       
        14)
            view_saved_config
            ;;

        15)
            update_proxy_tool
            ;;
        16)
            check_and_restart_services
            ;;   
        17)
            Update_certificate
            ;;                       
        18)
            uninstall
            ;;                   
        0)
            echo "感谢使用 Mr. xiao 安装脚本！再见！"
            exit 0
            ;;
        *)
            echo -e "${RED}无效的选择，请重新输入。${NC}"
            main_menu
            ;;
    esac
}

main_menu
