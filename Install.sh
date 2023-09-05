#!/bin/bash

RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

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
        elif command -v iptables >/dev/null 2>&1 && iptables -S | grep -q "INPUT -j DROP"; then
            firewall="iptables"
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
       iptables)
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

            iptables-save > /etc/sysconfig/iptables > /dev/null 2>&1

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

            firewall-cmd --reload > /dev/null 2>&1

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

function create_caddy_folder() {
    local folder="/usr/local/etc/caddy"
    if [[ ! -d "$folder" ]]; then
        mkdir -p "$folder"
    fi
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

function check_config_file_existence() {
    local config_file="/usr/local/etc/sing-box/config.json"
    if [ ! -f "$config_file" ]; then
     echo -e "${RED}sing-box 配置文件不存在，请先搭建节点！${NC}"
      exit 1
    fi
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
        sysctl -p
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
                echo -e "${RED}无效的选择，请重新输入。${NC}"
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

function install_latest_caddy() {
    local architecture=$(uname -m)

    case "$architecture" in
        "x86_64"|"amd64")
            architecture="amd64"
            ;;
        "i686"|"i386")
            architecture="386"
            ;;
        "aarch64"|"arm64")
            architecture="arm64"
            ;;
        "armv5tel")
            architecture="armv5"
            ;;
        "armv6l")
            architecture="armv6"
            ;;
        "armv7l")
            architecture="armv7"
            ;;
        "s390x")
            architecture="s390"
            ;;
        *)
            echo "Unsupported architecture: $architecture"
            exit 1
            ;;
    esac

    local latest_version=$(curl -s https://api.github.com/repos/caddyserver/caddy/releases/latest | grep -o '"tag_name": "v.*"' | cut -d'"' -f4)
    local download_url="https://github.com/caddyserver/caddy/releases/download/$latest_version/caddy_${latest_version:1}_linux_$architecture.tar.gz"

    echo "Downloading Caddy version $latest_version..."
    wget -q -O caddy.tar.gz $download_url
    tar -xf caddy.tar.gz -C /usr/bin/
    chmod +x /usr/bin/caddy
    rm caddy.tar.gz
    
    echo "Caddy has been installed."
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

function configure_caddy_service() {
    echo "Configuring Caddy startup service..."
    local service_file="/etc/systemd/system/caddy.service"

    if [[ -f $service_file ]]; then
        rm "$service_file"
    fi

        local service_config='[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/caddy run --environ --config /usr/local/etc/caddy/caddy.json
ExecReload=/usr/bin/caddy reload --config /usr/local/etc/caddy/caddy.json
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=512
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target'

        echo "$service_config" >"$service_file"
        echo "Caddy startup service has been configured."
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
        password=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 12 | head -n 1)
        echo "随机生成的密码：$password"
    else
        echo "密码：$password"
    fi
}

function read_up_speed() {
    while true; do
        read -p "请输入上行速度 (默认50): " up_mbps
        up_mbps=${up_mbps:-50}

        if [[ $up_mbps =~ ^[0-9]+$ ]]; then
            echo "上行速度设置成功：$up_mbps Mbps"
            break
        else
            echo -e "${RED}错误：请输入数字作为上行速度。${NC}"
        fi
    done
}

function read_down_speed() {
    while true; do
        read -p "请输入下行速度 (默认100): " down_mbps
        down_mbps=${down_mbps:-100}

        if [[ $down_mbps =~ ^[0-9]+$ ]]; then
            echo "下行速度设置成功：$down_mbps Mbps"
            break
        else
            echo -e "${RED}错误：请输入数字作为下行速度。${NC}"
        fi
    done
}

function generate_uuid() {
    if [[ -n $(command -v uuidgen) ]]; then
        command_name="uuidgen"
    elif [[ -n $(command -v uuid) ]]; then
        command_name="uuid -v 4"
    else
        echo -e "${RED}错误：无法生成UUID，请手动设置。${NC}"
        exit 1
    fi

    while true; do
        read -p "请输入UUID（默认随机生成）: " input_uuid
        if [[ -n $input_uuid ]]; then
            if [[ $input_uuid =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
                uuid=$input_uuid
                break
            else
                echo -e "${RED}无效的UUID格式，请重新输入。${NC}"
            fi
        else
            uuid=$($command_name)
            break
        fi
    done

    echo "生成的UUID：$uuid"
}

function generate_transport_config() {
    if [[ "$flow_type" == "xtls-rprx-vision" ]]; then
        transport_config=""
    else
        generate_transport_type
        transport_config='      
      "transport": {
        "type": "'"$transport_type"'"
      },'
    fi
}

function set_short_id() {
    while true; do
        read -p "请输入 short id (默认随机生成): " short_id

        if [[ -z "$short_id" ]]; then
            short_id=$(openssl rand -hex 8)
            break
        elif [[ "$short_id" =~ ^[0-9a-fA-F]{2,8}$ ]]; then
            break
        else
            echo "错误：请输入两到八位的十六进制字符串。"
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

function web_port() {
    while true; do
        read -p "请输入web伪装监听端口 (默认8080): " fallback_port
        fallback_port=${fallback_port:-8080}  

        if [[ "$fallback_port" =~ ^[1-9][0-9]{0,4}$ && $fallback_port -le 65535 ]]; then
            echo "web端口: $fallback_port"
            break
        else       
            echo -e "${RED}错误：端口范围1-65535，请重新输入！${NC}"
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

    local_ip_v4=$(curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org || curl -s https://ifconfig.co/ip || curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
    local_ip_v6=$(ip -o -6 addr show scope global | awk '{split($4, a, "/"); print a[1]; exit}')

    if [[ -n "$local_ip_v4" ]]; then
        echo "$local_ip_v4"
    elif [[ -n "$local_ip_v6" ]]; then
        echo "$local_ip_v6"
    else
        echo "无法获取本机IP地址"
    fi
}

function get_domain() {
    while true; do
        read -p "请输入域名： " domain

        local_ip_v4=$(curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org || curl -s https://ifconfig.co/ip || curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" || curl -s icanhazip.com || curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
        local_ip_v6=$(curl -6 -s https://ifconfig.co/ip || curl -6 -s https://api.myip.com | jq -r '.ip' || ip -o -6 addr show scope global | awk '{split($4, a, "/"); print a[1]; exit}')

        resolved_ipv4=$(dig +short A "$domain" 2>/dev/null)
        resolved_ipv6=$(dig +short AAAA "$domain" 2>/dev/null)

        echo "输入的域名：$domain"
        echo "本地IPv4地址：$local_ip_v4"
        echo "本地IPv6地址：$local_ip_v6"
        echo "解析的IPv4地址：$resolved_ipv4"
        echo "解析的IPv6地址：$resolved_ipv6"

        if [[ -z $domain ]]; then
            echo -e "${RED}错误：域名不能为空，请重新输入。${NC}"
        else
            if [[ ("$resolved_ipv4" == "$local_ip_v4" && ! -z "$resolved_ipv4") || ("$resolved_ipv6" == "$local_ip_v6" && ! -z "$resolved_ipv6") ]]; then
                break
            else
                resolved_ip=$(ping "$domain" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
                echo "解析的IP地址（ping）：$resolved_ip"
                if [[ ("$resolved_ipv4" == "$local_ip_v4" && ! -z "$resolved_ipv4") || ("$resolved_ipv6" == "$local_ip_v6" && ! -z "$resolved_ipv6") ]]; then
                    break
                else
                    echo -e "${RED}错误：域名未绑定本机IP，请重新输入。${NC}"
                fi
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
            echo -e "${RED}伪装网址无效或不可用，请重新输入。${NC}"
        fi
    done
}

function test_caddy_config() {
    echo "Testing Caddy configuration file..."
    local output
    local caddy_pid

    output=$(timeout 8 /usr/bin/caddy run --environ --config /usr/local/etc/caddy/caddy.json 2>&1 &)
    caddy_pid=$!

    wait $caddy_pid 2>/dev/null

    if echo "$output" | grep -i "error"; then
        echo -e "${RED}Caddy configuration test failed. Please check the configuration file.${NC}"
        echo "$output" | grep -i "error" --color=always 
    else
        echo "Caddy configuration test passed."
    fi
}

function set_certificate_and_private_key() {
    while true; do
        read -p "请输入证书路径 (默认/etc/ssl/private/cert.crt): " certificate_path
        certificate_path=${certificate_path:-"/etc/ssl/private/cert.crt"}

        if [[ "$certificate_path" != "/etc/ssl/private/cert.crt" && (! -f "$certificate_path" || ${certificate_path: -4} != ".crt") ]]; then
            echo -e "${RED}错误：证书文件不存在，请重新输入。${NC}"
        else
            break
        fi
    done

    while true; do
        read -p "请输入私钥路径 (默认/etc/ssl/private/private.key): " private_key_path
        private_key_path=${private_key_path:-"/etc/ssl/private/private.key"}

        if [[ "$private_key_path" != "/etc/ssl/private/private.key" && (! -f "$private_key_path" || ${private_key_path: -4} != ".key") ]]; then
            echo -e "${RED}错误：私钥文件不存在，请重新输入。${NC}"
        else
            break
        fi
    done
}

function apply_certificate() {
    local domain="$1"
    local has_ipv4=false

    if curl -s4 ifconfig.co &>/dev/null; then
        has_ipv4=true
    fi
    
    echo "Requesting a certificate..."
    curl -s https://get.acme.sh | sh -s email=example@gmail.com
    alias acme.sh=~/.acme.sh/acme.sh
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    if $has_ipv4; then
        ~/.acme.sh/acme.sh --issue -d "$domain" --standalone
    else
        ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --listen-v6
    fi

    echo "Installing the certificate..."
    certificate_path=$(~/.acme.sh/acme.sh --install-cert -d "$domain" --ecc --key-file "$private_key_path" --fullchain-file "$certificate_path")

    set_certificate_path="$certificate_path"
    set_private_key_path="$private_key_path"
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

function encryption_method() {
    while true; do
        read -p "请选择加密方式(默认3)：
1). 2022-blake3-aes-128-gcm
2). 2022-blake3-aes-256-gcm
3). 2022-blake3-chacha20-poly1305
请选择[1-3]: " encryption_choice
        encryption_choice=${encryption_choice:-3}

        case $encryption_choice in
            1)
                ss_method="2022-blake3-aes-128-gcm"
                ss_password=$(sing-box generate rand --base64 16)
                shadowtls_password=$(openssl rand -base64 16)
                break
                ;;
            2)
                ss_method="2022-blake3-aes-256-gcm"
                ss_password=$(sing-box generate rand --base64 32)
                shadowtls_password=$(openssl rand -base64 32)
                break
                ;;
            3)
                ss_method="2022-blake3-chacha20-poly1305"
                ss_password=$(sing-box generate rand --base64 32)
                shadowtls_password=$(openssl rand -base64 32)
                break
                ;;
            *)
                echo -e "${RED}错误：无效的选择，请重新输入。${NC}"
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
            echo -e "${RED}错误：无效的选择，请重新输入!${NC}"
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
                echo -e "${RED}错误：无效的选择，请重新输入。${NC}"
                ;;
        esac
    done
}

function ask_certificate_option() {
    while true; do
        read -p "请选择证书来源：
1). 自动申请证书
2). 自备证书
请选择[1-2]: " certificate_option

        case $certificate_option in
            1)
                echo "You have chosen to automatically request a certificate."
                apply_certificate "$domain" "$private_key_path" "$certificate_path"
                break
                ;;
            2)
                echo "You have chosen to use your own certificate."
                break
                ;;

            *)
                echo -e "${RED}错误：无效的选择，请重新输入。${NC}"
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

function select_flow_type() {
    while true; do
        read -p "请选择节点类型 (默认1)：
1). vless+vision+reality
2). vless+h2/grpc+reality
请选择[1-2]: " flow_option

        case $flow_option in
            "" | 1)
                flow_type="xtls-rprx-vision"
                break
                ;;
            2)
                flow_type=""
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
        echo "请选择传输层协议（默认1）："
        echo "1). TCP（trojan+tcp+tls+web）"
        echo "2). ws（trojan+ws+tls+CDN）"

        read -p "请选择 [1-2]: " setup_type
        if [ -z "$setup_type" ]; then
            setup_type="1"
        fi

        case $setup_type in
            1)
                transport_removed=true
                fallback_removed=false
                break
                ;;
            2)
                transport_removed=false
                fallback_removed=true
                break
                ;;
            *)
                echo -e "${RED}无效的选择，请重新输入!${NC}"
                ;;
        esac
    done
}

function generate_transport_type() {
    while true; do
        read -p "请选择传输层协议(默认1)：
1). http
2). grpc
请选择[1-2]: " transport_option

        case $transport_option in
            1)
                transport_type="http"
                break
                ;;
            2)
                transport_type="grpc"
                break
                ;;
            "")
                transport_type="http"
                break
                ;;                
            *)
                echo -e "${RED}错误的选项，请重新输入！${NC}" >&2
                ;;
        esac
    done
}

function configure_short_ids() {
    short_ids="\"$(openssl rand -hex 7)\""
    current_length=7

    while true; do
        read -p "是否继续添加 short id？(Y/N，默认N): " choice
        choice=${choice,,}  
        
        if [[ "$choice" == "y" ]]; then
            set_short_id
            current_length=$((current_length - 1))
            if [[ "$current_length" -ge 1 ]]; then
                short_ids+=$',\n            "'$(openssl rand -hex "$current_length")'"'
            else
                break
            fi
        elif [[ "$choice" == "n" || -z "$choice" ]]; then
            break
        else
            echo "错误：请输入 'Y' 或 'N'。"
        fi
    done

    short_ids+=$''
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
            echo -e "${RED}无效的输入，请重新输入。${NC}"
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
            echo -e "${RED}无效的输入，请重新输入。${NC}"
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
            echo -e "${RED}无效的输入，请重新输入。${NC}"
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
            echo -e "${RED}无效的输入，请重新输入。${NC}"
        fi
    done

    users+=$'\n      ]'
}

function add_shadowtls_user() {
    local user_password=""
    if [[ $encryption_choice == 2 || $encryption_choice == 3 ]]; then
        user_password=$(openssl rand -base64 32)
    elif [[ $encryption_choice == 1 ]]; then
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
            echo -e "${RED}无效的输入，请重新输入。${NC}"
        fi
    done

    users+=$'\n      ]'
}

function prompt_and_generate_transport_config() {    
    if [[ $setup_type == 2 ]]; then
        read -p "请输入 ws 路径 (默认随机生成): " transport_path_input
        transport_path=${transport_path_input:-/$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)}

        if [[ ! "$transport_path" =~ ^/ ]]; then
            transport_path="/$transport_path"
        fi

        echo ",
      \"transport\": {
        \"type\": \"ws\",
        \"path\": \"$transport_path\"
      }"
    fi

    if [[ $setup_type == 1 ]]; then
        echo ",
      \"fallback\": {
        \"server\": \"127.0.0.1\",
        \"server_port\": $fallback_port
      }"
    fi
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

  if ! grep -q '"log": {' "$config_file" || ! grep -q '"inbounds": \[' "$config_file" || ! grep -q '"outbounds": \[' "$config_file"; then
    echo -e '{\n  "log": {\n  },\n  "inbounds": [\n  ],\n  "outbounds": [\n  ]\n}' > "$config_file"
    sed -i '/"log": {/!b;n;c\    "disabled": false,\n    "level": "info",\n    "timestamp": true\n  },' "$config_file"
    sed -i '/"outbounds": \[/!b;n;c\    {\n      "type": "direct",\n      "tag": "direct"\n    }\n  ]' "$config_file"
  fi
}

function modify_format_inbounds() {
    file_path="/usr/local/etc/sing-box/config.json"
    start_line=$(grep -n '"outbounds": \[' "$file_path" | cut -d: -f1)

    if [ -n "$start_line" ]; then
        line_to_modify_1=$((start_line - 2))
        line_to_modify_2=$((start_line - 1))

        if [ "$line_to_modify_1" -ge 1 ]; then
            sed -i "$line_to_modify_1 s/.*/    }/" "$file_path"
            sed -i "$line_to_modify_2 s/.*/  ],/" "$file_path"
        fi
    fi
}

function generate_Direct_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    awk -v listen_port="$listen_port" -v target_address="$target_address" -v override_port="$override_port" '
        /"inbounds": \[/{found=1}
        {print}
        found && /"inbounds": \[/{print "    {"; print "      \"type\": \"direct\","; print "      \"tag\": \"direct-in\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"sniff_timeout\": \"300ms\","; print "      \"proxy_protocol\": false,"; print "      \"network\": \"tcp\","; print "      \"override_address\": \"" target_address "\","; print "      \"override_port\": " override_port; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_ss_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    awk -v listen_port="$listen_port" -v ss_method="$ss_method" -v ss_password="$ss_password" '
        /"inbounds": \[/{found=1}
        {print}
        found && /"inbounds": \[/{print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"ss-in\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"method\": \"" ss_method "\","; print "      \"password\": \"" ss_password "\""; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_naive_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local certificate=""
    local private_key="" 
    listen_port
    set_username
    set_password    
    naive_multiple_users
    get_domain    
    set_certificate_and_private_key
    certificate_path="$certificate_path"
    private_key_path="$private_key_path"

    awk -v listen_port="$listen_port" -v users="$users" -v domain="$domain" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" '
        /"inbounds": \[/{found=1}
        {print}
        found && /"inbounds": \[/{print "    {"; print "      \"type\": \"naive\","; print "      \"tag\": \"naive-in\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"users\": " users ","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" domain "\","; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\""; print "      }"; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_tuic_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local certificate=""
    local private_key=""    
    listen_port
    set_username
    set_password
    generate_uuid
    tuic_multiple_users    
    set_congestion_control
    get_domain
    set_certificate_and_private_key
    certificate_path="$certificate_path"
    private_key_path="$private_key_path"

    awk -v listen_port="$listen_port" -v users="$users" -v congestion_control="$congestion_control" -v domain="$domain" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" '
        /"inbounds": \[/{found=1}
        {print}
        found && /"inbounds": \[/{print "    {"; print "      \"type\": \"tuic\","; print "      \"tag\": \"tuic-in\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"users\": " users ","; print "      \"congestion_control\": \"" congestion_control "\","; print "      \"auth_timeout\": \"3s\","; print "      \"zero_rtt_handshake\": false,"; print "      \"heartbeat\": \"10s\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" domain "\","; print "        \"alpn\": ["; print "          \"h3\""; print "        ],"; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\""; print "      }"; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_Hysteria_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local certificate=""
    local private_key="" 
    listen_port
    read_up_speed
    read_down_speed
    set_username
    set_password    
    hysteria_multiple_users 
    get_domain   
    set_certificate_and_private_key
    certificate_path="$certificate_path"
    private_key_path="$private_key_path"

    awk -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v users="$users" -v domain="$domain" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" '
        /"inbounds": \[/{found=1}
        {print}
        found && /"inbounds": \[/{print "    {"; print "      \"type\": \"hysteria\","; print "      \"tag\": \"hysteria-in\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"up_mbps\": " up_mbps ","; print "      \"down_mbps\": " down_mbps ","; print "      \"users\": " users ","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" domain "\","; print "        \"alpn\": ["; print "          \"h3\""; print "        ],"; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\""; print "      }"; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_shadowtls_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local users=""    
    listen_port
    encryption_method
    add_shadowtls_user
    add_multiple_shadowtls_users
    generate_target_server

    awk -v listen_port="$listen_port" -v users="$users" -v target_server="$target_server" -v ss_method="$ss_method" -v ss_password="$ss_password" '
        /"inbounds": \[/{found=1}
        {print}
        found && /"inbounds": \[/{print "    {"; print "      \"type\": \"shadowtls\","; print "      \"tag\": \"st-in\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"version\": 3,"; print "      \"users\": [" users ""; print "      ],"; print "      \"handshake\": {"; print "        \"server\": \"" target_server "\","; print "        \"server_port\": 443"; print "      },"; print "      \"strict_mode\": true,"; print "      \"detour\": \"stls-in\""; print "    },"; print "    {"; print "      \"type\": \"shadowsocks\","; print "      \"tag\": \"stls-in\","; print "      \"listen\": \"127.0.0.1\","; print "      \"network\": \"tcp\","; print "      \"method\": \"" ss_method "\","; print "      \"password\": \"" ss_password "\""; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_juicity_config() {
    local config_file="/usr/local/etc/juicity/config.json"
    local users=""
    local certificate=""
    local private_key=""
    
    listen_port
    generate_uuid
    set_password
    users="\"$uuid\": \"$password\""
    get_domain 
    set_certificate_and_private_key
    certificate_path="$certificate_path"
    private_key_path="$private_key_path"
    set_congestion_control

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
    listen_port
    select_flow_type
    generate_uuid
    generate_transport_config
    generate_server_name
    generate_target_server
    generate_private_key
    set_short_id
    configure_short_ids

    awk -v listen_port="$listen_port" -v uuid="$uuid" -v flow_type="$flow_type" -v transport_config="$transport_config" -v server_name="$server_name" -v target_server="$target_server" -v private_key="$private_key" -v short_id="$short_id" -v short_ids="$short_ids" '
        /"inbounds": \[/{found=1}
        {print}
        found && /"inbounds": \[/{print "    {"; print "      \"type\": \"vless\","; print "      \"tag\": \"vless-in\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"users\": ["; print "        {"; print "          \"uuid\": \"" uuid "\","; print "          \"flow\": \"" flow_type "\""; print "        }"; print "      ], " transport_config; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" server_name "\","; print "        \"reality\": {"; print "          \"enabled\": true,"; print "          \"handshake\": {"; print "            \"server\": \"" target_server "\","; print "            \"server_port\": 443"; print "          },"; print "          \"private_key\": \"" private_key "\","; print "          \"short_id\": ["; print "            \"" short_id "\","; print "            " short_ids; print "          ]"; print "        }"; print "      }"; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_Hy2_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local certificate=""
    local private_key="" 
    listen_port
    read_up_speed
    read_down_speed
    set_username
    set_password    
    hy2_multiple_users
    get_fake_domain
    get_domain   
    set_certificate_and_private_key
    certificate_path="$certificate_path"
    private_key_path="$private_key_path"

    awk -v listen_port="$listen_port" -v up_mbps="$up_mbps" -v down_mbps="$down_mbps" -v users="$users" -v fake_domain="$fake_domain" -v domain="$domain" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" '
        /"inbounds": \[/{found=1}
        {print}
        found && /"inbounds": \[/{print "    {"; print "      \"type\": \"hysteria2\","; print "      \"tag\": \"hy2-in\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"up_mbps\": " up_mbps ","; print "      \"down_mbps\": " down_mbps ","; print "      \"users\": " users ","; print "      "; print "      \"ignore_client_bandwidth\": false,"; print "      \"masquerade\": \"https://" fake_domain "\","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" domain "\","; print "        \"alpn\": ["; print "          \"h3\""; print "        ],"; print "        \"certificate_path\": \"" certificate_path "\","; print "        \"key_path\": \"" private_key_path "\""; print "      }"; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
}

function generate_trojan_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
        
    awk -v listen_port="$listen_port" -v users="$users" -v domain="$domain" -v certificate_path="$certificate_path" -v private_key_path="$private_key_path" -v transport_and_fallback_config="$transport_and_fallback_config" '
        /"inbounds": \[/{found=1}
        {print}
        found && /"inbounds": \[/{print "    {"; print "      \"type\": \"trojan\","; print "      \"tag\": \"trojan-in\","; print "      \"listen\": \"::\","; print "      \"listen_port\": " listen_port ","; print "      \"sniff\": true,"; print "      \"sniff_override_destination\": true,"; print "      \"users\": " users ","; print "      \"tls\": {"; print "        \"enabled\": true,"; print "        \"server_name\": \"" domain "\","; print "        \"alpn\": ["; print "          \"h2\","; print "          \"http/1.1\""; print "        ],"; print "        \"certificate_path\": \"/etc/ssl/certificates/acme-v02.api.letsencrypt.org-directory/" domain "/" domain ".crt\","; print "        \"key_path\": \"/etc/ssl/certificates/acme-v02.api.letsencrypt.org-directory/" domain "/" domain ".key\""; print "      }" transport_and_fallback_config; print "    },"; found=0}
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
} 
  
function generate_caddy_config() {
    local caddy_config="/usr/local/etc/caddy/caddy.json"

    awk -v fallback_port="$fallback_port" -v fake_domain="$fake_domain" -v domain="$domain" '
        BEGIN {
            print "{"
            print "  \"logging\": {"
            print "    \"logs\": {"
            print "      \"default\": {"
            print "        \"writer\": {"
            print "          \"output\": \"file\","
            print "          \"filename\": \"/var/log/caddy.log\""
            print "        },"
            print "        \"level\": \"WARN\""
            print "      }"
            print "    }"
            print "  },"
            print "  \"storage\": {"
            print "    \"module\": \"file_system\","
            print "    \"root\": \"/etc/ssl\""
            print "  },"
            print "  \"apps\": {"
            print "    \"http\": {"
            print "      \"servers\": {"
            print "        \"h1\": {"
            print "          \"listen\": [\":80\"],"
            print "          \"routes\": ["
            print "            {"
            print "              \"handle\": ["
            print "                {"
            print "                  \"handler\": \"static_response\","
            print "                  \"headers\": {"
            print "                    \"Location\": [\"https://{http.request.host}{http.request.uri}\"]"
            print "                  },"
            print "                  \"status_code\": 301"
            print "                }"
            print "              ]"
            print "            }"
            print "          ],"
            print "          \"protocols\": [\"h1\"]"
            print "        },"
            print "        \"h1h2c\": {"
            print "          \"listen\": [\"127.0.0.1:" fallback_port "\"],"
            print "          \"routes\": ["
            print "            {"
            print "              \"handle\": ["
            print "                {"
            print "                  \"handler\": \"headers\","
            print "                  \"response\": {"
            print "                    \"set\": {"
            print "                      \"Strict-Transport-Security\": [\"max-age=31536000; includeSubDomains; preload\"]"
            print "                    }"
            print "                  }"
            print "                },"
            print "                {"
            print "                  \"handler\": \"reverse_proxy\","
            print "                  \"headers\": {"
            print "                    \"request\": {"
            print "                      \"set\": {"
            print "                        \"Host\": [\"{http.reverse_proxy.upstream.hostport}\"],"
            print "                        \"X-Forwarded-Host\": [\"{http.request.host}\"]"
            print "                      }"
            print "                    }"
            print "                  },"
            print "                  \"transport\": {"
            print "                    \"protocol\": \"http\","
            print "                    \"tls\": {}"
            print "                  },"
            print "                  \"upstreams\": [{\"dial\": \"" fake_domain ":443\"}]"
            print "                }"
            print "              ]"
            print "            }"
            print "          ],"
            print "          \"protocols\": [\"h1\",\"h2c\"]"
            print "        }"
            print "      }"
            print "    },"
            print "    \"tls\": {"
            print "      \"certificates\": {"
            print "        \"automate\": [\"" domain "\"]"
            print "      },"
            print "      \"automation\": {"
            print "        \"policies\": ["
            print "          {"
            print "            \"issuers\": ["
            print "              {"
            print "                \"module\": \"acme\""
            print "              }"
            print "            ]"
            print "          }"
            print "        ]"
            print "      }"
            print "    }"
            print "  }"
            print "}"
        }
    ' > "$caddy_config"
}

function update_route_file() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local geosite_list=$(IFS=,; echo "${geosite[*]}") 
    local geosite_formatted=$(sed 's/,/,\\n          /g' <<< "$geosite_list") 

    sed -i '/"log": {/!b;n;/"/!b;n;/"/!b;n;/"/!b;n;a\
  "route": {\
    "rules": [\
      {\
        "geosite": [\
          '"$geosite_formatted"'\
        ],\
        "outbound": "'$1'"\
      }\
    ]\
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
                print "    {"
                print "      \"type\": \"direct\","
                print "      \"tag\": \"warp-IPv4-out\","
                print "      \"detour\": \"wireguard-out\","
                print "      \"domain_strategy\": \"ipv4_only\""
                print "    },"
                print "    {"
                print "      \"type\": \"direct\","
                print "      \"tag\": \"warp-IPv6-out\","
                print "      \"detour\": \"wireguard-out\","
                print "      \"domain_strategy\": \"ipv6_only\""
                print "    },"
                print "    {"
                print "      \"type\": \"wireguard\","
                print "      \"tag\": \"wireguard-out\","
                print "      \"server\": \"" server "\","
                print "      \"server_port\": " server_port ","
                print "      \"system_interface\": false,"
                print "      \"interface_name\": \"wg0\","
                print "      \"local_address\": ["
                print "        \"" local_address_ipv4 "\","
                print "        \"" local_address_ipv6 "\""
                print "      ],"
                print "      \"private_key\": \"" private_key "\","
                print "      \"peer_public_key\": \"" peer_public_key "\","
                print "      \"reserved\": " reserved ","
                print "      \"mtu\": " mtu
                print "    }"
            } else {
                print $0
            }
        }
    ' "$config_file" > "$config_file.tmp"
    mv "$config_file.tmp" "$config_file"
    echo "warp配置完成。"
}

function display_reality_config() {
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
    echo "传输层协议: $transport_type" | tee -a "$output_file"
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

function display_trojan_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"  
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")
    local passwords=($(jq -r '.inbounds[0].users[].password' "$config_file"))
    local password_list=""
    for password in "${passwords[@]}"; do
        password_list+="\n$password"
    done
    local alpn=$(jq -r '.inbounds[0].tls.alpn | join(", ")' "$config_file")
    local transport_type=$(jq -r '.inbounds[0].transport.type' "$config_file")
    local transport_path=$(jq -r '.inbounds[0].transport.path' "$config_file")

    echo -e "${CYAN}trojan 节点配置信息：${NC}"  | tee -a "$output_file"
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file" 
    echo "地址: $server_name"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "监听端口: $listen_port"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo -e "密码:$password_list"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "ALPN: $alpn"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    if [ "$transport_type" != "null" ]; then
        echo "传输协议: $transport_type"  | tee -a "$output_file"
        echo "路径: $transport_path"  | tee -a "$output_file"
    else
        echo "传输协议: tcp"  | tee -a "$output_file"
    fi
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file" 
    echo "配置信息已保存至 $output_file"
}

function display_tuic_config() {
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

function display_Hysteria_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local server_name=$(jq -r '.inbounds[0].tls.server_name' "$config_file")      
    local alpn=$(jq -r '.inbounds[0].tls.alpn[0]' "$config_file")
    echo -e "${CYAN}Hysteria 节点配置信息：${NC}"  | tee -a "$output_file"
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
        local auth_str=$(echo "$users" | jq -r ".[$i].auth_str")
        echo "用户$i: $auth_str"  | tee -a "$output_file"
    done
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file"  
    echo "配置信息已保存至 $output_file"
}

function display_Hy2_config() {
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

function display_shadowtls_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local local_ip
    local_ip=$(get_local_ip)    
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")       
    local shadowtls_passwords=$(jq -r '.inbounds[0].users[] | "ShadowTLS 密码: \(.password)"' "$config_file")
    local user_input=$(jq -r '.inbounds[0].handshake.server' "$config_file")
    local ss_password=$(jq -r '.inbounds[1].password' "$config_file")    

    echo -e "${CYAN}ShadowTLS 节点配置信息：${NC}" | tee -a "$output_file"
    echo -e "${CYAN}================================================================${NC}" | tee -a "$output_file"
    echo "服务器地址: $local_ip" | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "监听端口: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "$shadowtls_passwords" | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "Shadowsocks 密码: $ss_password" | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}" | tee -a "$output_file"
    echo "握手服务器地址: $user_input" | tee -a "$output_file"
    echo -e "${CYAN}================================================================${NC}" | tee -a "$output_file"
    echo "配置信息已保存至 $output_file"
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

function display_Shadowsocks_config() {
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

function display_NaiveProxy_config() {
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

    if [ -f "/etc/systemd/system/caddy.service" ]; then
        systemctl reload caddy.service
        systemctl status --no-pager caddy.service
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
    systemctl daemon-reload
    echo "sing-box 卸载完成。"
}

function uninstall_caddy() {
    echo "开始卸载 caddy..."
    systemctl stop caddy
    systemctl disable caddy
    rm -rf /etc/systemd/system/caddy.service
    rm -rf /usr/local/etc/caddy
    rm -rf /usr/bin/caddy
    systemctl daemon-reload
    echo "caddy 卸载完成。"
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
    
    if [ -e /usr/bin/caddy ]; then
        install_latest_caddy
    fi

    if [ -e /usr/local/bin/sing-box ]; then
        select_sing_box_install_option
    fi
}

function uninstall() {
    local uninstall_sing_box=false
    local uninstall_caddy=false
    local uninstall_juicity=false

    if [[ -f "/etc/systemd/system/sing-box.service" ]] || [[ -f "/usr/local/bin/sing-box" ]] || [[ -d "/usr/local/etc/sing-box/" ]]; then
        uninstall_sing_box=true
    fi
    
    if [[ -f "/etc/systemd/system/caddy.service" ]] || [[ -f "/usr/bin/caddy" ]] || [[ -d "/usr/local/etc/caddy" ]]; then
        uninstall_caddy=true
    fi

    if [[ -f "/etc/systemd/system/juicity.service" ]] || [[ -f "/usr/local/bin/juicity-server" ]] || [[ -d "/usr/local/etc/juicity/" ]]; then
        uninstall_juicity=true
    fi

    if [[ "$uninstall_sing_box" == true ]]; then
        uninstall_sing_box
    fi

    if [[ "$uninstall_caddy" == true ]]; then
        uninstall_caddy
    fi

    if [[ "$uninstall_juicity" == true ]]; then
        uninstall_juicity
    fi    
}


function check_vless_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    
    if grep -Pzo '"tag": "vless-in"[^}]*' "$config_file" > /dev/null; then
        echo -e "${RED}vless 已安装，请选择其它协议或卸载后重新运行脚本！${NC}"
        exit 1
    fi
}

function check_tuic_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    
    if grep -Pzo '"tag": "tuic-in"[^}]*' "$config_file" > /dev/null; then
        echo -e "${RED}TUIC 已安装，请选择其它协议或卸载后重新运行脚本！${NC}"
        exit 1
    fi
}

function check_direct_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    
    if grep -Pzo '"tag": "direct-in"[^}]*' "$config_file" > /dev/null; then
        echo -e "${RED}Direct 已安装，请选择其它协议或卸载后重新运行脚本！${NC}"
        exit 1
    fi
}

function check_trojan_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    
    if grep -Pzo '"tag": "trojan-in"[^}]*' "$config_file" > /dev/null; then
        echo -e "${RED}Trojan 已安装，请选择其它协议或卸载后重新运行脚本！${NC}"
        exit 1
    fi
}

function check_hysteria_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    
    if grep -Pzo '"tag": "hysteria-in"[^}]*' "$config_file" > /dev/null; then
        echo -e "${RED}Hysteria 已安装，请选择其它协议或卸载后重新运行脚本！${NC}"
        exit 1
    fi
}

function check_hy2_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    
    if grep -Pzo '"tag": "hy2-in"[^}]*' "$config_file" > /dev/null; then
        echo -e "${RED}Hysteria2 已安装，请选择其它协议或卸载后重新运行脚本！${NC}"
        exit 1
    fi
}

function check_shadowtls_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    
    if grep -Pzo '"tag": "st-in"[^}]*' "$config_file" > /dev/null; then
        echo -e "${RED}ShadowTLS 已安装，请选择其它协议或卸载后重新运行脚本！${NC}"
        exit 1
    fi
}

function check_naive_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    
    if grep -Pzo '"tag": "naive-in"[^}]*' "$config_file" > /dev/null; then
        echo -e "${RED}NaiveProxy 已安装，请选择其它协议或卸载后重新运行脚本！${NC}"
        exit 1
    fi
}

function check_Shadowsocks_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    
    if grep -Pzo '"tag": "ss-in"[^}]*' "$config_file" > /dev/null; then
        echo -e "${RED}Shadowsocks 已安装，请选择其它协议或卸载后重新运行脚本！${NC}"
        exit 1
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
    check_firewall_configuration 
    ask_certificate_option
    configure_juicity_service
    systemctl daemon-reload
    systemctl enable juicity.service
    systemctl start juicity.service
    systemctl restart juicity.service
    display_juicity_config
}

function Direct_install() {
    install_sing_box
    check_direct_config
    log_outbound_config    
    listen_port
    override_address
    override_port
    generate_Direct_config
    modify_format_inbounds
    check_firewall_configuration 
    systemctl daemon-reload   
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_Direct_config
}

function Shadowsocks_install() {
    install_sing_box
    check_Shadowsocks_config
    log_outbound_config    
    listen_port
    encryption_method
    generate_ss_config
    modify_format_inbounds
    check_firewall_configuration 
    systemctl daemon-reload   
    systemctl enable sing-box   
    systemctl start sing-box
    systemctl restart sing-box
    display_Shadowsocks_config
}

function NaiveProxy_install() {
    install_sing_box
    check_naive_config  
    log_outbound_config        
    generate_naive_config
    modify_format_inbounds    
    check_firewall_configuration   
    ask_certificate_option 
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_NaiveProxy_config
}

function tuic_install() {
    install_sing_box 
    check_tuic_config
    log_outbound_config    
    generate_tuic_config
    modify_format_inbounds    
    check_firewall_configuration 
    ask_certificate_option
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_tuic_config
}

function Hysteria_install() {
    install_sing_box  
    check_hysteria_config
    log_outbound_config    
    generate_Hysteria_config
    modify_format_inbounds    
    check_firewall_configuration 
    ask_certificate_option 
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_Hysteria_config
}

function Hysteria2_install() {
    install_sing_box  
    check_hy2_config
    log_outbound_config    
    generate_Hy2_config
    modify_format_inbounds    
    check_firewall_configuration 
    ask_certificate_option 
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_Hy2_config
}

function shadowtls_install() {
    install_sing_box 
    check_shadowtls_config
    log_outbound_config 
    generate_shadowtls_config
    modify_format_inbounds    
    check_firewall_configuration      
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_shadowtls_config
}

function reality_install() {
    install_sing_box 
    check_vless_config
    log_outbound_config         
    generate_reality_config 
    modify_format_inbounds     
    check_firewall_configuration              
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl restart sing-box
    display_reality_config
}

function trojan_install() {
    install_sing_box
    check_trojan_config 
    install_latest_caddy
    configure_caddy_service     
    create_caddy_folder      
    log_outbound_config 
    prompt_setup_type  
    listen_port
    set_password
    trojan_multiple_users     
    web_port
    get_fake_domain
    get_domain 
    generate_caddy_config
    transport_and_fallback_config=$(prompt_and_generate_transport_config)                  
    check_firewall_configuration
    test_caddy_config       
    generate_trojan_config
    modify_format_inbounds 
    check_firewall_configuration
    systemctl daemon-reload
    systemctl enable caddy        
    systemctl enable sing-box 
    systemctl start caddy
    systemctl start sing-box
    systemctl restart caddy
    systemctl restart sing-box
    display_trojan_config
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

function main_menu() {
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo -e "║ ${CYAN}作者${NC}： Mr. xiao                                                        ║"
echo -e "║ ${CYAN}项目地址${NC}: https://github.com/TinrLin                                   ║"
echo -e "║ ${CYAN}Telegram 群组${NC}: https://t.me/mrxiao758                                  ║"
echo -e "║ ${CYAN}YouTube频道${NC}: https://youtube.com/@Mr_xiao502                           ║"
echo "╠════════════════════════════════════════════════════════════════════════╣"
echo "║ 请选择要执行的操作：                                                   ║"
echo -e "║${CYAN} [1]${NC}  TUIC                   ${CYAN} [2]${NC}  Juicity                              ║"
echo -e "║${CYAN} [3]${NC}  Vless                  ${CYAN} [4]${NC}  Direct                               ║"
echo -e "║${CYAN} [5]${NC}  Trojan                 ${CYAN} [6]${NC}  Hysteria                             ║"
echo -e "║${CYAN} [7]${NC}  ShadowTLS              ${CYAN} [8]${NC}  NaiveProxy                           ║"
echo -e "║${CYAN} [9]${NC}  Shadowsocks            ${CYAN} [10]${NC} WireGuard                            ║"
echo -e "║${CYAN} [11]${NC} Hysteria2              ${CYAN} [12]${NC} 查看节点信息                         ║"
echo -e "║${CYAN} [13]${NC} 重启服务               ${CYAN} [14]${NC} 更新代理工具                         ║"
echo -e "║${CYAN} [15]${NC} 卸载                   ${CYAN} [0]${NC}  退出                                 ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"

    local choice
    read -p "请选择 [0-15]: " choice

    case $choice in
        1)
            tuic_install
            ;;
        2)
            juicity_install
            ;;            
        3)
            reality_install
            ;;
        4)
            Direct_install
            ;;
        5)
            trojan_install
            ;;                
        6)
            Hysteria_install
            ;;
        7)
            shadowtls_install
            ;;
        8)
            NaiveProxy_install
            ;;
        9)
            Shadowsocks_install
            ;; 
        10)
            wireguard_install
            ;;  
        11)
            Hysteria2_install
            ;;                           
        12)
            view_saved_config
            ;;

        13)
            check_and_restart_services
            ;;
        14)
            update_proxy_tool
            ;;             
        15)
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
