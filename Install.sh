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

            local ports=("$listen_port" "$override_port" "$fallback_port" "80")

            if ! ufw status | grep -q "Status: active" > /dev/null 2>&1; then
                ufw enable > /dev/null
            fi

            for port in "${ports[@]}"; do
                if ! ufw status | grep -q " $port" > /dev/null 2>&1; then
                    ufw allow "$port" > /dev/null
                fi
            done

            ufw reload > /dev/null
            echo "Firewall configuration has been updated."
            ;;

        iptables)

            local port_protocols=("tcp" "udp")
            local ports=("$listen_port" "$override_port" "$fallback_port" "80")

            for protocol in "${port_protocols[@]}"; do
                for port in "${ports[@]}"; do
                    if ! iptables -C INPUT -p "$protocol" --dport "$port" -j ACCEPT >/dev/null 2>&1; then
                        iptables -A INPUT -p "$protocol" --dport "$port" -j ACCEPT >/dev/null 2>&1
                    fi
                done
            done

            iptables-save > /etc/sysconfig/iptables > /dev/null 2>&1
            echo "iptables firewall configuration has been updated."
            ;;

        firewalld)
        
            local ports=("$listen_port" "$override_port" "$fallback_port" "80")

            for port in "${ports[@]}"; do
                if ! firewall-cmd --zone=public --list-ports | grep -q "$port/tcp" > /dev/null 2>&1; then
                    firewall-cmd --zone=public --add-port="$port/tcp" --permanent > /dev/null 2>&1
                fi

                if ! firewall-cmd --zone=public --list-ports | grep -q "$port/udp" > /dev/null 2>&1; then
                    firewall-cmd --zone=public --add-port="$port/udp" --permanent > /dev/null 2>&1
                fi
            done

            firewall-cmd --reload > /dev/null 2>&1
            echo "firewalld firewall configuration has been updated."
            ;;
    esac
}

function check_sing_box_folder() {
    local folder="/usr/local/etc/sing-box"
    if [[ ! -d "$folder" ]]; then
        mkdir -p "$folder"
    fi
}

function check_caddy_folder() {
    local folder="/usr/local/etc/caddy"
    if [[ ! -d "$folder" ]]; then
        mkdir -p "$folder"
    fi
}

function create_tuic_directory() {
    local tuic_directory="/usr/local/etc/tuic"
    local ssl_directory="/etc/ssl/private"
    
    if [[ ! -d "$tuic_directory" ]]; then
        mkdir -p "$tuic_directory"
    fi
    
    if [[ ! -d "$ssl_directory" ]]; then
        mkdir -p "$ssl_directory"
    fi
}

function check_juicity_folder() {
    local folder="/usr/local/etc/juicity"
    if [[ ! -d "$folder" ]]; then
        mkdir -p "$folder"
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
        echo "请选择 sing-box 的安装方式："
        echo "1). 编译安装sing-box（支持全部功能）"
        echo "2). 下载安装sing-box（支持部分功能）"

        local install_option
        read -p "请选择 [1-2]: " install_option

        case $install_option in
            1)
                install_go
                compile_install_sing_box
                break
                ;;
            2)
                install_latest_sing_box
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

function download_juicity() {
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

function install_caddy() {
    echo "Installing xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    ~/go/bin/xcaddy build --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive
    setcap cap_net_bind_service=+ep ./caddy

    mv caddy /usr/bin/
    echo "Caddy installation completed."
}

function download_tuic() {
    local repo="EAimTY/tuic"
    local arch=$(uname -m)

    case "$arch" in
        x86_64)
            arch="x86_64-unknown-linux-gnu"
            ;;
        i686)
            arch="i686-unknown-linux-gnu"
            ;;
        aarch64)
            arch="aarch64-unknown-linux-gnu"
            ;;
        armv7l)
            arch="armv7-unknown-linux-gnueabihf"
            ;;
        *)
            echo -e "${RED}不支持的架构: $arch${NC}"
            exit 1
            ;;
    esac

    local releases_url="https://api.github.com/repos/$repo/releases/latest"
    local download_url=$(curl -sL "$releases_url" | grep -Eo "https://github.com/[^[:space:]]+/releases/download/[^[:space:]]+$arch" | head -1)

    if [ -z "$download_url" ]; then
        echo -e "${RED}Failed to retrieve the latest TUIC program download link.${NC}"
        exit 1
    fi

    if [ -e "/usr/local/bin/tuic" ]; then
        rm /usr/local/bin/tuic
    fi    

    echo "Downloading the latest TUIC program..."
    wget -O /usr/local/bin/tuic "$download_url" >/dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to download the TUIC program.${NC}"
        exit 1
    fi

    chmod +x /usr/local/bin/tuic
    echo "TUIC program download and installation completed."
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

function configure_tuic_service() {
    echo "Configuring TUIC startup service..."
    local service_file="/etc/systemd/system/tuic.service"

    if [[ -f $service_file ]]; then
        rm "$service_file"
    fi
    
        local service_config='[Unit]
Description=tuic service
Documentation=https://github.com/EAimTY/tuic
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/usr/local/etc/tuic/
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/local/bin/tuic -c /usr/local/etc/tuic/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target'

        echo "$service_config" >"$service_file"
        echo "TUIC startup service has been configured."
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

function override_port() {
    while true; do
        read -p "请输入目标端口 (默认443): " override_port
        override_port=${override_port:-443}

        if [[ $override_port =~ ^[1-9][0-9]{0,4}$ && $override_port -le 65535 ]]; then
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
            break
        else       
            echo -e "${RED}错误：端口范围1-65535，请重新输入！${NC}"
        fi
    done    
}

function override_address() {
  while true; do
    read -p "请输入目标地址（IP或域名）: " target_address
    if [[ -n "$target_address" ]]; then
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
    else
      echo -e "${RED}错误：目标地址不能为空！${NC}"
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

function get_domain() {
    while true; do
        read -p "请输入域名（用于自动申请证书）: " domain

        local_ip_v4=$(hostname -I | awk '{print $1}')
        local_ip_v6=$(ip -o -6 addr show scope global | awk '{split($4, a, "/"); print a[1]; exit}')

        resolved_ipv4=$(dig +short A "$domain" 2>/dev/null)
        resolved_ipv6=$(dig +short AAAA "$domain" 2>/dev/null)

        if [[ -z $domain ]]; then
            echo -e "${RED}错误：域名不能为空，请重新输入。${NC}"
        else
            if [[ ("$resolved_ipv4" == "$local_ip_v4" && ! -z "$resolved_ipv4") || ("$resolved_ipv6" == "$local_ip_v6" && ! -z "$resolved_ipv6") ]]; then
                break
            else
                echo -e "${RED}错误：域名未绑定本机IP，请重新输入。${NC}"
            fi
        fi
    done
}


function test_caddy_config() {
    echo "Testing Caddy configuration file..."
    local output
    local caddy_pid

    output=$(timeout 15 /usr/bin/caddy run --environ --config /usr/local/etc/caddy/caddy.json 2>&1 &)
    caddy_pid=$!

    wait $caddy_pid 2>/dev/null

    if echo "$output" | grep -i "error"; then
        echo -e "${RED}Caddy configuration test failed. Please check the configuration file.${NC}"
        echo "$output" | grep -i "error" --color=always 
    else
        echo "Caddy configuration test passed."
    fi
}

function generate_uuid() {
    if [[ -n $(command -v uuidgen) ]]; then
        uuid=$(uuidgen)
    elif [[ -n $(command -v uuid) ]]; then
        uuid=$(uuid -v 4)
    else
        echo -e "${RED}错误：无法生成UUID，请手动设置。${NC}"
        exit 1
    fi
    echo "随机生成的UUID：$uuid"
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

function add_tuic_multiple_users() {
    while true; do
        read -p "是否继续添加用户？(Y/N, 默认为N): " add_multiple_users

        if [[ -z "$add_multiple_users" || "$add_multiple_users" == "N" || "$add_multiple_users" == "n" ]]; then
            break
        elif [[ "$add_multiple_users" == "Y" || "$add_multiple_users" == "y" ]]; then

            generate_uuid

            set_password

            users+=",\n\"$uuid\": \"$password\""
        else
            echo -e "${RED}错误：无效的选择，请重新输入。${NC}"
        fi
    done
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
                get_domain
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

function read_users() {
    users="[
        {
          \"auth_str\": \"$password\"
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

function add_shadowtls_user() {
    local user_password=""
    if [[ $encryption_choice == 2 || $encryption_choice == 3 ]]; then
        user_password=$(openssl rand -base64 32)
    elif [[ $encryption_choice == 1 ]]; then
        user_password=$(openssl rand -base64 16)
    fi

    local new_user=$(set_username)
    new_user=${new_user##*: }
    
    users+=",{
      \"name\": \"$new_user\",
      \"password\": \"$user_password\"
    }"

    echo "用户名: $new_user"
    echo "ShadowTLS 密码: $user_password"
}

function validate_tls13_support() {
    local server="$1"
    local tls13_supported="false"

    if command -v openssl >/dev/null 2>&1; then
        local openssl_output=$(timeout 90s openssl s_client -connect "$server:443" -tls1_3 2>&1)
        if [[ $openssl_output == *"Protocol  : TLSv1.3"* ]]; then
            tls13_supported="true"
        fi
    fi

    echo "$tls13_supported"
}

function generate_server_name_config() {
    local server_name="www.gov.hk"

    read -p "请输入可用的 serverName 列表 (默认为 www.gov.hk): " user_input
    
    echo "Verifying server's TLS version support..." >&2
    
    if [[ -n "$user_input" ]]; then
        server_name="$user_input"
        local tls13_support=$(validate_tls13_support "$server_name")

        if [[ "$tls13_support" == "false" ]]; then
            echo -e "${RED}该网址不支持 TLS 1.3，请重新输入！${NC}" >&2
            generate_server_name_config
            return
        fi
    fi

    echo "$server_name"
}

function generate_target_server_config() {
    local target_server="www.gov.hk"

    read -p "请输入目标网站地址(默认为 www.gov.hk): " user_input
    
    echo "Verifying server's TLS version support..." >&2
    
    if [[ -n "$user_input" ]]; then
        target_server="$user_input"
        local tls13_support=$(validate_tls13_support "$target_server")

        if [[ "$tls13_support" == "false" ]]; then
            echo -e "${RED}该目标网站地址不支持 TLS 1.3，请重新输入！${NC}" >&2
            generate_target_server_config
            return
        fi
    fi

    echo "$target_server"
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

function generate_short_id() {
    local length=$1
    local short_id=$(openssl rand -hex "$length")
    echo "$short_id"
}

function select_flow_type() {
    local flow_type="xtls-rprx-vision"

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

    echo "$flow_type"
}

function generate_short_ids_config() {
    local short_ids=()
    local add_more_short_ids="y"
    local length=8

    while [[ "$add_more_short_ids" == "y" ]]; do
        if [[ ${#short_ids[@]} -eq 8 ]]; then
            echo -e "${YELLOW}已达到最大 shortId 数量限制！${NC}" >&2
            break
        fi

        local short_id=$(generate_short_id "$length")
        short_ids+=("$short_id")

        while true; do
            read -p "是否继续添加 shortId？(Y/N，默认为 N): " add_more_short_ids
            add_more_short_ids=${add_more_short_ids:-n}
            case $add_more_short_ids in
                [yY])
                    add_more_short_ids="y"
                    break
                    ;;
                [nN])
                    add_more_short_ids="n"
                    break
                    ;;
                *)
                    echo -e "${RED}错误的选项，请重新输入！${NC}" >&2
                    ;;
            esac
        done

        if [[ "$add_more_short_ids" == "y" ]]; then
            length=$((length - 1))
        fi
    done

    local short_ids_config=$(printf '            "%s",\n' "${short_ids[@]}")
    short_ids_config=${short_ids_config%,}  

    echo "$short_ids_config"
}

function generate_flow_config() {
    local flow_type="$1"
    local transport_config=""

    if [[ "$flow_type" != "" ]]; then
        return  
    fi

    local transport_type=""

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

    transport_config='
      "transport": {
        "type": "'"$transport_type"'"
      },'

    echo "$transport_config"
}

function generate_user_config() {
    local flow_type="$1"
    local users=()
    local add_more_users="y"

    while [[ "$add_more_users" == "y" ]]; do
        local user_uuid

        while true; do
            read -p "请输入用户 UUID (默认随机生成): " user_uuid

            if [[ -z "$user_uuid" ]]; then
                user_uuid=$(generate_uuid | sed 's/随机生成的UUID：//')
                break
            fi

            if [[ $user_uuid =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]]; then
                break
            else
                echo -e "${RED}无效的 UUID，请重新输入！${NC}" >&2
            fi
        done

        users+=('
        {
          "uuid": "'"$user_uuid"'",
          "flow": "'"$flow_type"'"
        },')

        while true; do
            read -p "是否继续添加用户？(Y/N，默认为 N): " add_more_users
            add_more_users=${add_more_users:-n}
            case $add_more_users in
                [yY])
                    add_more_users="y"
                    break
                    ;;
                [nN])
                    add_more_users="n"
                    break
                    ;;
                *)
                    echo -e "${RED}错误的选项，请重新输入！${NC}" >&2
                    ;;
            esac
        done
    done

    users[-1]=${users[-1]%,}

    echo "${users[*]}"
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

function prompt_additional_users() {
  read -p "是否添加多用户？(Y/N，默认N): " additional_users_input

  case "$additional_users_input" in
    [Yy])
      while true; do
        read -p "请输入密码 (回车生成随机密码): " user_password_input
        if [[ -z "$user_password_input" ]]; then
          user_password=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12)
        else
          user_password="$user_password_input"
        fi

        if [[ -z "$user_password" ]]; then
          echo -e "${RED}错误：密码不能为空。${NC}"
          continue
        fi

        if [[ -z "$users" ]]; then
          users+=",
        {
          \"password\": \"$user_password\"
        }"
        else
          users+=",
        {
          \"password\": \"$user_password\"
        }"
        fi

        read -p "是否继续添加用户？(Y/N，默认N): " continue_add_input
        case "$continue_add_input" in
          [Nn]|"")
            break
            ;;
          *)
            continue
            ;;
        esac
      done
      ;;
    [Nn]|"")
      ;;
    *)
       echo -e "${RED}无效的选择，请输入 Y 或 N。${NC}"
      prompt_additional_users
      ;;
  esac
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
        h1h2c_port=$(grep -oE '"listen": \["127.0.0.1:[0-9]+"],' /usr/local/etc/caddy/caddy.json | cut -d':' -f3 | tr -d '",[]' | head -n 1)
        echo ",
      \"fallback\": {
        \"server\": \"127.0.0.1\",
        \"server_port\": $h1h2c_port
      }"
    fi
}

function generate_Direct_config() {
    local config_file="/usr/local/etc/sing-box/config.json"

    echo "{
  \"log\": {
    \"disabled\": false,
    \"level\": \"info\",
    \"timestamp\": true
  },
  \"inbounds\": [
    {
      \"type\": \"direct\",
      \"tag\": \"direct-in\",
      \"listen\": \"::\",
      \"listen_port\": $listen_port,
      \"sniff\": true,
      \"sniff_override_destination\": true,
      \"sniff_timeout\": \"300ms\",
      \"proxy_protocol\": false,
      \"network\": \"tcp\",
      \"override_address\": \"$target_address\",
      \"override_port\": $override_port
    }
  ],
  \"outbounds\": [
    {
      \"type\": \"direct\",
      \"tag\": \"direct\"
    },
    {
      \"type\": \"block\",
      \"tag\": \"block\"
    }
  ]
}" > "$config_file"
}

function generate_ss_config() {
    local config_file="/usr/local/etc/sing-box/config.json"

    echo "{
  \"log\": {
    \"disabled\": false,
    \"level\": \"info\",
    \"timestamp\": true
  },
  \"inbounds\": [
    {
      \"type\": \"shadowsocks\",
      \"tag\": \"ss-in\",
      \"listen\": \"::\",
      \"listen_port\": $listen_port,
      \"method\": \"$ss_method\",
      \"password\": \"$ss_password\"
    }
  ],
  \"outbounds\": [
    {
      \"type\": \"direct\",
      \"tag\": \"direct\"
    },
    {
      \"type\": \"block\",
      \"tag\": \"block\"
    }
  ]
}" > "$config_file"
}

function generate_naive_config() {
    local config_file="/usr/local/etc/caddy/caddy.json"

    echo "{
  \"apps\": {
    \"http\": {
      \"servers\": {
        \"https\": {
          \"listen\": [\":$listen_port\"],
          \"routes\": [
            {
              \"handle\": [
                {
                  \"handler\": \"forward_proxy\",
                  \"auth_user_deprecated\": \"$username\",
                  \"auth_pass_deprecated\": \"$password\",
                  \"hide_ip\": true,
                  \"hide_via\": true,
                  \"probe_resistance\": {}
                }
              ]
            },
            {
              \"handle\": [
                {
                  \"handler\": \"headers\",
                  \"response\": {
                    \"set\": {
                      \"Strict-Transport-Security\": [\"max-age=31536000; includeSubDomains; preload\"]
                    }
                  }
                },
                {
                  \"handler\": \"reverse_proxy\",
                  \"headers\": {
                    \"request\": {
                      \"set\": {
                        \"Host\": [
                          \"{http.reverse_proxy.upstream.hostport}\"
                        ],
                        \"X-Forwarded-Host\": [\"{http.request.host}\"]
                      }
                    }
                  },
                  \"transport\": {
                    \"protocol\": \"http\",
                    \"tls\": {}
                  },
                  \"upstreams\": [
                    {\"dial\": \"$fake_domain:443\"}
                  ]
                }
              ]
            }
          ],
          \"tls_connection_policies\": [
            {
              \"match\": {
                \"sni\": [\"$domain\"]
              },
              \"protocol_min\": \"tls1.2\",
              \"protocol_max\": \"tls1.2\",
              \"cipher_suites\": [\"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256\"],
              \"curves\": [\"secp521r1\",\"secp384r1\",\"secp256r1\"]
            }
          ],
          \"protocols\": [\"h1\",\"h2\"]
        }
      }
    },
    \"tls\": {
      \"certificates\": {
        \"automate\": [\"$domain\"]
      },
      \"automation\": {
        \"policies\": [
          {
            \"issuers\": [
              {
                \"module\": \"acme\"
              }
            ]
          }
        ]
      }
    }
  }
}" > "$config_file"
}

function generate_tuic_config() {
    local config_file="/usr/local/etc/tuic/config.json"
    local users=""
    local certificate=""
    local private_key=""
    
    listen_port
    generate_uuid
    set_password
    users="\"$uuid\": \"$password\""

    add_tuic_multiple_users
    users=$(echo -e "$users" | sed -e 's/^/        /')

    set_certificate_and_private_key
    certificate_path="$certificate_path"
    private_key_path="$private_key_path"
    set_congestion_control

    echo "{
    \"server\": \"[::]:$listen_port\",
    \"users\": {
$users
    },
    \"certificate\": \"$certificate_path\",
    \"private_key\": \"$private_key_path\",
    \"congestion_control\": \"$congestion_control\",
    \"alpn\": [\"h3\", \"spdy/3.1\"],
    \"udp_relay_ipv6\": true,
    \"zero_rtt_handshake\": false,
    \"dual_stack\": true,
    \"auth_timeout\": \"3s\",
    \"task_negotiation_timeout\": \"3s\",
    \"max_idle_time\": \"10s\",
    \"max_external_packet_size\": 1500,
    \"send_window\": 16777216,
    \"receive_window\": 8388608,
    \"gc_interval\": \"3s\",
    \"gc_lifetime\": \"15s\",
    \"log_level\": \"warn\"
}" > "$config_file"
}

function generate_Hysteria_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local certificate=""
    local private_key=""
 
    listen_port
    read_up_speed
    read_down_speed
    set_password    
    read_users    
    set_certificate_and_private_key
    certificate_path="$certificate_path"
    private_key_path="$private_key_path"

    echo "生成 Hysteria 配置文件..."
    echo "{
  \"log\": {
    \"disabled\": false,
    \"level\": \"info\",
    \"timestamp\": true
  },
  \"inbounds\": [
    {
      \"type\": \"hysteria\",
      \"tag\": \"hysteria-in\",
      \"listen\": \"::\",
      \"listen_port\": $listen_port,
      \"sniff\": true,
      \"sniff_override_destination\": true,
      \"up_mbps\": $up_mbps,
      \"down_mbps\": $down_mbps,
      \"users\": $users,
      \"tls\": {
        \"enabled\": true,
        \"alpn\": [
          \"h3\"
        ],
        \"certificate_path\": \"$certificate_path\",
        \"key_path\": \"$private_key_path\"
      }
    }
  ],
  \"outbounds\": [
    {
      \"type\": \"direct\",
      \"tag\": \"direct\"
    },
    {
      \"type\": \"block\",
      \"tag\": \"block\"
    }
  ]
}" > "$config_file"
}

function generate_shadowtls_config() {
    local config_file="/usr/local/etc/sing-box/config.json"

    listen_port
    set_username
    encryption_method

    local users="{
          \"name\": \"$username\",
          \"password\": \"$shadowtls_password\"
        }"

    local add_multiple_users="Y"

    while [[ $add_multiple_users == [Yy] ]]; do
        read -p "是否添加多用户？(Y/N，默认为N): " add_multiple_users

        if [[ $add_multiple_users == [Yy] ]]; then
            add_shadowtls_user
        fi
    done

    local user_input=$(generate_target_server_config) 

    echo "{
  \"inbounds\": [
    {
      \"type\": \"shadowtls\",
      \"tag\": \"st-in\",
      \"listen\": \"::\",
      \"listen_port\": $listen_port,
      \"version\": 3,
      \"users\": [
        $users
      ],
      \"handshake\": {
        \"server\": \"$user_input\",
        \"server_port\": 443
      },
      \"strict_mode\": true,
      \"detour\": \"ss-in\"
    },
    {
      \"type\": \"shadowsocks\",
      \"tag\": \"ss-in\",
      \"listen\": \"127.0.0.1\",
      \"network\": \"tcp\",
      \"method\": \"$ss_method\",
      \"password\": \"$ss_password\"
    }
  ],
  \"outbounds\": [
    {
      \"type\": \"direct\",
      \"tag\": \"direct\"
    },
    {
      \"type\": \"block\",
      \"tag\": \"block\"
    }
  ]
}" | jq '.' > "$config_file"
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

    local listen_port_output=$(listen_port)
    local listen_port=$(echo "$listen_port_output" | grep -oP '\d+$')
    local flow_type=$(select_flow_type)

    transport_config=$(generate_flow_config "$flow_type")

    users=$(generate_user_config "$flow_type")

    local server_name=$(generate_server_name_config)
    local target_server=$(generate_target_server_config)
    local private_key=$(generate_private_key_config)
    local short_ids=$(generate_short_ids_config)

    local config_content="{
  \"log\": {
    \"disabled\": false,
    \"level\": \"info\",
    \"timestamp\": true
  },
  \"inbounds\": [
    {
      \"type\": \"vless\",
      \"tag\": \"vless-in\",
      \"listen\": \"::\",
      \"listen_port\": $listen_port,
      \"users\": [$users
      ],$transport_config
      \"tls\": {
        \"enabled\": true,
        \"server_name\": \"$server_name\",
        \"reality\": {
          \"enabled\": true,
          \"handshake\": {
            \"server\": \"$target_server\",
            \"server_port\": 443
          },
          \"private_key\": \"$private_key\",
          \"short_id\": [
$short_ids
          ]
        }
      }
    }
  ],
  \"outbounds\": [
    {
      \"type\": \"direct\",
      \"tag\": \"direct\"
    },
    {
      \"type\": \"block\",
      \"tag\": \"block\"
    }
  ]
}"
    echo "$config_content" > "$config_file" 
    check_firewall_configuration       
}

function generate_caddy_config() {
  caddy_config="{
  \"logging\": {
    \"logs\": {
      \"default\": {
        \"writer\": {
          \"output\": \"file\",
          \"filename\": \"/var/log/caddy.log\"
        },
        \"level\": \"WARN\"
      }
    }
  },
  \"storage\": {
    \"module\": \"file_system\",
    \"root\": \"/etc/ssl\"
  },
  \"apps\": {
    \"http\": {
      \"servers\": {
        \"h1\": {
          \"listen\": [\":80\"],
          \"routes\": [{
            \"handle\": [{
              \"handler\": \"static_response\",
              \"headers\": {
                \"Location\": [\"https://{http.request.host}{http.request.uri}\"]
              },
              \"status_code\": 301
            }]
          }],
          \"protocols\": [\"h1\"]
        },
        \"h1h2c\": {
          \"listen\": [\"127.0.0.1:$fallback_port\"],
          \"routes\": [{
            \"handle\": [
              {
                \"handler\": \"headers\",
                \"response\": {
                  \"set\": {
                    \"Strict-Transport-Security\": [\"max-age=31536000; includeSubDomains; preload\"]
                  }
                }
              },
              {
                \"handler\": \"reverse_proxy\",
                \"headers\": {
                  \"request\": {
                    \"set\": {
                      \"Host\": [\"{http.reverse_proxy.upstream.hostport}\"],
                      \"X-Forwarded-Host\": [\"{http.request.host}\"]
                    }
                  }
                },
                \"transport\": {
                  \"protocol\": \"http\",
                  \"tls\": {}
                },
                \"upstreams\": [{\"dial\": \"$fake_domain:443\"}]
              }
            ]
          }],
          \"protocols\": [\"h1\",\"h2c\"]
        }
      }
    },
    \"tls\": {
      \"certificates\": {
        \"automate\": [\"$domain\"]
      },
      \"automation\": {
        \"policies\": [{
          \"issuers\": [{
            \"module\": \"acme\"
          }]
        }]
      }
    }
  }
}"
  echo "$caddy_config" > /usr/local/etc/caddy/caddy.json
}

function generate_trojan_config() {
  server_name=$(grep -oE '"automate": \["[^"]+"' /usr/local/etc/caddy/caddy.json | cut -d'"' -f4)

 sing_box_config="{
  \"log\": {
    \"disabled\": false,
    \"level\": \"info\",
    \"timestamp\": true
  },
  \"inbounds\": [
    {
      \"type\": \"trojan\",
      \"tag\": \"trojan-in\",
      \"listen\": \"::\",
      \"listen_port\": $listen_port,
      \"sniff\": true,
      \"sniff_override_destination\": true,
      \"users\": [
        {
          \"password\": \"$password\"
        }$users
      ],
      \"tls\": {
        \"enabled\": true,
        \"server_name\": \"$server_name\",
        \"alpn\": [
          \"h2\",
          \"http/1.1\"
        ],
        \"certificate_path\": \"/etc/ssl/certificates/acme-v02.api.letsencrypt.org-directory/$server_name/$server_name.crt\",
        \"key_path\": \"/etc/ssl/certificates/acme-v02.api.letsencrypt.org-directory/$server_name/$server_name.key\"
      }$transport_and_fallback_config
    }
  ],
  \"outbounds\": [
    {
      \"type\": \"direct\",
      \"tag\": \"direct\"
    },
    {
      \"type\": \"block\",
      \"tag\": \"block\"
    }
  ]
}"
    echo "$sing_box_config" > /usr/local/etc/sing-box/config.json
}

function display_reality_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"    
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
    echo "监听端口: $listen_port" | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "用户 UUID:" | tee -a "$output_file"
    echo "$users" | tee -a "$output_file"
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
    local config_file="/usr/local/etc/tuic/config.json"
    local output_file="/usr/local/etc/tuic/output.txt"  
    local listen_port=$(jq -r '.server' "$config_file" | sed 's/\[::\]://')
    local UUIDS=$(jq -r '.users | to_entries[] | "UUID:\(.key)\t密码:\(.value)"' "$config_file")
    local congestion_control=$(jq -r '.congestion_control' "$config_file")
    local alpn=$(jq -r '.alpn[] | select(. != "")' "$config_file" | sed ':a;N;$!ba;s/\n/, /g')
  
    echo -e "${CYAN}TUIC 节点配置信息：${NC}"  | tee -a "$output_file"     
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file"  
    echo "监听端口: $listen_port"  | tee -a "$output_file" 
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"  
    echo "UUID和密码列表:"  | tee -a "$output_file" 
    echo "$UUIDS"  | tee -a "$output_file" 
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "拥塞控制算法: $congestion_control"  | tee -a "$output_file" 
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file"  
    echo "ALPN协议:$alpn"  | tee -a "$output_file" 
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file" 
    echo "配置信息已保存至 $output_file"    
}

function display_Hysteria_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt" 

    echo -e "${CYAN}Hysteria 节点配置信息：${NC}"  | tee -a "$output_file"
    echo -e "${CYAN}==================================================================${NC}"  | tee -a "$output_file" 
    echo "域名：$domain"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "监听端口：$listen_port"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "上行速度：${up_mbps}Mbps"  | tee -a "$output_file"
    echo -e "${CYAN}------------------------------------------------------------------${NC}"  | tee -a "$output_file" 
    echo "下行速度：${down_mbps}Mbps"  | tee -a "$output_file"
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

function display_shadowtls_config() {
    local config_file="/usr/local/etc/sing-box/config.json"
    local output_file="/usr/local/etc/sing-box/output.txt"
    local listen_port=$(jq -r '.inbounds[0].listen_port' "$config_file")       
    local shadowtls_passwords=$(jq -r '.inbounds[0].users[] | "ShadowTLS 密码: \(.password)"' "$config_file")
    local user_input=$(jq -r '.inbounds[0].handshake.server' "$config_file")
    local ss_password=$(jq -r '.inbounds[1].password' "$config_file")    

    echo -e "${CYAN}ShadowTLS 节点配置信息：${NC}" | tee -a "$output_file"
    echo -e "${CYAN}================================================================${NC}" | tee -a "$output_file"
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
    local_ip=$(hostname -I | awk '{print $1}')
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
    local_ip=$(hostname -I | awk '{print $1}')
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
    local config_file="/usr/local/etc/caddy/caddy.json"
    local output_file="/usr/local/etc/caddy/output.txt"
    local listen_port=$(jq -r '.apps.http.servers.https.listen[0]' "$config_file")
    local username=$(jq -r '.apps.http.servers.https.routes[0].handle[0].auth_user_deprecated' "$config_file")
    local password=$(jq -r '.apps.http.servers.https.routes[0].handle[0].auth_pass_deprecated' "$config_file")
    local domain=$(jq -r '.apps.http.servers.https.tls_connection_policies[0].match.sni[0]' "$config_file")
  
    echo -e "${CYAN}NaiveProxy 节点配置信息：${NC}"  | tee -a "$output_file"
    echo -e "${CYAN}================================================================${NC}"  | tee -a "$output_file"
    echo "监听端口: $listen_port"  | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "用 户 名: $username"  | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "密    码: $password"  | tee -a "$output_file"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"  | tee -a "$output_file"
    echo "域    名: $domain"  | tee -a "$output_file"   
    echo -e "${CYAN}================================================================${NC}"  | tee -a "$output_file"
    echo "配置信息已保存至 $output_file" 
}

function display_juicity_config() {
    local config_file="/usr/local/etc/juicity/config.json"
    local output_file="/usr/local/etc/juicity/output.txt"  
    local listen_port=$(jq -r '.listen' "$config_file" | sed 's/\://')
    local UUIDS=$(jq -r '.users | to_entries[] | "UUID:\(.key)\t密码:\(.value)"' "$config_file")
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

check_and_restart_services() {
    if [ -f "/etc/systemd/system/tuic.service" ]; then
        systemctl restart tuic.service
        systemctl status --no-pager tuic.service
    fi

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

function uninstall_naiveproxy() {
    echo "开始卸载 NaiveProxy..."
    systemctl stop caddy
    systemctl disable caddy
    rm -rf /etc/systemd/system/caddy.service
    rm -rf /usr/local/etc/caddy
    rm -rf /usr/bin/caddy
    systemctl daemon-reload
    echo "NaiveProxy 卸载完成。"
}

function uninstall_tuic() {
    echo "开始卸载 TUIC..."
    systemctl stop tuic.service
    systemctl disable tuic.service
    rm -rf /etc/systemd/system/tuic.service
    rm -rf /usr/local/etc/tuic
    rm -rf /usr/local/bin/tuic
    echo "TUIC 卸载完成。"
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

function uninstall() {
    local uninstall_sing_box=false
    local uninstall_caddy=false
    local uninstall_tuic=false
    local uninstall_juicity=false

    if [[ -f "/etc/systemd/system/sing-box.service" ]]; then
        uninstall_sing_box=true
    fi
    
    if [[ -f "/etc/systemd/system/caddy.service" ]]; then
        uninstall_caddy=true
    fi

    if [[ -f "/etc/systemd/system/tuic.service" ]]; then
        uninstall_tuic=true
    fi

    if [[ -f "/etc/systemd/system/juicity.service" ]]; then
        uninstall_juicity=true
    fi    

    if [[ "$uninstall_sing_box" == true ]]; then
        uninstall_sing_box
    fi

    if [[ "$uninstall_caddy" == true ]]; then
        uninstall_naiveproxy
    fi

    if [[ "$uninstall_tuic" == true ]]; then
        uninstall_tuic
    fi

    if [[ "$uninstall_juicity" == true ]]; then
        uninstall_juicity
    fi    
}

function juicity_install() {
    configure_dns64
    enable_bbr
    check_juicity_folder   
    download_juicity
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
    configure_dns64
    enable_bbr
    select_sing_box_install_option
    configure_sing_box_service
    check_sing_box_folder    
    listen_port
    override_address
    override_port
    generate_Direct_config
    check_firewall_configuration 
    systemctl daemon-reload   
    systemctl enable sing-box   
    systemctl start sing-box
    display_Direct_config
}

function Shadowsocks_install() {
    configure_dns64
    enable_bbr
    select_sing_box_install_option
    configure_sing_box_service
    check_sing_box_folder
    listen_port
    encryption_method
    generate_ss_config
    check_firewall_configuration 
    systemctl daemon-reload   
    systemctl enable sing-box   
    systemctl start sing-box
    display_Shadowsocks_config
}

function NaiveProxy_install() {
    configure_dns64
    enable_bbr
    install_go
    install_caddy
    check_caddy_folder
    listen_port
    set_username
    set_password
    get_fake_domain
    get_domain    
    generate_naive_config
    check_firewall_configuration    
    test_caddy_config
    configure_caddy_service
    systemctl daemon-reload 
    systemctl enable caddy
    systemctl start caddy
    systemctl reload caddy
    display_NaiveProxy_config
}

function tuic_install() {
    configure_dns64
    enable_bbr
    create_tuic_directory   
    download_tuic
    generate_tuic_config
    check_firewall_configuration 
    ask_certificate_option
    configure_tuic_service
    systemctl daemon-reload
    systemctl enable tuic.service
    systemctl start tuic.service
    systemctl restart tuic.service
    display_tuic_config
}

function Hysteria_install() {
    configure_dns64
    enable_bbr
    select_sing_box_install_option      
    check_sing_box_folder
    generate_Hysteria_config
    check_firewall_configuration 
    ask_certificate_option 
    configure_sing_box_service
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    display_Hysteria_config
}

function shadowtls_install() {
    configure_dns64
    enable_bbr
    select_sing_box_install_option      
    check_sing_box_folder
    generate_shadowtls_config
    check_firewall_configuration      
    configure_sing_box_service
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    display_shadowtls_config
}

function reality_install() {
    configure_dns64
    enable_bbr
    select_sing_box_install_option      
    check_sing_box_folder    
    generate_reality_config            
    configure_sing_box_service    
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    display_reality_config
}

function trojan_install() {
    configure_dns64
    enable_bbr
    check_sing_box_folder
    check_caddy_folder
    select_sing_box_install_option
    configure_sing_box_service
    install_latest_caddy
    configure_caddy_service
    prompt_setup_type
    listen_port
    set_password
    prompt_additional_users    
    web_port
    get_fake_domain
    get_domain      
    generate_caddy_config 
    transport_and_fallback_config=$(prompt_and_generate_transport_config)
    check_firewall_configuration
    test_caddy_config
    generate_trojan_config
    check_firewall_configuration 
    systemctl daemon-reload
    systemctl enable caddy
    systemctl enable sing-box 
    systemctl start caddy
    systemctl start sing-box
    display_trojan_config
}

function view_saved_config() {
    local config_paths=(
        "/usr/local/etc/sing-box/output.txt"
        "/usr/local/etc/tuic/output.txt"
        "/usr/local/etc/caddy/output.txt"
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
echo -e "║${CYAN} [9]${NC}  Shadowsocks            ${CYAN} [10]${NC} 查看节点信息                         ║"
echo -e "║${CYAN} [11]${NC} 重启服务               ${CYAN} [12]${NC} 卸载                                 ║"
echo -e "║${CYAN} [0]${NC}  退出                                                              ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"

    local choice
    read -p "请选择 [0-12]: " choice

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
            view_saved_config
            ;;

        11)
            check_and_restart_services
            ;;
        12)
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
