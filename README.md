# **说明**
### 脚本支持IPV6单栈机。
### 脚本支持 CentOS 8+、Debian 10+、Ubuntu 20+ 操作系统。
### 脚本支持 warp 解锁 ChatGPT、Netflix、Disney+。
### 脚本支持多协议共存。

# **安装**
- **Debian&&Ubuntu使用以下命令安装依赖**
```
apt update && apt -y install curl wget tar socat jq git openssl uuid-runtime build-essential zlib1g-dev libssl-dev libevent-dev dnsutils
```
- **CentOS使用以下命令安装依赖**
```
yum update && yum -y install curl wget tar socat jq git openssl util-linux gcc-c++ zlib-devel openssl-devel libevent-devel bind-utils
```
- **使用以下命令运行脚本**
```
bash <(curl -L https://raw.githubusercontent.com/TinrLin/script_installation/main/Install.sh)
```
# **Hysteria端口跳跃**
```
# Debian&&Ubuntu
- **安装iptables-persistent**
```
apt install iptables-persistent
```
- **Allow all inbound**
```
iptables -P INPUT ACCEPT
```
- **Clear all default rules**
```
iptables -F
```
- **Clear all custom rules**
```
iptables -X
```
- **All counters are cleared**
```
iptables -Z
```
- **Allow local access**
```
iptables -A INPUT -i lo -j ACCEPT
```
- **Open ssh port,replace 22 with your ssh port**
```
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```
- **Open port 80 (HTTP)**
```
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```
- **Open port 443 (HTTPS)**
```
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```
- **Open port 10010 (UDP),replace 10010 with your listening port**
```
iptables -A INPUT -p udp --dport 10010 -j ACCEPT
```
- **Open port 20000-40000 (UDP),20000-40000 can be set by yourself**
```
iptables -A INPUT -p udp --dport 20000:40000 -j ACCEPT
```
- **Allows to accept return data after native request**
```
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
```
- **All other entries are prohibited**
```
iptables -P INPUT DROP
```
- **Allow all outbound**
```
iptables -P OUTPUT ACCEPT
```
- **Check open ports**
```
iptables -L
```
- **Add NAT rule**
```
iptables -t nat -A PREROUTING -p udp --dport 20000:40000 -j DNAT --to-destination :10010
```
- **View NAT rules**
```
iptables -t nat -nL --line
```
- **Save iptables rules**
```
netfilter-persistent save
```
```
# **脚本支持的节点类型**
- **TUIC V5**
- **juicity**
- **WireGuard**
- **Hysteria2**
- **Vless+vision+Reality**
- **Vless+h2+Reality**
- **Vless+gRPC+Reality**
- **Direct tunnel server**
- **Trojan+tcp+tls+web**
- **Trojan+ws+tls+(CDN)**
- **Hysteria**
- **ShadowTLS V3**
- **NaiveProxy**
- **Shadowsocks**
