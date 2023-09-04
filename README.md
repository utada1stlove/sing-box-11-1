# **说明**
- **脚本支持IPV6单栈机。**
- **脚本支持 CentOS 8+、Debian 10+、Ubuntu 20+ 操作系统。**
- **脚本支持 warp 解锁 ChatGPT、Netflix、Disney+。**
- **脚本支持多协议共存。**

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

## 安装iptables-persistent
apt install iptables-persistent

## 允许所有入站
iptables -P INPUT ACCEPT

## 清空所有默认规则
iptables -F

## 清空所有自定义规则
iptables -X

## 所有计数器清零
iptables -Z

## 允许本地访问
iptables -A INPUT -i lo -j ACCEPT

## 开放22端口,22替换为你的ssh连接端口
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

## 开放80端口(HTTP)，申请证书时使用，要放行其它端口请将80替换为你要放行的端口
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

## 开放10010端口(UDP)，10010替换为节点的监听端口
iptables -A INPUT -p udp --dport 10010 -j ACCEPT

## 开放20000-40000端口(UDP)，20000-40000可以自己设置
iptables -A INPUT -p udp --dport 20000:40000 -j ACCEPT

## 允许接受本机请求之后的返回数据
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

## 其他入站一律禁止
iptables -P INPUT DROP

## 允许所有出站
iptables -P OUTPUT ACCEPT

## 查看开放的端口
iptables -L

## 添加NAT规则，20000:40000替换为你设置端口跳跃的范围，10010替换为你节点的监听端口
iptables -t nat -A PREROUTING -p udp --dport 20000:40000 -j DNAT --to-destination :10010

## 查看NAT规则
iptables -t nat -nL --line

## 保存iptables规则
netfilter-persistent save
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
