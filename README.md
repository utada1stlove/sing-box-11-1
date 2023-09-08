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

## 清空默认规则
iptables -F

## 清空自定义规则
iptables -X

## 允许本地访问
iptables -A INPUT -i lo -j ACCEPT

## 开放SSH端口（假设SSH端口为22）
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

## 开放HTTP端口
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

## 开放UDP端口（10010替换为节点的监听端口）
iptables -A INPUT -p udp --dport 10010 -j ACCEPT

## 开放UDP端口范围（假设UDP端口范围为20000-40000）
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
```
# CentOS
## 安装iptables-service
yum install iptables-services

## 启用iptables服务
systemctl enable iptables

## 启动iptables服务
systemctl start iptables

## 清空默认规则
iptables -F

## 清空自定义规则
iptables -X

## 允许本地访问
iptables -A INPUT -i lo -j ACCEPT

## 开放SSH端口（假设SSH端口为22）
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

## 开放HTTP端口
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

## 开放UDP端口（10010替换为节点的监听端口）
iptables -A INPUT -p udp --dport 10010 -j ACCEPT

## 开放UDP端口范围（假设UDP端口范围为20000-40000）
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
service iptables save
```

# **脚本支持的节点类型**
- **TUIC V5**
- **juicity**
- **WireGuard**
- **Hysteria2**
- **Vless+vision+Reality**
- **Vless+h2+Reality**
- **Vless+gRPC+Reality**
- **Direct--sing-box版任意门**
- **Trojan+tcp+tls+web**
- **Trojan+ws+tls+(CDN)**
- **Hysteria**
- **ShadowTLS V3**
- **NaiveProxy**
- **Shadowsocks**
