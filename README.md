# **Description**
### This script supports vps of IPV6 single-stack network.
### The script supports CentOS 8+, Debian 10+, Ubuntu 20+ operating systems.

# **Installation**
```
#Debian&&Ubuntu
apt update && apt -y install curl wget tar socat jq git openssl uuid-runtime build-essential zlib1g-dev libssl-dev libevent-dev
```
```
#CentOS
yum update && yum -y install curl wget tar socat jq git openssl util-linux gcc-c++ zlib-devel openssl-devel libevent-devel
```
```
bash <(curl -L https://raw.githubusercontent.com/TinrLin/script_installation/main/Install.sh)
```
# **Supported node types in this script**
- **TUIC V5**
- **juicity**
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
