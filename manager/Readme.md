<div align="center">

[![banner](https://raw.githubusercontent.com/TheyCallMeSecond/sing-box-manager/main/img/01.png?raw=true "banner")](https://raw.githubusercontent.com/TheyCallMeSecond/sing-box-manager/main/img/01.png?raw=true "banner")

</div>

# **Updated content**
- **V 1.2**
- **Client profile added Clash API support.**
- **Other optimizations and fixes.**

<details>
   <summary><b>Historical update content</b></summary>

- **V 1.1**
- **Modify the DNS configuration section of the client configuration file.**

<br>

- **V 1.1-beta.3**
- **Add HTTPUpgrade transport layer.**

<br>

- **V 1.1-beta.2**
- **Fix the automatic update certificate issue.**
- **Fix Cron detection rules.**

<br>

- **V 1.1-beta.1** 
- **Add Multiplex (multiplexing), TCP Brutal (congestion control algorithm), ECH (TLS extension) configuration; to enable Multiplex and TCP Brutal, please use the sing-box kernel above 1.7.0, please Install TCP Brutal on your own.**
- **Add support for Juicity node link generation.**
- **Add support for HTTP protocol.**
- **Other optimizations and fixes.**

<br>

- **V 1.0** 
- **Add WireGuard unblock YouTube option.**
- **Add node management options to support deleting the configuration of any node, including server and client configuration files.**
- **Deleting node configuration only supports Version: 1.0 and later.**
- **Other optimizations and fixes.** 
</details>

# **Notes**
- **The script uses sing-box and Juicity kernel.**
- **Script supports CentOS 8+, Debian 10+, Ubuntu 20+ operating systems.**
- **All protocols of the script support self-signed certificates (except NaiveProxy).**
- **Script supports multiple users.**
- **Script supports coexistence of all protocols.**
- **Script supports self-signed 100-year certificates.**
- **Script supports automatic renewal of certificates.**
- **The script supports HTTP, WebSocket, gRPC, HTTPUpgrade transport protocols.**
- **The script supports Multiplex, TCP Brutal, and ECH configuration; to enable Multiplex and TCP Brutal, the sing-box kernel needs to be ≥1.7.0, and please install TCP Brutal on the server.**
- **Since Clash does not support TCP Brutal and ECH configurations, the Clash configuration file will not be automatically generated if these configurations are enabled.**

# **Install**
- **Debian&&Ubuntu use the following command to install dependencies**
```
apt update && apt -y install curl wget tar socat jq git openssl uuid-runtime build-essential zlib1g-dev libssl-dev libevent-dev dnsutils cron
```
- **CentOS uses the following command to install dependencies**
```
yum update && yum -y install curl wget tar socat jq git openssl util-linux gcc-c++ zlib-devel openssl-devel libevent-devel bind-utils cronie
```
- **Run the script using the following command**
```
wget -N -O /root/singbox.sh https://raw.githubusercontent.com/TheyCallMeSecond/sing-box-manager/main/Install.sh && chmod +x /root/singbox.sh && ln -sf /root/singbox.sh /usr/local/bin/singbox && bash /root/singbox.sh
```

# **Instructions**
- **The Clash client configuration file is located in /usr/local/etc/sing-box/clash.yaml. After downloading, it can be used by loading it into the Clash client. It needs to cooperate with the Meta kernel.**
- **sing-box computer configuration file is located in /usr/local/etc/sing-box/win_client.json. After downloading, it can be loaded into V2rayN and SFM clients for use.**
- **sing-box mobile phone configuration file is located in /usr/local/etc/sing-box/phone_client.json. After downloading, it can be loaded into SFA and SFI clients for use.**

# **Node types supported by script**
- **SOCKS**
- **HTTP**
- **TUIC V5**
- **Juicity**
- **WireGuard--Unlock ChatGPT, Netflix, Disney+, Google, Spotify**
- **Hysteria2**
- **VLESS+TCP**
- **VLESS+WebSocket**
- **VLESS+gRPC**
- **VLESS+HTTPUpgrade**
- **VLESS+Vision+REALITY**
- **VLESS+H2C+REALITY**
- **VLESS+gRPC+REALITY**
- **Direct--sing-box**
- **Trojan+TCP**
- **Trojan+WebSocket**
- **Trojan+gRPC**
- **Trojan+HTTPUpgrade**
- **Trojan+TCP+TLS**
- **Trojan+H2C+TLS**
- **Trojan+gRPC+TLS**
- **Trojan+WebSocket+TLS**
- **Trojan+HTTPUpgrade+TLS**
- **Hysteria**
- **ShadowTLS V3**
- **NaiveProxy**
- **Shadowsocks**
- **VMess+TCP**
- **VMess+WebSocket**
- **VMess+gRPC**
- **VMess+HTTPUpgrade**   
- **VMess+TCP+TLS**
- **VMess+WebSocket+TLS** 
- **VMess+H2C+TLS**
- **VMess+gRPC+TLS** 
- **VMess+HTTPUpgrade+TLS**
