#!/bin/bash
wget https://github.com/xmdhs/clash2singbox/releases/download/v0.1.4/clash2singbox-linux-amd64

chmod +x clash2singbox-linux-amd64

./clash2singbox-linux-amd64 -url
 https://client.fhlsep.cn/api/v1/client/subscribe?token=523b649f50410fffc48e446869c7a2c4|   -o /etc/sing-box/singbox.json