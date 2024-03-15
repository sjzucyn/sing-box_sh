#!/bin/bash

bash <(curl -fsSL https://get.hy2.sh/)
bash <(curl -L -s https://gitlab.com/rwkgyg/acme-script/raw/main/acme.sh)
my_ip=$(curl -s https://api.ipify.org)
apt install nginx -y

touch /etc/nginx/sites-enabled/default
touch /etc/nginx/sites-available/default
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default

cd /etc/hysteria
openssl ecparam -genkey -name prime256v1 -out private.key
openssl req -new -x509 -days 36500 -key private.key -out cert.crt -subj "/CN=www.bing.com"
# 指定文件路径
file_path1="/etc/hysteria/config.yaml"
file_path2="/etc/hysteria/client.yaml
file_path6="/etc/nginx/nginx.conf"
echo "请输入您的hy密码："
read my_uuid
echo "您好，设置密码为$my_uuid"
echo "请输入您的节点名称tag："
read my_name
echo "您好，设置节点tag为$my_name"
# 创建文件并写入多行内容
touch "$file_path1"
touch "$file_path2"

touch "$file_path6"
cat << EOF > "$file_path1"
# listen: :443 

tls:
  cert: /etc/hysteria/cert.crt 
  key: /etc/hysteria/private.key

auth:
  type: password
  password: $my_uuid 

masquerade: 
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true
EOF
echo "$file_path1"
cat << EOF > "$file_path2"
mode: rule
ipv6: true
log-level: silent
allow-lan: true
mixed-port: 7890
unified-delay: false
tcp-concurrent: true
external-controller-tls: 127.0.0.1:9090
find-process-mode: strict
global-client-fingerprint: chrome
profile: {store-selected: true, store-fake-ip: true}

sniffer:
  enable: true
  parse-pure-ip: true
  sniff: {HTTP: {ports: [80, 8080-8880], override-destination: true}, TLS: {ports: [443, 8443]}, QUIC: {ports: [443, 8443]}}
  skip-domain: ['Mijia Cloud']

tun:
  enable: true
  stack: system
  dns-hijack: ['any:53']
  auto-route: true
  auto-detect-interface: true
  strict-route: true
dns:
  enable: true
  listen: :1053
  ipv6: true
  # 路由器个人建议使用 redir-host 以最佳兼容性
  # 其他设备可以使用 fake-ip
  enhanced-mode: fake-ip
  fake-ip-range: 28.0.0.1/8
  fake-ip-filter:
    - '+.lan'
    - '+.local'
    - www.baidu.com

  nameserver:
    - 'tls://8.8.4.4#dns'
    - 'tls://1.0.0.1#dns'
    - 'tls://[2001:4860:4860::8844]#dns'
    - 'tls://[2606:4700:4700::1001]#dns'


proxy-providers:
  provider1:
    type: http
    url: "https://nachoneko.cn/api/v1/client/subscribe?token=523b649f50410fffc48e446869c7a2c4&host=pull.free.video.10010.com"
    path: ./proxy_providers/provider1.yaml
    interval: 3600
proxies:
- name: "${my_name}"
  type: hysteria2
  server: $my_ip
  port: 443
  # ports: 10000-20000/443
  #  up和down均不写或为0则使用BBR流控
  # up: "30 Mbps" # 若不写单位，默认为 Mbps
  # down: "200 Mbps" # 若不写单位，默认为 Mbps
  password: $my_uuid
  # obfs: salamander # 默认为空，如果填写则开启obfs，目前仅支持salamander
  # obfs-password: yourpassword
  sni: www.bing.com
  skip-cert-verify: true
  # fingerprint: xxxx
  alpn:
    - h3
  # ca: "./my.ca"
  # ca-str: "xyz"
  quic:
  initStreamReceiveWindow: 8388608 
  maxStreamReceiveWindow: 8388608 
  initConnReceiveWindow: 20971520 
  maxConnReceiveWindow: 20971520 
  maxIdleTimeout: 30s 
  keepAlivePeriod: 10s 
  disablePathMTUDiscovery: false 
proxy-groups:
- name: "亚太地区"
  type: select
  proxies:
  - DIRECT
  - 其他地区
  url: 'https://www.gstatic.com/generate_204'
  interval: 300
  lazy: true
  timeout: 5000

  disable-udp: false
  include-all: true
  include-all-proxies: false
  include-all-providers: false
  filter: "(?i)港|台|新加|日|美|韩|泰"
- name: "国内地区"
  type: select
  proxies:
  - DIRECT

  url: 'https://www.gstatic.com/generate_204'
  interval: 300
  lazy: true
  timeout: 5000

  disable-udp: false
  include-all: true
  include-all-proxies: false
  include-all-providers: false
  filter: "(?i)移动|联通|电信"  
- name: "其他地区"
  type: select
  proxies:
  

  url: 'https://www.gstatic.com/generate_204'
  interval: 300
  lazy: true
  timeout: 5000

  disable-udp: false
  include-all: true
  include-all-proxies: false
  include-all-providers: false
  exclude-filter: "(?i)港|台|新加|日|美|移动|联通|电信|韩|泰"
 
rule-providers:
  ads:
    type: http
    behavior: domain
    format: text
    path: ./rules/ads.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/ads.list"
    interval: 86400

  applications:
    type: http
    behavior: classical
    format: text
    path: ./rules/applications.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/applications.list"
    interval: 86400

  private:
    type: http
    behavior: domain
    format: text
    path: ./rules/private.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/private.list"
    interval: 86400

  microsoft-cn:
    type: http
    behavior: domain
    format: text
    path: ./rules/microsoft-cn.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/microsoft-cn.list"
    interval: 86400

  apple-cn:
    type: http
    behavior: domain
    format: text
    path: ./rules/apple-cn.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/apple-cn.list"
    interval: 86400

  google-cn:
    type: http
    behavior: domain
    format: text
    path: ./rules/google-cn.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/google-cn.list"
    interval: 86400

  games-cn:
    type: http
    behavior: domain
    format: text
    path: ./rules/games-cn.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/games-cn.list"
    interval: 86400

  networktest:
    type: http
    behavior: classical
    format: text
    path: ./rules/networktest.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/networktest.list"
    interval: 86400

  proxy:
    type: http
    behavior: domain
    format: text
    path: ./rules/proxy.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/proxy.list"
    interval: 86400

  cn:
    type: http
    behavior: domain
    format: text
    path: ./rules/cn.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/cn.list"
    interval: 86400

  telegramip:
    type: http
    behavior: ipcidr
    format: text
    path: ./rules/telegramip.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/telegramip.list"
    interval: 86400

  privateip:
    type: http
    behavior: ipcidr
    format: text
    path: ./rules/privateip.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/privateip.list"
    interval: 86400

  cnip:
    type: http
    behavior: ipcidr
    format: text
    path: ./rules/cnip.list
    url: "https://cdn.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/cnip.list"
    interval: 86400

rules:
  - RULE-SET,ads,REJECT

  - RULE-SET,cn,国内地区

  - RULE-SET,cnip,国内地区
  - MATCH,亚太地区


EOF
echo "$file_path2"


cat << 'EOF' > "$file_path6"
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	# server_tokens off;

	# server_names_hash_bucket_size 64;
	# server_name_in_redirect off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	##
	# SSL Settings
	##

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
	ssl_prefer_server_ciphers on;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	##
	# Gzip Settings
	##

	gzip on;

	# gzip_vary on;
	# gzip_proxied any;
	# gzip_comp_level 6;
	# gzip_buffers 16 8k;
	# gzip_http_version 1.1;
	# gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;

server {
    
    listen 8080 ssl;
    
      ssl_certificate /root/ygkkkca/cert.crt;
    ssl_certificate_key /root/ygkkkca/private.key;

    location /ddas {
        alias /etc/hysteria/;
        autoindex on;  # 可选，启用目录列表
    }

}  
}
#	# See sample authentication script at:
#	# http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
# 
#	# auth_http localhost/auth.php;
#	# pop3_capabilities "TOP" "USER";
#	# imap_capabilities "IMAP4rev1" "UIDPLUS";
# 
#	server {
#		listen     localhost:110;
#		protocol   pop3;
#		proxy      on;
#	}
# 
#	server {
#		listen     localhost:143;
#		protocol   imap;
#		proxy      on;
#	}
#}

EOF
echo "$file_path6"


nginx -s reload

rm /etc/systemd/system/hysteria-server.service
touch /etc/systemd/system/hysteria.service

cat << 'EOF' > /etc/systemd/system/hysteria.service

[Unit]
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml --log-level info
Restart=on-failure
RestartSec=10
LimitNPROC=512
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target

EOF

systemctl daemon-reload

reboot