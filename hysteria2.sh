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
file_path2="/etc/hysteria/clash_meta_client.yaml"l
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
    url: https://www.google.com/ 
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
  prefer-h3: true
  ipv6: true
  listen: 0.0.0.0:1053
  fake-ip-range: 198.18.0.1/16
  enhanced-mode: fake-ip
  fake-ip-filter:
    - '*.lan'
    - '*.localdomain'
    - '*.example'
    - '*.invalid'
    - '*.localhost'
    - '*.test'
    - '*.local'
    - '*.home.arpa'
    - 'time.*.com'
    - 'time.*.gov'
    - 'time.*.edu.cn'
    - 'time.*.apple.com'
    - 'time-ios.apple.com'
    - 'time1.*.com'
    - 'time2.*.com'
    - 'time3.*.com'
    - 'time4.*.com'
    - 'time5.*.com'
    - 'time6.*.com'
    - 'time7.*.com'
    - 'ntp.*.com'
    - 'ntp1.*.com'
    - 'ntp2.*.com'
    - 'ntp3.*.com'
    - 'ntp4.*.com'
    - 'ntp5.*.com'
    - 'ntp6.*.com'
    - 'ntp7.*.com'
    - '*.time.edu.cn'
    - '*.ntp.org.cn'
    - '+.pool.ntp.org'
    - 'time1.cloud.tencent.com'
    - 'music.163.com'
    - '*.music.163.com'
    - '*.126.net'
    - 'musicapi.taihe.com'
    - 'music.taihe.com'
    - 'songsearch.kugou.com'
    - 'trackercdn.kugou.com'
    - '*.kuwo.cn'
    - 'api-jooxtt.sanook.com'
    - 'api.joox.com'
    - 'joox.com'
    - 'y.qq.com'
    - '*.y.qq.com'
    - 'streamoc.music.tc.qq.com'
    - 'mobileoc.music.tc.qq.com'
    - 'isure.stream.qqmusic.qq.com'
    - 'dl.stream.qqmusic.qq.com'
    - 'aqqmusic.tc.qq.com'
    - 'amobile.music.tc.qq.com'
    - '*.xiami.com'
    - '*.music.migu.cn'
    - 'music.migu.cn'
    - '+.msftconnecttest.com'
    - '+.msftncsi.com'
    - 'localhost.ptlogin2.qq.com'
    - 'localhost.sec.qq.com'
    - '+.qq.com'
    - '+.tencent.com'
    - '+.srv.nintendo.net'
    - '*.n.n.srv.nintendo.net'
    - '+.stun.playstation.net'
    - 'xbox.*.*.microsoft.com'
    - '*.*.xboxlive.com'
    - 'xbox.*.microsoft.com'
    - 'xnotify.xboxlive.com'
    - '+.battlenet.com.cn'
    - '+.wotgame.cn'
    - '+.wggames.cn'
    - '+.wowsgame.cn'
    - '+.wargaming.net'
    - 'proxy.golang.org'
    - 'stun.*.*'
    - 'stun.*.*.*'
    - '+.stun.*.*'
    - '+.stun.*.*.*'
    - '+.stun.*.*.*.*'
    - '+.stun.*.*.*.*.*'
    - 'heartbeat.belkin.com'
    - '*.linksys.com'
    - '*.linksyssmartwifi.com'
    - '*.router.asus.com'
    - 'mesu.apple.com'
    - 'swscan.apple.com'
    - 'swquery.apple.com'
    - 'swdownload.apple.com'
    - 'swcdn.apple.com'
    - 'swdist.apple.com'
    - 'lens.l.google.com'
    - 'stun.l.google.com'
    - 'na.b.g-tun.com'
    - '+.nflxvideo.net'
    - '*.square-enix.com'
    - '*.finalfantasyxiv.com'
    - '*.ffxiv.com'
    - '*.ff14.sdo.com'
    - 'ff.dorado.sdo.com'
    - '*.mcdn.bilivideo.cn'
    - '+.media.dssott.com'
    - 'shark007.net'
    - 'Mijia Cloud'
    - '+.cmbchina.com'
    - '+.cmbimg.com'
    - 'adguardteam.github.io'
    - 'adrules.top'
    - 'anti-ad.net'
    - 'local.adguard.org'
    - 'static.adtidy.org'
    - '+.sandai.net'
    - '+.n0808.com'
    - '+.3gppnetwork.org'
  default-nameserver:
    - https://223.5.5.5/dns-query
    - https://1.12.12.12/dns-query
  nameserver:
    - https://dns.alidns.com/dns-query#h3=true
    - https://doh.pub/dns-query
  nameserver-policy:
    'rule-set:ads': rcode://success
    'rule-set:microsoft-cn,apple-cn,google-cn,games-cn': [https://dns.alidns.com/dns-query#h3=true, https://doh.pub/dns-query]
    'rule-set:cn,private': [https://dns.alidns.com/dns-query#h3=true, https://doh.pub/dns-query]
    'rule-set:proxy': ['https://cloudflare-dns.com/dns-query#🪜 代理域名&h3=true', 'https://dns.google/dns-query#🪜 代理域名']

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
  sni: bing.com
  skip-cert-verify: true
  # fingerprint: xxxx
  alpn:
    - h3
  # ca: "./my.ca"
  # ca-str: "xyz"
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
systemctl start sing-box.service

nginx -s reload
