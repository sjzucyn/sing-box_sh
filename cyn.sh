#!/bin/bash

apt install nginx -y  && yum install nginx -y
bash <(curl -L -s https://gitlab.com/rwkgyg/acme-script/raw/main/acme.sh)
my_ip=$(curl -s https://api.ipify.org)

set -e -o pipefail
curl -fsSL https://get.docker.com | bash -s docker
docker volume create clash2sfa    
docker run -d -p 8080:8080 -v clash2sfa:/server/db ghcr.io/xmdhs/clash2sfa

ARCH_RAW=$(uname -m)
case "${ARCH_RAW}" in
    'x86_64')    ARCH='amd64';;
    'x86' | 'i686' | 'i386')     ARCH='386';;
    'aarch64' | 'arm64') ARCH='arm64';;
    'armv7l')   ARCH='armv7';;
    's390x')    ARCH='s390x';;
    *)          echo "Unsupported architecture: ${ARCH_RAW}"; exit 1;;
esac

VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest \
    | grep tag_name \
    | cut -d ":" -f2 \
    | sed 's/\"//g;s/\,//g;s/\ //g;s/v//')

curl -Lo sing-box.deb "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box_${VERSION}_linux_${ARCH}.deb"
sudo dpkg -i sing-box.deb
rm sing-box.deb
touch /etc/nginx/sites-enabled/default
touch /etc/nginx/sites-available/default
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default

cd /etc/sing-box
openssl ecparam -genkey -name prime256v1 -out private.key
openssl req -new -x509 -days 36500 -key private.key -out cert.crt -subj "/CN=www.bing.com"
# 指定文件路径
file_path1="/etc/sing-box/muban.json"
file_path2="/etc/sing-box/clash_meta_client.yaml"
file_path3="/etc/sing-box/sing_box_client.json"
file_path4="/etc/sing-box/config.json"
file_path5="/etc/systemd/system/sing-box.service"
file_path6="/etc/nginx/nginx.conf"
echo "请输入您的uuid："
read my_uuid
echo "您好，设置uuid为$my_uuid"
echo "请输入您的节点名称tag："
read my_pass_id
echo "您好，设置节点tag为$my_pass_id"
# 创建文件并写入多行内容
touch "$file_path1"
touch "$file_path2"
touch "$file_path3"
touch "$file_path4"
touch "$file_path5"
touch "$file_path6"
cat << EOF > "$file_path1"
{
	"log": {
		"disabled": true,
		"level": "trace",
		"output": "box.log",
		"timestamp": true
	},
	"dns": {
		"servers": [{
				"tag": "dns_proxy",
				"address": "https://1.1.1.1/dns-query",
				"address_resolver": "dns_resolver",
				"strategy": "prefer_ipv4",
				"detour": "亚太地区"
			},
			{
				"tag": "dns_direct",
				"address": "h3://dns.alidns.com/dns-query",
				"address_resolver": "dns_resolver",
				"strategy": "prefer_ipv4",
				"detour": "direct"
			},
			{
				"tag": "dns_block",
				"address": "rcode://refused"
			},
			{
				"tag": "dns_resolver",
				"address": "223.5.5.5",
				"strategy": "prefer_ipv4",
				"detour": "direct"
			}
		],
		"rules": [{
				"outbound": "any",
				"server": "dns_resolver"
			},
			{
				"clash_mode": "direct",
				"server": "dns_direct"
			},
			{
				"clash_mode": "global",
				"server": "dns_proxy"
			},
			{
				"rule_set": [
					"geosite-cn"
				],
				"server": "dns_direct"
			},

			{
				"domain_suffix": [
					"icloudnative.io",
					"fuckcloudnative.io",
					"sealos.io",
					"cdn.jsdelivr.net"
				],
				"server": "dns_direct"
			}

		],
		"final": "dns_proxy"
	},
	"ntp": {
		"enabled": true,
		"server": "time.apple.com",
		"server_port": 123,
		"interval": "30m0s",
		"detour": "direct"
	},
	"inbounds": [

		{
			"tag": "tun-in",
			"type": "tun",
			"inet4_address": "172.19.0.1/30",
			"inet6_address": "fdfe:dcba:9876::1/126",
			"auto_route": true,
			"strict_route": true,
			"stack": "system",
			"mtu": 9000,
			"sniff": true
		}
	],
	"outbounds": [

		{
			"tag": "亚太地区",
			"type": "selector",
			"outbounds": [
				"include: (?i)港|台|新加|日|美|韩|泰"
				
					

			]
		},
		{
			"tag": "其他地区",
			"type": "selector",
			"outbounds": [

				"exclude: (?i)港|台|新加|日|美|移动|联通|电信|韩|泰|最新|回国|以下"

			]
		},

		{
			"tag": "国内",
			"type": "selector",
			"outbounds": [
				"direct",
				"include: (?i)移动|联通|电信"

			]
		}

	],
	"route": {
		"rules": [{
				"protocol": "dns",
				"outbound": "dns-out"
			},
			{
				"clash_mode": "direct",
				"outbound": "direct"
			},
			{
				"clash_mode": "global",
				"outbound": "亚太地区"
			},
			{
				"protocol": "quic",
				"outbound": "block"
			},
			{
				"inbound": "socks-in",
				"outbound": "亚太地区"
			},
			{
				"rule_set": "geosite-category-ads-all",
				"outbound": "block"
			},
			{
				"rule_set": "geoip-cn",
				"outbound": "国内"
			},
			{
				"ip_is_private": true,
				"ip_cidr": \ "${my_ip}\",
				"outbound": "direct"
			}
		],
		"rule_set": [{
				"tag": "geoip-cn",
				"type": "remote",
				"format": "binary",
				"url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
				"download_detour": "亚太地区"
			},
			{
				"tag": "geosite-cn",
				"type": "remote",
				"format": "binary",
				"url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
				"download_detour": "亚太地区"
			},
			{
				"tag": "geosite-private",
				"type": "remote",
				"format": "binary",
				"url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-private.srs",
				"download_detour": "亚太地区"
			},
			{
				"tag": "geosite-category-ads-all",
				"type": "remote",
				"format": "binary",
				"url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
				"download_detour": "亚太地区"
			}
		],
		"final": "亚太地区",
		"find_process": true,
		"auto_detect_interface": true
	},
	"experimental": {
		"cache_file": {
			"enabled": true
		},
		"clash_api": {
			"external_controller": "0.0.0.0:9090",
			"external_ui": "metacubexd",
			"external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
			"external_ui_download_detour": "亚太地区",
			"default_mode": "rule"
		}
	}
}
EOF
echo "$file_path1"
cat << EOF > "$file_path2"
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: vless-reality-vision-$my_pass_id               
  type: vless
  server: $my_ip                           
  port: 48631                                
  uuid: $my_uuid   
  network: tcp
  udp: true
  tls: true
  flow: xtls-rprx-vision
  servername: www.yahoo.com                 
  reality-opts: 
    public-key: qNepGdsIFnbqcyT7K_SNMs_sVt4DPx6RuEm1CVDAhU8    
    short-id: 4f4dadbc                      
  client-fingerprint: chrome                  

- name: vmess-ws-$my_pass_id                         
  type: vmess
  server: $my_ip                        
  port: 80                                     
  uuid: $my_uuid       
  alterId: 0
  cipher: auto
  udp: true
  tls: false
  network: ws
  servername: www.bing.com                    
  ws-opts:
    path: "$my_uuid-vm"                             
    headers:
      Host: host=pull.free.video.10010.com                     

- name: hysteria2-$my_pass_id                            
  type: hysteria2                                      
  server: $my_ip                               
  port: 13129                                
  password: $my_uuid                          
  alpn:
    - h3
  sni: www.bing.com                               
  skip-cert-verify: true
  fast-open: true

- name: tuic5-$my_pass_id                            
  server: $my_ip                      
  port: 59488                                    
  type: tuic
  uuid: $my_uuid       
  password: $my_uuid   
  alpn: [h3]
  disable-sni: true
  reduce-rtt: true
  udp-relay-mode: native
  congestion-controller: bbr
  sni: www.bing.com                                
  skip-cert-verify: true  

proxy-groups:
- name: 负载均衡
  type: load-balance
  url: https://www.gstatic.com/generate_204
  interval: 300
  strategy: round-robin
  proxies:
    - vless-reality-vision-$my_pass_id                              
    - vmess-ws-$my_pass_id
    - hysteria2-$my_pass_id
    - tuic5-$my_pass_id

- name: 自动选择
  type: url-test
  url: https://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - vless-reality-vision-$my_pass_id                              
    - vmess-ws-$my_pass_id
    - hysteria2-$my_pass_id
    - tuic5-$my_pass_id
    
- name: 🌍选择代理节点
  type: select
  proxies:
    - 负载均衡                                         
    - 自动选择
    - DIRECT
    - vless-reality-vision-$my_pass_id                              
    - vmess-ws-$my_pass_id
    - hysteria2-$my_pass_id
    - tuic5-$my_pass_id
rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理节点

EOF
echo "$file_path2"

cat << EOF > "$file_path3"
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "external_ui_download_url": "",
      "external_ui_download_detour": "",
      "secret": "",
      "default_mode": "Rule"
       },
      "cache_file": {
            "enabled": true,
            "path": "cache.db",
            "store_fakeip": true
        }
    },
    "dns": {
        "servers": [
            {
                "tag": "proxydns",
                "address": "tls://8.8.8.8/dns-query",
                "detour": "select"
            },
            {
                "tag": "localdns",
                "address": "h3://223.5.5.5/dns-query",
                "detour": "direct"
            },
            {
                "address": "rcode://refused",
                "tag": "block"
            },
            {
                "tag": "dns_fakeip",
                "address": "fakeip"
            }
        ],
        "rules": [
            {
                "outbound": "any",
                "server": "localdns",
                "disable_cache": true
            },
            {
                "clash_mode": "Global",
                "server": "proxydns"
            },
            {
                "clash_mode": "Direct",
                "server": "localdns"
            },
            {
                "rule_set": "geosite-cn",
                "server": "localdns"
            },
            {
                 "rule_set": "geosite-geolocation-!cn",
                 "server": "proxydns"
            },
             {
                "rule_set": "geosite-geolocation-!cn",         
                "query_type": [
                    "A",
                    "AAAA"
                ],
                "server": "dns_fakeip"
            }
          ],
           "fakeip": {
           "enabled": true,
           "inet4_range": "198.18.0.0/15",
           "inet6_range": "fc00::/18"
         },
          "independent_cache": true,
          "final": "proxydns"
        },
      "inbounds": [
    {
      "type": "tun",
      "inet4_address": "172.19.0.1/30",
      "inet6_address": "fd00::1/126",
      "auto_route": true,
      "strict_route": true,
      "sniff": true,
      "sniff_override_destination": true,
      "domain_strategy": "prefer_ipv4"
    }
  ],
  "outbounds": [
    {
      "tag": "select",
      "type": "selector",
      "default": "auto",
      "outbounds": [
        "auto",
        "vless-$my_pass_id",
        "vmess-$my_pass_id",
        "hy2-$my_pass_id",
        "tuic5-$my_pass_id"
      ]
    },
    {
      "type": "vless",
      "tag": "vless-$my_pass_id",
      "server": "$my_ip",
      "server_port": 48631,
      "uuid": "$my_uuid",
      "packet_encoding": "xudp",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "www.yahoo.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
      "reality": {
          "enabled": true,
          "public_key": "qNepGdsIFnbqcyT7K_SNMs_sVt4DPx6RuEm1CVDAhU8",
          "short_id": "4f4dadbc"
        }
      }
    },
{
            "server": "$my_ip",
            "server_port": 80,
            "tag": "vmess-$my_pass_id",
            "tls": {
                "enabled": false,
                "server_name": "www.bing.com",
                "insecure": false,
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            },
            "packet_encoding": "packetaddr",
            "transport": {
                "headers": {
                    "Host": [
                        "host=pull.free.video.10010.com"
                    ]
                },
                "path": "$my_uuid-vm",
                "type": "ws"
            },
            "type": "vmess",
            "security": "auto",
            "uuid": "$my_uuid"
        },

    {
        "type": "hysteria2",
        "tag": "hy2-$my_pass_id",
        "server": "$my_ip",
        "server_port": 13129,
        "password": "$my_uuid",
        "tls": {
            "enabled": true,
            "server_name": "www.bing.com",
            "insecure": true,
            "alpn": [
                "h3"
            ]
        }
    },
        {
            "type":"tuic",
            "tag": "tuic5-$my_pass_id",
            "server": "$my_ip",
            "server_port": 59488,
            "uuid": "$my_uuid",
            "password": "$my_uuid",
            "congestion_control": "bbr",
            "udp_relay_mode": "native",
            "udp_over_stream": false,
            "zero_rtt_handshake": false,
            "heartbeat": "10s",
            "tls":{
                "enabled": true,
                "server_name": "www.bing.com",
                "insecure": true,
                "alpn": [
                    "h3"
                ]
            }
        },
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "block",
      "type": "block"
    },
    {
      "tag": "dns-out",
      "type": "dns"
    },
    {
      "tag": "auto",
      "type": "urltest",
      "outbounds": [
        "vless-$my_pass_id",
        "vmess-$my_pass_id",
        "hy2-$my_pass_id",
        "tuic5-$my_pass_id"
      ],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "1m",
      "tolerance": 50,
      "interrupt_exist_connections": false
    }
  ],
  "route": {
      "rule_set": [
            {
                "tag": "geosite-geolocation-!cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
            },
            {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
            },
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
            }
        ],
    "auto_detect_interface": true,
    "final": "select",
    "rules": [
      {
        "outbound": "dns-out",
        "protocol": "dns"
      },
      {
        "clash_mode": "Direct",
        "outbound": "direct"
      },
      {
        "clash_mode": "Global",
        "outbound": "select"
      },
      {
        "rule_set": "geoip-cn",
        "outbound": "direct"
      },
      {
        "rule_set": "geosite-cn",
        "outbound": "direct"
      },
      {
      "ip_is_private": true,
      "outbound": "direct"
      },
      {
        "rule_set": "geosite-geolocation-!cn",
        "outbound": "select"
      }
    ]
  },
    "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m",
    "detour": "direct"
  }
}

EOF
echo "$file_path3"
cat << EOF > "$file_path4"
{
"log": {
    "disabled": false,
    "level": "info",
	"output": "box.log",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "sniff": true,
      "sniff_override_destination": true,
      "tag": "vless-sb",
      "listen": "::",
      "listen_port": 48631,
      "users": [
        {
          "uuid": "$my_uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.yahoo.com",
          "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.yahoo.com",
            "server_port": 443
          },
          "private_key": "4KHbdsPOATIbsvrERziNM5ziJsGbyav6gaH26c_2aF8",
          "short_id": ["4f4dadbc"]
        }
      }
    },
{
        "type": "vmess",
        "sniff": true,
        "sniff_override_destination": true,
        "tag": "vmess-sb",
        "listen": "::",
        "listen_port": 80,
        "users": [
            {
                "uuid": "$my_uuid",
                "alterId": 0
            }
        ],
        "transport": {
            "type": "ws",
            "path": "$my_uuid-vm",
            "max_early_data":2048,
            "early_data_header_name": "Sec-WebSocket-Protocol"    
        },
        "tls":{
                "enabled": false,
                "server_name": "www.bing.com",
                "certificate_path": "/etc/sing-box/cert.crt",
                "key_path": "/etc/sing-box/private.key"
            }
    }, 
    {
        "type": "hysteria2",
        "sniff": true,
        "sniff_override_destination": true,
        "tag": "hy2-sb",
        "listen": "::",
        "listen_port": 13129,
        "users": [
            {
                "password": "$my_uuid"
            }
        ],
        "ignore_client_bandwidth":false,
        "tls": {
            "enabled": true,
            "alpn": [
                "h3"
            ],
            "certificate_path": "/etc/sing-box/cert.crt",
            "key_path": "/etc/sing-box/private.key"
        }
    },
        {
            "type":"tuic",
            "sniff": true,
            "sniff_override_destination": true,
            "tag": "tuic5-sb",
            "listen": "::",
            "listen_port": 59488,
            "users": [
                {
                    "uuid": "$my_uuid",
                    "password": "$my_uuid"
                }
            ],
            "congestion_control": "bbr",
            "tls":{
                "enabled": true,
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/etc/sing-box/cert.crt",
                "key_path": "/etc/sing-box/private.key"
            }
        }
],
"outbounds": [
{
"type":"direct",
"tag":"direct"

}
]
}
EOF
echo "$file_path4"
cat << 'EOF'> "$file_path5"
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/bin/sing-box -D /etc/sing-box -c /etc/sing-box/config.json run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target

EOF
echo "$file_path5"
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
    
    listen 443 ssl;
    
      ssl_certificate /root/ygkkkca/cert.crt;
    ssl_certificate_key /root/ygkkkca/private.key;

    location /ddas {
        alias /etc/sing-box/;
        autoindex on;  # 可选，启用目录列表
    }

}  
server {
    
    listen 10010 ssl;
    
      ssl_certificate /root/ygkkkca/cert.crt;
    ssl_certificate_key /root/ygkkkca/private.key;


      location / {
    proxy_pass  http://localhost:8080; # 转发规则
    proxy_set_header Host $proxy_host; # 修改转发请求头，让8080端口的应用可以受到真实的请求
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}  }
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