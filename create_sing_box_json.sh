#!/bin/bash
htmlid=$(curl -X PUT 'http://127.0.0.1:8080/put' -H 'User-Agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36' -H 'Accept-Encoding: gzip, deflate, br, zstd' -H 'Content-Type: application/json' -H 'sec-ch-ua: "Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"' -H 'sec-ch-ua-platform: "Android"' -H 'sec-ch-ua-mobile: ?1' -H 'Origin: http://127.0.0.1:8080' -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-Mode: cors' -H 'Sec-Fetch-Dest: empty' -H 'Referer: http://127.0.0.1:8080/' -H 'Accept-Language: zh-CN,zh;q=0.9,en;q=0.8' -d '{
  "Sub": "http://127.0.0.1/ddas/clash_meta_client.yaml|https://nachoneko.cn/api/v1/client/subscribe?token=523b649f50410fffc48e446869c7a2c4&host=pull.free.video.10010.com",
  "Include": "",
  "Exclude": "",
  "Config": "",
  "ConfigUrl": "https://127.0.0.1/ddas/muban.json",
  "AddTag": true,
  "DisableUrlTest": true
}')

echo "http://127.0.0.1:8080/sub?id=${htmlid}"

curl -X GET "http://127.0.0.1:8080/sub?id=${htmlid}" -H 'User-Agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H 'Accept-Encoding: gzip, deflate, br, zstd' -H 'Cache-Control: max-age=0' -H 'sec-ch-ua: "Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"' -H 'sec-ch-ua-mobile: ?1' -H 'sec-ch-ua-platform: "Android"' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Site: none' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-User: ?1' -H 'Sec-Fetch-Dest: document' -H 'Accept-Language: zh-CN,zh;q=0.9,en;q=0.8' -o /etc/sing-box/new.json
