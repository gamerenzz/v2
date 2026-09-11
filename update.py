import base64
import json
import re
import requests
import yaml
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 1. 解密密钥与偏移量 (AES-256-CBC)
KEY = b"36KeAARKZuKF39N9LFyycLUyKMhZDq0B"
IV = b"36KeAARKZuKF39N9"

# 2. 真实有效的主订阅源列表（按优先级排列）
URLS = [
    "https://raw.githubusercontent.com/bannedbook/fanqiang/refs/heads/master/docs/vsp-cn.py"

]

def fetch_and_decrypt():
    headers = {"User-Agent": "NekoBox/Android/6.5.0"}
    for url in URLS:
        try:
            print(f"[*] 正在尝试拉取: {url}")
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200 and resp.text.strip():
                encrypted_base64 = resp.text.strip()
                raw_cipher = base64.b64decode(encrypted_base64)
                cipher = AES.new(KEY, AES.MODE_CBC, IV)
                decrypted = unpad(cipher.decrypt(raw_cipher), AES.block_size).decode('utf-8')
                print("[+] 解密成功！")
                return decrypted
        except Exception as e:
            print(f"[-] 请求/解密失败: {e}")
    raise Exception("所有订阅源均无法拉取/解密！")

def clean_node_name(ps_name, server_addr, existing_names):
    name = ps_name.strip()
    if name.startswith("http://") or name.startswith("https://") or not name:
        prefix = server_addr.split("-")[0] if "-" in server_addr else server_addr.split(".")[0]
        name = prefix.lower()

    original_name = name
    count = 1
    while name in existing_names:
        name = f"{original_name}-{count}"
        count += 1
    existing_names.add(name)
    return name

def parse_vmess_links(decrypted_text):
    vmess_nodes = []
    existing_names = set()
    
    links = re.findall(r'vmess://[a-zA-Z0-9+/=]+', decrypted_text)
    for link in links:
        try:
            b64_str = link.replace("vmess://", "")
            raw_json = base64.b64decode(b64_str).decode('utf-8')
            node_info = json.loads(raw_json)
            
            valid_name = clean_node_name(node_info.get("ps", ""), node_info.get("add", ""), existing_names)
            node_info["ps"] = valid_name
            
            new_b64 = base64.b64encode(json.dumps(node_info).encode('utf-8')).decode('utf-8')
            new_link = f"vmess://{new_b64}"
            
            vmess_nodes.append((new_link, node_info))
        except Exception as e:
            print(f"[-] 解析节点异常: {e}")
    return vmess_nodes

def generate_v2ray(vmess_nodes):
    all_links = "\n".join([item[0] for item in vmess_nodes])
    return base64.b64encode(all_links.encode('utf-8')).decode('utf-8')

def generate_clash(vmess_nodes):
    proxies = []
    proxy_names = []

    for _, n in vmess_nodes:
        name = n.get("ps")
        proxy_names.append(name)
        
        server_host = n.get("host") if n.get("host") else n.get("add")
        proxy_item = {
            "name": name,
            "type": "vmess",
            "server": n.get("add"),
            "port": int(n.get("port", 80)),
            "uuid": n.get("id"),
            "alterId": int(n.get("aid", 0)),
            "cipher": n.get("scy", "auto"),
            "udp": True,
            "tls": False,
            "network": "http",
            "http-opts": {
                "path": [n.get("path", "/")],
                "headers": {
                    "Host": [server_host]
                }
            }
        }
        if n.get("net") == "httpupgrade":
            proxy_item["http-opts"]["v2ray-http-upgrade"] = True
            
        proxies.append(proxy_item)

    clash_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["AUTO"] + proxy_names
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "url": "https://cp.cloudflare.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names
            }
        ],
        "rules": [
            "DOMAIN-SUFFIX,18838005.xyz,DIRECT",
            "DOMAIN-SUFFIX,cn,DIRECT",
            "DOMAIN-KEYWORD,baidu,DIRECT",
            "DOMAIN-KEYWORD,qq,DIRECT",
            "DOMAIN-KEYWORD,weixin,DIRECT",
            "DOMAIN-KEYWORD,alipay,DIRECT",
            "DOMAIN-KEYWORD,taobao,DIRECT",
            "DOMAIN-KEYWORD,bilibili,DIRECT",
            "DOMAIN-KEYWORD,jd,DIRECT",
            "GEOIP,LAN,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,PROXY"
        ]
    }
    return yaml.dump(clash_config, allow_unicode=True, sort_keys=False)

def generate_singbox(vmess_nodes):
    node_tags = [n.get("ps") for _, n in vmess_nodes]
    
    outbounds = [
        {
            "type": "selector",
            "tag": "proxy",
            "outbounds": ["auto"] + node_tags,
            "default": "auto"
        },
        {
            "type": "urltest",
            "tag": "auto",
            "outbounds": node_tags,
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": "3m",
            "idle_timeout": "30m"
        }
    ]

    for _, n in vmess_nodes:
        server_host = n.get("host") if n.get("host") else n.get("add")
        node_outbound = {
            "type": "vmess",
            "tag": n.get("ps"),
            "server": n.get("add"),
            "server_port": int(n.get("port", 80)),
            "uuid": n.get("id"),
            "security": n.get("scy", "auto"),
            "alter_id": int(n.get("aid", 0)),
            "transport": {
                "type": n.get("net", "httpupgrade"),
                "host": server_host,
                "path": n.get("path", "/")
            }
        }
        outbounds.append(node_outbound)

    outbounds.append({"type": "direct", "tag": "direct"})
    outbounds.append({"type": "block", "tag": "block"})

    singbox_config = {
        "log": {
            "level": "debug",
            "timestamp": True
        },
        "dns": {
            "servers": [
                {
                    "type": "tcp",
                    "tag": "dns-remote",
                    "server": "8.8.8.8",
                    "server_port": 53,
                    "detour": "proxy"
                },
                {
                    "type": "udp",
                    "tag": "dns-direct",
                    "server": "223.5.5.5",
                    "server_port": 53
                }
            ],
            "rules": [
                {
                    "domain_suffix": [
                        "18838005.xyz",
                        ".cn"
                    ],
                    "server": "dns-direct"
                },
                {
                    "domain_keyword": [
                        "baidu",
                        "qq",
                        "weixin",
                        "alipay",
                        "taobao",
                        "bilibili"
                    ],
                    "server": "dns-direct"
                }
            ],
            "final": "dns-remote",
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": [
                    "172.19.0.1/30"
                ],
                "auto_route": True,
                "strict_route": True
            }
        ],
        "outbounds": outbounds,
        "route": {
            "default_domain_resolver": "dns-direct",
            "rules": [
                {
                    "action": "sniff"
                },
                {
                    "protocol": "dns",
                    "action": "hijack-dns"
                },
                {
                    "network": "udp",
                    "port": 443,
                    "action": "reject"
                },
                {
                    "ip_is_private": True,
                    "action": "route",
                    "outbound": "direct"
                },
                {
                    "domain_suffix": [
                        ".cn",
                        "18838005.xyz"
                    ],
                    "action": "route",
                    "outbound": "direct"
                },
                {
                    "domain_keyword": [
                        "baidu",
                        "qq",
                        "weixin",
                        "alipay",
                        "taobao",
                        "bilibili",
                        "jd"
                    ],
                    "action": "route",
                    "outbound": "direct"
                }
            ],
            "auto_detect_interface": True,
            "final": "proxy"
        }
    }
    return json.dumps(singbox_config, indent=2, ensure_ascii=False)

def main():
    decrypted_text = fetch_and_decrypt()
    nodes = parse_vmess_links(decrypted_text)
    print(f"[*] 成功获取并解密 {len(nodes)} 个节点：{[n['ps'] for _, n in nodes]}")

    with open("v2ray.txt", "w", encoding="utf-8") as f:
        f.write(generate_v2ray(nodes))

    with open("clash.yaml", "w", encoding="utf-8") as f:
        f.write(generate_clash(nodes))

    with open("singbox.json", "w", encoding="utf-8") as f:
        f.write(generate_singbox(nodes))

    print("[+] 全部更新完毕！")

if __name__ == "__main__":
    main()
