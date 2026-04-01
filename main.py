from time import sleep
import requests
import argparse

parse = argparse.ArgumentParser(description="WAF Tespit Tool'u")
parse.add_argument("-u", help="Hedef site", required=True, type=str)

args = parse.parse_args()
site = args.u

print(""""
  █████╗ ██╗     ███████╗██╗  ██╗
 ██╔══██╗██║     ██╔════╝╚██╗██╔╝
 ███████║██║     █████╗   ╚███╔╝ 
 ██╔══██║██║     ██╔══╝   ██╔██╗ 
 ██║  ██║███████╗███████╗██╔╝ ██╗
 ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
""")

print(f"{site} taranmaya başlanıyor...")
sleep(2)

try:
    res = requests.get(site, timeout=5)
    
    if res.status_code == 200:
        headers = res.headers
        score = 0
        waf_name = "Bilinmiyor"

        # 1. Server header
        server = headers.get("Server", "")
        if "cloudflare" in server.lower():
            score += 40
            waf_name = "Cloudflare"

        # 2. CF header kontrolü
        for key in headers:
            if key.lower().startswith("cf-"):
                score += 30
                waf_name = "Cloudflare"

        # 3. Cookie kontrolü
        if "__cf_bm" in headers.get("Set-Cookie", ""):
            score += 30
            waf_name = "Cloudflare"

        print(f"Skor: {score}")

        if score >= 80:
            print(f"WAF kesin: {waf_name}")
        elif score >= 40:
            print(f"Muhtemel WAF: {waf_name}")
        else:
            print("WAF tespit edilemedi")

    else:
        print("Site erişilebilir ama beklenmeyen status code:", res.status_code)

except requests.exceptions.RequestException as e:
    print(f"Hata: {e}")