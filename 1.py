import aiohttp
import asyncio
from urllib.parse import urljoin


async def check_url(session, url):
    """Асинхронная проверка URL"""
    try:
        async with session.get(url, timeout=5, ssl=False) as response:
            text = await response.text()
            if any(keyword in text.lower() for keyword in ['login', 'password', 'router', 'admin']):
                print(f"[+] {url} - {response.status}")
                return url
    except:
        pass
    return None


async def scan_router_async(ip):
    """Асинхронное сканирование"""
    base_urls = [
        f"http://{ip}",
        f"https://{ip}",
        f"http://{ip}:8080",
        f"https://{ip}:8443",
        f"http://{ip}:80",
        f"https://{ip}:443"
    ]

    paths = [
        '', '/admin', '/login', '/cgi-bin/luci', '/goform/login',
        '/admin/login.html', '/index.html', '/home.htm'
    ]

    urls_to_check = []
    for base in base_urls:
        for path in paths:
            urls_to_check.append(urljoin(base, path))

    async with aiohttp.ClientSession() as session:
        tasks = [check_url(session, url) for url in urls_to_check]
        results = await asyncio.gather(*tasks)

    found = [r for r in results if r]
    if found:
        print(f"\n[!] Найдено {len(found)} панелей:")
        for url in found:
            print(f"    {url}")
    else:
        print("[-] Панели не найдены")


if __name__ == "__main__":
    target = input("Введите IP роутера: ").strip()
    asyncio.run(scan_router_async(target))