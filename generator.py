from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import platform
import random
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse, quote  # 修复: 增加了 quote

import requests
import yaml

VERSION = "v7"
OUTPUT_PATH = Path("output/clash.yaml")
TEST_URL = "http://www.gstatic.com/generate_204"
# 优化: 缩短超时时间并减少重试，避免死等
SOURCE_TIMEOUT = 10 
LATENCY_TIMEOUT_MS = 5000
MAX_RETRIES = 2
MAX_WORKERS = int(os.getenv("FREE_PROXY_AIRPORT_MAX_WORKERS", "24"))
MAX_CANDIDATES = int(os.getenv("FREE_PROXY_AIRPORT_MAX_CANDIDATES", "0"))

# (此处保留原有的 SOURCE_GROUPS 列表，为了节省篇幅已折叠，请保留你原有的 SOURCE_GROUPS)
SOURCE_GROUPS = [
    {
        "name": "openRunner clash-freenode",
        "primary": "https://raw.githubusercontent.com/openRunner/clash-freenode/main/sub.yaml",
        "fallbacks": [],
    },
    {
        "name": "snakem982 proxypool",
        "primary": "https://raw.githubusercontent.com/snakem982/proxypool/main/clash.yaml",
        "fallbacks": [],
    },
    # ... 请将你原本那 60 多个源粘贴在这里 ...
]

SUPPORTED_PROXY_TYPES = {
    "ss", "ssr", "vmess", "vless", "trojan", 
    "hysteria", "hysteria2", "hy2", "tuic", "socks5", "http"
}


@dataclass
class ProxyMetric:
    proxy: dict[str, Any]
    latency: int
    region: str
    health_score: float


def fetch_text(url: str, retries: int = MAX_RETRIES) -> str:
    headers = {
        "User-Agent": f"free-proxy-airport/{VERSION} (+https://github.com/)",
        "Accept": "text/plain, text/yaml, application/yaml, */*",
    }
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=SOURCE_TIMEOUT)
            response.raise_for_status()
            return response.content.decode("utf-8", errors="replace")
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(1 * attempt)
    raise RuntimeError(f"failed: {last_error}")


def maybe_base64_decode(text: str) -> str:
    compact = "".join(text.split())
    if not compact or len(compact) % 4 != 0:
        return text
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return text
    try:
        decoded = base64.b64decode(compact, validate=True).decode("utf-8")
    except Exception:
        return text
    return decoded if "proxies:" in decoded or "://" in decoded else text


def load_yaml_document(text: str) -> Any:
    try:
        decoded = maybe_base64_decode(text)
        return yaml.safe_load(decoded)
    except yaml.YAMLError as exc:
        return None


def parse_uri_proxy(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    
    match = re.match(r"^([a-z0-9]+)://", line)
    if not match:
        return None
    
    scheme = match.group(1).lower()
    if scheme not in SUPPORTED_PROXY_TYPES and scheme != "hy2":
        return None

    try:
        parsed = urlparse(line)
        name = unquote(parsed.fragment) or f"{scheme}-{parsed.hostname}"
        proxy = {
            "name": name,
            "type": "hysteria2" if scheme == "hy2" else scheme,
            "server": parsed.hostname,
            "port": parsed.port or (443 if scheme in ("vless", "trojan", "hysteria2") else 80),
        }

        if scheme in ("vless", "trojan", "vmess"):
            if parsed.username:
                proxy["uuid" if scheme in ("vless", "vmess") else "password"] = parsed.username
            query = parse_qs(parsed.query)
            if "security" in query: proxy["security"] = query["security"][0]
            if "type" in query: proxy["network"] = query["type"][0]
            if "sni" in query: proxy["servername"] = query["sni"][0]
            if "alpn" in query: proxy["alpn"] = query["alpn"][0].split(",")
            if "allowInsecure" in query or "insecure" in query:
                val = query.get("allowInsecure", query.get("insecure", ["0"]))[0]
                proxy["skip-cert-verify"] = val in ("1", "true", "True")

        elif scheme == "ss":
            if parsed.username:
                try:
                    userInfo = base64.b64decode(parsed.username + "==").decode("utf-8")
                    if ":" in userInfo:
                        cipher, password = userInfo.split(":", 1)
                        proxy["cipher"] = cipher
                        proxy["password"] = password
                except Exception:
                    pass
        return proxy
    except Exception:
        return None


def extract_proxy_block(text: str) -> list[Any]:
    lines = maybe_base64_decode(text).splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        if re.match(r"^proxies\s*:\s*$", line):
            start = index
            break
    if start is None:
        return []

    block: list[str] = []
    for line in lines[start + 1:]:
        if line and not line.startswith((" ", "\t", "-")) and re.match(r"^[A-Za-z0-9_-]+\s*:", line):
            break
        block.append(line)

    try:
        parsed = yaml.safe_load("proxies:\n" + "\n".join(block))
    except yaml.YAMLError:
        return []
    if isinstance(parsed, dict) and isinstance(parsed.get("proxies"), list):
        return parsed["proxies"]
    return []


def extract_proxies(text: str) -> list[dict[str, Any]]:
    document = load_yaml_document(text)
    proxies: list[Any] = []
    if isinstance(document, dict):
        proxies = document.get("proxies", [])
    elif isinstance(document, list):
        proxies = document
    
    if not proxies:
        proxies = extract_proxy_block(text)

    if not proxies:
        decoded_text = maybe_base64_decode(text)
        for line in decoded_text.splitlines():
            parsed_proxy = parse_uri_proxy(line)
            if parsed_proxy:
                proxies.append(parsed_proxy)

    clean: list[dict[str, Any]] = []
    for proxy in proxies:
        if isinstance(proxy, dict):
            clean.append(dict(proxy))
    return clean


# 优化: 并发抓取源，极大提升速度
def collect_proxies() -> tuple[int, list[dict[str, Any]]]:
    collected: list[dict[str, Any]] = []
    
    def fetch_source(source: dict) -> list[dict[str, Any]]:
        source_found = []
        for url in expand_source_urls(source):
            print(f"[FETCH] 正在抓取 -> {url}")
            try:
                text = fetch_text(url)
                found = extract_proxies(text)
                if found:
                    print(f"[OK] 成功抓取: {source['name']} ({len(found)} 节点)")
                    source_found.extend(found)
                    break
            except Exception as exc:
                print(f"[WARN] 抓取失败: {source['name']} | 错误: {exc}")
        return source_found

    # 10 个线程并发抓取
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(fetch_source, src) for src in SOURCE_GROUPS]
        for future in as_completed(futures):
            try:
                collected.extend(future.result())
            except Exception as e:
                pass

    sanitized = sanitize_and_deduplicate(collected)
    if MAX_CANDIDATES > 0 and len(sanitized) > MAX_CANDIDATES:
        print(f"[WARN] 限制测试节点数，从 {len(sanitized)} 截断为 {MAX_CANDIDATES}")
        sanitized = sanitized[:MAX_CANDIDATES]
    return len(collected), sanitized


def expand_source_urls(source: dict[str, Any]) -> list[str]:
    urls = [str(source["primary"])]
    for item in source.get("fallbacks", []):
        urls.append(str(item))
    return unique_ordered(urls)


def unique_ordered(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def sanitize_and_deduplicate(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen_fingerprints: set[str] = set()
    seen_names: set[str] = set()
    result: list[dict[str, Any]] = []

    for index, raw in enumerate(proxies, start=1):
        proxy = normalize_proxy(raw, index)
        if not proxy:
            continue

        fingerprint = proxy_fingerprint(proxy)
        if fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)

        base_name = str(proxy["name"]).strip() or f"node-{index}"
        name = base_name
        suffix = 2
        while name in seen_names:
            name = f"{base_name}-{suffix}"
            suffix += 1
        proxy["name"] = name
        seen_names.add(name)
        result.append(proxy)
    return result


def normalize_proxy(raw: dict[str, Any], index: int) -> dict[str, Any] | None:
    proxy = {key: value for key, value in raw.items() if value is not None}
    proxy_type = str(proxy.get("type", "")).lower().strip()
    if proxy_type not in SUPPORTED_PROXY_TYPES: return None
    if proxy_type == "hy2": proxy_type = "hysteria2"
    proxy["type"] = proxy_type
    name = str(proxy.get("name", "")).strip() or f"node-{index}"
    server = str(proxy.get("server", "")).strip()
    if not server: return None
    try:
        port = int(proxy.get("port"))
    except Exception:
        return None
    if port <= 0 or port > 65535: return None
    proxy["name"], proxy["server"], proxy["port"] = name, server, port
    return proxy


def proxy_fingerprint(proxy: dict[str, Any]) -> str:
    important = {
        "type": proxy.get("type"), "server": proxy.get("server"), "port": proxy.get("port"),
        "uuid": proxy.get("uuid"), "password": proxy.get("password"),
    }
    return hashlib.sha256(json.dumps(important, sort_keys=True).encode("utf-8")).hexdigest()


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def find_or_install_mihomo() -> Path:
    for name in ("mihomo", "clash-meta", "clash"):
        if found := shutil.which(name):
            print(f"[OK] 使用已存在的代理内核: {found}")
            return Path(found)

    install_dir = Path(tempfile.gettempdir()) / "free-proxy-airport-mihomo"
    install_dir.mkdir(parents=True, exist_ok=True)
    binary = install_dir / ("mihomo.exe" if os.name == "nt" else "mihomo")
    if binary.exists():
        return binary

    print("[INFO] 未找到本地代理内核，准备下载 Mihomo...")
    url = select_mihomo_asset()
    print(f"[INFO] 正在下载内核: {url}")
    archive = download_file(url, install_dir)
    extracted = extract_mihomo_binary(archive, install_dir)
    extracted.chmod(extracted.stat().st_mode | stat.S_IXUSR)
    if extracted != binary:
        shutil.copy2(extracted, binary)
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    return binary


def select_mihomo_asset() -> str:
    api_url = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
    data = requests.get(api_url, headers={"User-Agent": "free-proxy"}, timeout=15).json()
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    os_token = {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(system, "")
    arch_tokens = ["amd64-compatible", "amd64"] if machine in {"x86_64", "amd64"} else ["arm64"] if machine in {"arm64", "aarch64"} else []

    for asset in data.get("assets", []):
        name = str(asset.get("name", "")).lower()
        if os_token in name and any(t in name for t in arch_tokens) and (name.endswith(".gz") or name.endswith(".zip")):
            return asset.get("browser_download_url", "")
    raise RuntimeError("未找到适用的 Mihomo 内核包")


def download_file(url: str, directory: Path) -> Path:
    target = directory / Path(url.split("?")[0]).name
    with requests.get(url, stream=True, timeout=30) as response:
        response.raise_for_status()
        with target.open("wb") as file:
            for chunk in response.iter_content(chunk_size=1024 * 512):
                if chunk: file.write(chunk)
    return target


def extract_mihomo_binary(archive: Path, directory: Path) -> Path:
    if archive.suffix == ".gz":
        target = directory / archive.name[:-3]
        with gzip.open(archive, "rb") as source, target.open("wb") as dest:
            shutil.copyfileobj(source, dest)
        return target
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zipped:
            zipped.extractall(directory)
        for path in directory.rglob("*"):
            if path.is_file() and "mihomo" in path.name.lower():
                return path
    raise RuntimeError("不支持的压缩格式")


def write_benchmark_config(path: Path, proxies: list[dict[str, Any]], controller_port: int) -> None:
    config = {
        "mixed-port": find_free_port(),
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": f"127.0.0.1:{controller_port}",
        "proxies": proxies,
        "proxy-groups": [{"name": "BENCHMARK", "type": "select", "proxies": [str(p["name"]) for p in proxies] or ["DIRECT"]}],
    }
    path.write_text(yaml.safe_dump(config, allow_unicode=True), encoding="utf-8")


def benchmark_proxies(proxies: list[dict[str, Any]]) -> list[ProxyMetric]:
    if not proxies: return []
    print(f"\n[INFO] 准备测试 {len(proxies)} 个节点的延迟...")
    engine = find_or_install_mihomo()
    
    with tempfile.TemporaryDirectory(prefix="proxy-airport-") as temp_name:
        temp_dir = Path(temp_name)
        config_path = temp_dir / "benchmark.yaml"
        controller_port = find_free_port()
        controller_url = f"http://127.0.0.1:{controller_port}"
        write_benchmark_config(config_path, proxies, controller_port)

        process = subprocess.Popen([str(engine), "-d", str(temp_dir), "-f", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(30):
                if process.poll() is not None: raise RuntimeError("Mihomo 异常退出")
                try:
                    if requests.get(f"{controller_url}/version", timeout=1).status_code == 200: break
                except: pass
                time.sleep(0.5)
            metrics = run_delay_tests(controller_url, proxies)
        finally:
            process.terminate()
            try: process.wait(timeout=3)
            except: process.kill()
        return metrics


def run_delay_tests(controller_url: str, proxies: list[dict[str, Any]]) -> list[ProxyMetric]:
    workers = max(1, min(MAX_WORKERS, len(proxies)))
    metrics: list[ProxyMetric] = []
    
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(test_single_proxy, session, controller_url, proxy): proxy for proxy in proxies}
            for completed, future in enumerate(as_completed(futures), start=1):
                try:
                    if metric := future.result():
                        metrics.append(metric)
                except Exception as exc:
                    pass
                if completed % 50 == 0 or completed == len(futures):
                    print(f"[INFO] 测速进度: {completed}/{len(futures)} | 存活节点: {len(metrics)}")
                    
    metrics.sort(key=lambda item: item.health_score, reverse=True)
    return metrics


def test_single_proxy(session: requests.Session, controller_url: str, proxy: dict[str, Any]) -> ProxyMetric | None:
    name = str(proxy["name"])
    url = f"{controller_url}/proxies/{quote(name, safe='')}/delay?timeout={LATENCY_TIMEOUT_MS}&url={quote(TEST_URL, safe='')}"
    try:
        response = session.get(url, timeout=(LATENCY_TIMEOUT_MS / 1000) + 3)
        if response.status_code == 200:
            latency = int(response.json().get("delay", 0))
            if 0 < latency <= LATENCY_TIMEOUT_MS:
                region = detect_region(name)
                score = (1 / latency) * 0.6 + (3 if region in {"HK", "SG", "JP"} else 2 if region == "US" else 1) * 0.3
                return ProxyMetric(proxy=proxy, latency=latency, region=region, health_score=score)
    except:
        pass
    return None


def detect_region(name: str) -> str:
    text = name.lower()
    if any(t in text for t in ["hk", "hong kong", "香港"]): return "HK"
    if any(t in text for t in ["jp", "japan", "日本"]): return "JP"
    if any(t in text for t in ["us", "united states", "美国"]): return "US"
    if any(t in text for t in ["sg", "singapore", "新加坡"]): return "SG"
    return "OTHER"


def main() -> None:
    total_raw, candidates = collect_proxies()
    metrics = benchmark_proxies(candidates)
    
    if not metrics:
        print("\n[WARN] 所有节点测速失败，可能是网络问题或没有任何可用节点。")
        return

    hk_names = [m.proxy["name"] for m in metrics if m.region == "HK"] or ["DIRECT"]
    jp_names = [m.proxy["name"] for m in metrics if m.region == "JP"] or ["DIRECT"]
    us_names = [m.proxy["name"] for m in metrics if m.region == "US"] or ["DIRECT"]
    auto_names = [m.proxy["name"] for m in metrics[:min(30, len(metrics))]]

    config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": [m.proxy for m in metrics],
        "proxy-groups": [
            {"name": "AUTO-FAST", "type": "url-test", "proxies": auto_names, "url": TEST_URL, "interval": 300},
            {"name": "HK-POOL", "type": "select", "proxies": hk_names},
            {"name": "JP-POOL", "type": "select", "proxies": jp_names},
            {"name": "US-POOL", "type": "select", "proxies": us_names},
            {"name": "PROXY", "type": "select", "proxies": ["AUTO-FAST", "HK-POOL", "JP-POOL", "US-POOL", "DIRECT"]},
        ],
        "rules": ["MATCH,PROXY"]
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
    
    print("\n" + "="*40)
    print(f"🎉 处理完成！")
    print(f"总计找到有效节点候选: {len(candidates)}")
    print(f"成功通过测速的节点数: {len(metrics)}")
    print(f"配置文件已生成至: {OUTPUT_PATH.absolute()}")
    print("="*40)


if __name__ == "__main__":
    main()
