import time
import subprocess
import sys
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from shutil import which
import argparse
import csv
import threading

# Optional dependencies (tray + encryption)
try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except Exception:
    HAS_TRAY = False

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

# ---------- Paths / Defaults ----------
NETWORK_INTERFACE = None
TEST_DOMAIN = "www.microsoft.com"
CHECK_INTERVAL_SEC = 300
POWERSHELL = "powershell.exe"

SCRIPT_DIR = Path(__file__).resolve().parent
LOG_DIR = SCRIPT_DIR / "logs"
LOG_FILE = LOG_DIR / "ipvtri_dns.log"
LOG_MAX_BYTES = 1_000_000
LOG_BACKUPS = 5
TRUSTED_DNS_FILE = SCRIPT_DIR / "trusted_dns_list.txt"
CSV_DEFAULT = SCRIPT_DIR / "logs" / "ipvtri_dns.csv"
KEY_FILE = SCRIPT_DIR / ".ipvtri_key"

# ---------- Logger ----------
logger = logging.getLogger("IPvTriDNS")

def init_logging(level: str):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    f_handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8")
    f_fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    f_handler.setFormatter(f_fmt)

    c_handler = logging.StreamHandler(sys.stdout)
    c_fmt = logging.Formatter("%(message)s")
    c_handler.setFormatter(c_fmt)

    logger.handlers.clear()
    logger.addHandler(f_handler)
    logger.addHandler(c_handler)

# ---------- CSV Mirroring ----------
class CsvMirror:
    def __init__(self, path: Path | None):
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._ensure_header()

    def _ensure_header(self):
        if not self.path.exists() or self.path.stat().st_size == 0:
            with open(self.path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(
                    ["timestamp","event","interface","selected_dns","selected_name","latency_ms","current_dns","trusted"]
                )

    def write(self, event, iface, selected_ip, selected_name, latency_ms, current_dns, trusted):
        if not self.path:
            return
        with open(self.path, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                time.strftime("%Y-%m-%d %H:%M:%S"),
                event, iface, selected_ip, selected_name, latency_ms, current_dns, "yes" if trusted else "no"
            ])

# ---------- Optional Log Encryption ----------
class EncryptingHandler(logging.Handler):
    def __init__(self, key_path: Path):
        super().__init__()
        self.key_path = key_path
        self.enc_path = LOG_DIR / "ipvtri_dns.enc"
        self.fernet = None
        if HAS_CRYPTO:
            if key_path.exists():
                key = key_path.read_bytes()
            else:
                key = Fernet.generate_key()
                key_path.write_bytes(key)
            self.fernet = Fernet(key)

    def emit(self, record):
        if not HAS_CRYPTO or not self.fernet:
            return
        msg = self.format(record) + "\n"
        try:
            token = self.fernet.encrypt(msg.encode("utf-8"))
            with open(self.enc_path, "ab") as f:
                f.write(token + b"\n")
        except Exception:
            pass

# ---------- IPvTri+ DNS Pool (NO GOOGLE by default) ----------
dns_servers = [
    # Example IPvTri format entries (IP via RGB_IP)
    {"RGB_IP": [168,111,1,1],   "hex_color": "#A86F01FF", "Server": "ColorDNS – Admin Core"},
    {"RGB_IP": [1,1,1,1],       "hex_color": "#01FF01FF", "Server": "ColorDNS – GreenNode"},  # Cloudflare-like demo
    {"RGB_IP": [94,140,14,14],  "hex_color": "#5E8C0EFF", "Server": "AdGuard"},
    {"RGB_IP": [193,222,87,100],"hex_color": "#C1DE5764", "Server": "Anonymous-DNS"},
    {"RGB_IP": [9,9,9,9],       "hex_color": "#090909FF", "Server": "Quad9"},
]

# ---------- DoH templates (NO GOOGLE) ----------
DOH_TEMPLATES = {
    "1.1.1.1": "https://cloudflare-dns.com/dns-query",
    "1.0.0.1": "https://cloudflare-dns.com/dns-query",
    "9.9.9.9": "https://dns.quad9.net/dns-query",
    "94.140.14.14": "https://dns.adguard-dns.com/dns-query",
    "94.140.15.15": "https://dns.adguard-dns.com/dns-query",
}

# ---------- Blocklist (startup guard) ----------
DISALLOWED_IPS = {
    "8.8.8.8",  # Google DNS
    "8.8.4.4",  # Google DNS secondary
}

def sanitize_dns_pool(dns_pool):
    cleaned, removed = [], []
    for d in dns_pool:
        ip = ".".join(map(str, d.get("RGB_IP", []))) if "RGB_IP" in d else d.get("IP", "")
        if ip in DISALLOWED_IPS:
            removed.append((ip, d.get("Server","Unknown")))
        else:
            cleaned.append(d)
    if removed:
        for ip, name in removed:
            logger.warning(f"[Blocklist] Removed disallowed resolver from pool: {ip} ({name})")
    return cleaned

def sanitize_doh_templates(templates: dict):
    bad = [ip for ip in list(templates.keys()) if ip in DISALLOWED_IPS]
    for ip in bad:
        templates.pop(ip, None)
        logger.warning(f"[Blocklist] Removed disallowed DoH template: {ip}")
    return templates

def sanitize_trusted_file(path: Path):
    if not path.exists():
        return []
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    kept, removed = [], []
    for ln in lines:
        if ln in DISALLOWED_IPS:
            removed.append(ln)
        else:
            kept.append(ln)
    if removed:
        path.write_text("\n".join(kept)+("\n" if kept else ""), encoding="utf-8")
        logger.warning(f"[Blocklist] Removed from trusted list: {', '.join(sorted(set(removed)))}")
    return kept

# ---------- Utilities ----------
def get_ip_from_rgb(entry):
    return ".".join(map(str, entry["RGB_IP"]))

def print_color_tag(hex_color):
    try:
        r = int(hex_color[1:3],16); g = int(hex_color[3:5],16); b = int(hex_color[5:7],16)
        print(f"\033[48;2;{r};{g};{b}m     \033[0m {hex_color}")
    except:
        print(hex_color)

def run(cmd, timeout=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

def have(cmd_name): return which(cmd_name) is not None
def ps(script, timeout=8):
    return run(["powershell.exe","-NoProfile","-ExecutionPolicy","Bypass","-Command",script], timeout=timeout)

def autodetect_interface(only_physical=False):
    rc, out, err = ps("(Get-NetAdapter | Where-Object Status -eq 'Up' | Sort-Object ifIndex | Select-Object Name) | ConvertTo-Json")
    if rc != 0 or not out: return None
    import json
    try:
        items = json.loads(out)
        if isinstance(items, dict): items = [items]
        vpn_keys = ["nord","openvpn","wireguard","express","surfshark","tunnel","lynx","proton"]
        for it in items:
            name = it.get("Name","")
            if only_physical and any(k in name.lower() for k in vpn_keys): continue
            return name
    except Exception:
        pass
    return None

def test_dns_with_powershell(ip):
    script = (
        f"$sw=[System.Diagnostics.Stopwatch]::StartNew();"
        f"try{{ Resolve-DnsName -Name '{TEST_DOMAIN}' -Type A -Server '{ip}' -DnsOnly -ErrorAction Stop | Out-Null; "
        f"$sw.Stop(); [int]$sw.ElapsedMilliseconds }} catch {{ 1/0 }}"
    )
    rc, out, err = ps(script, timeout=7)
    if rc == 0 and out.isdigit():
        return int(out)
    return float('inf')

def test_icmp(ip):
    rc, out, err = run(["ping", ip, "-n", "1"], timeout=4)
    if rc == 0 and "Average =" in out:
        try:
            ms = int(out.split("Average =")[-1].replace("ms","").strip())
            return ms
        except:
            pass
    return float('inf')

def flush_dns():
    rc, out, err = run(["ipconfig","/flushdns"])
    print("[+] Flushed DNS cache." if rc == 0 else f"[!] Flush failed: {err or out}")
    if rc == 0: logger.info("Flushed DNS cache.")
    else: logger.warning(f"Flush failed: {err or out}")

def reset_dns_to_dhcp(iface):
    iface_unq = iface.strip('"')
    run(["netsh","interface","ipv4","set","dnsservers", f"name={iface_unq}", "source=static", "addr=none"])
    rc, out, err = run(["netsh","interface","ipv4","set","dnsservers", f"name={iface_unq}", "source=dhcp"])
    if rc != 0:
        rc, out, err = run(["netsh","interface","ipv4","set","dnsservers", f"name={iface_unq}", "dhcp"])
    if rc == 0:
        print(f"[+] DNS reset to DHCP on '{iface_unq}'."); logger.info(f"DNS reset to DHCP on '{iface_unq}'.")
    else:
        print(f"[!] DHCP reset failed: {err or out}"); logger.warning(f"DHCP reset failed: {err or out}")

def set_dns(iface, ip):
    iface_unq = iface.strip('"')
    run(["netsh","interface","ipv4","set","dnsservers", f"name={iface_unq}", "source=static", "addr=none"])
    rc, out, err = run(["netsh","interface","ipv4","set","dnsservers", f"name={iface_unq}", "static", ip, "primary"])
    if rc == 0:
        print(f"[+] DNS set to {ip} on '{iface_unq}'."); logger.info(f"DNS set to {ip} on '{iface_unq}'.")
        return True
    print(f"[!] Failed to set DNS: {err or out}"); logger.error(f"Failed to set DNS: {err or out}")
    return False

def current_dns(iface):
    rc, out, err = run(["netsh","interface","ipv4","show","dnsservers"])
    if rc != 0: return None
    lines = out.splitlines(); capture = False
    for line in lines:
        if iface.strip('"') in line: capture = True; continue
        if capture:
            s = line.strip()
            if s and s[0].isdigit():
                return s.split()[0]
            if "Register" in s: break
    return None

def enforce_doh(ip):
    tmpl = DOH_TEMPLATES.get(ip)
    if not tmpl:
        logger.info(f"No DoH template for {ip}."); return
    script = (
        f"try {{ Add-DnsClientDohServerAddress -ServerAddress '{ip}' -DohTemplate '{tmpl}' "
        f"-AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction Stop; 'OK' }} catch {{ 'ERR' }}"
    )
    rc, out, err = ps(script, timeout=6)
    if rc == 0 and "OK" in out:
        print(f"[+] DoH registered for {ip}"); logger.info(f"DoH registered for {ip} ({tmpl})")
    else:
        logger.warning(f"DoH registration failed for {ip} (Win10/11 required).")

# ---------- Tray Icon ----------
class TrayController:
    def __init__(self): self.icon = None
    def _create_image(self, rgb):
        img = Image.new('RGB', (64,64), rgb)
        d = ImageDraw.Draw(img); d.ellipse((10,10,54,54), fill=rgb); return img
    def run(self):
        if not HAS_TRAY: logger.warning("pystray/Pillow not available; tray disabled."); return
        self.icon = pystray.Icon("IPvTriDNS", self._create_image((128,128,128)), "IPvTri+ DNS")
        threading.Thread(target=self.icon.run, daemon=True).start()
    def update(self, status: str, tooltip: str):
        if not HAS_TRAY or not self.icon: return
        color = {"green":(0,180,0),"yellow":(220,200,0),"red":(200,0,0)}.get(status,(128,128,128))
        self.icon.icon = self._create_image(color); self.icon.title = f"IPvTri+ DNS — {tooltip}"

# ---------- Main ----------
def load_trusted_dns(file_path=TRUSTED_DNS_FILE):
    try:
        path = Path(file_path)
        with open(path, "r", encoding="utf-8") as f:
            lst = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            logger.info(f"Loaded trusted DNS list ({len(lst)} entries) from {path}")
            return lst
    except Exception as e:
        logger.warning(f"Could not load trusted DNS list: {e}")
        return []

def print_dns_status_summary(current, trusted_list):
    if not current:
        print("[!] No DNS server detected."); logger.warning("No DNS server detected."); return False
    trusted = current in trusted_list
    status = "[✓]" if trusted else "[!]"
    color = "\033[92m" if trusted else "\033[91m"
    msg = f"{status} Current DNS: {current} {'(trusted)' if trusted else '(UNTRUSTED)'}"
    logger.info(msg); print(f"{color}{msg}\033[0m")
    return trusted

def main():
    ap = argparse.ArgumentParser(description="IPvTri+ Auto DNS Super Changer (Pro)")
    ap.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"])
    ap.add_argument("--csv", default=None, help="Mirror events to CSV (default: logs/ipvtri_dns.csv).")
    ap.add_argument("--tray", action="store_true", help="System tray icon (pystray+Pillow).")
    ap.add_argument("--encrypt-logs", action="store_true", help="Mirror logs to encrypted .enc (cryptography).")
    ap.add_argument("--strict-only-trusted", action="store_true", help="Only switch to DNS listed as trusted.")
    ap.add_argument("--only-physical", action="store_true", help="Ignore VPN/tunnel adapters when auto-detecting.")
    ap.add_argument("--enforce-doh", action="store_true", help="Register DoH for chosen DNS (Win10/11).")
    args = ap.parse_args()

    init_logging(args.log_level)
    logger.info("=== IPvTri+ Auto DNS Switcher (v1.4) starting ===")

    # Startup guard
    global dns_servers, DOH_TEMPLATES
    dns_servers = sanitize_dns_pool(dns_servers)
    DOH_TEMPLATES = sanitize_doh_templates(DOH_TEMPLATES)
    _cleaned_trusted = sanitize_trusted_file(TRUSTED_DNS_FILE)

    if args.encrypt_logs and HAS_CRYPTO:
        enc = EncryptingHandler(KEY_FILE)
        enc.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(enc); logger.info("Encrypted log mirroring enabled (logs/ipvtri_dns.enc).")
    elif args.encrypt_logs and not HAS_CRYPTO:
        logger.warning("cryptography not installed; --encrypt-logs disabled.")

    csv_path = Path(args.csv) if args.csv else CSV_DEFAULT
    csv_mirror = CsvMirror(csv_path)
    if args.csv is not None:
        logger.info(f"CSV mirroring enabled: {csv_path}")

    if not have(POWERSHELL):
        print("[!] powershell.exe not found."); logger.error("PowerShell missing."); sys.exit(1)

    iface = f'"{NETWORK_INTERFACE}"' if NETWORK_INTERFACE else None
    if iface is None:
        detected = autodetect_interface(only_physical=args.only_physical)
        if detected:
            iface = f'"{detected}"'; print(f"[*] Auto-detected interface: {detected}"); logger.info(f"Auto-detected: {detected}")
        else:
            print("[!] Could not auto-detect an active network interface."); logger.error("No active interface."); sys.exit(1)

    tray = TrayController()
    if args.tray and HAS_TRAY: tray.run()
    elif args.tray: print("[!] Tray requested but pystray/Pillow not installed.")

    print("[*] IPvTri+ Auto DNS Switcher is running. Press Ctrl+C to stop."); logger.info("Main loop started.")
    trusted_dns_list = _cleaned_trusted if _cleaned_trusted else load_trusted_dns(TRUSTED_DNS_FILE)

    while True:
        try:
            print("\n[=== Testing DNS Servers ===]"); logger.info("Testing DNS servers...")
            fastest = None; fastest_time = float('inf'); per_server_times = []

            # Try PowerShell DNS timing first
            for d in dns_servers:
                ip = get_ip_from_rgb(d); print_color_tag(d["hex_color"])
                print(f" - Testing {d['Server']} ({ip}) ...", end="", flush=True)
                t = test_dns_with_powershell(ip)
                if t == float('inf'):
                    print(" FAIL"); logger.info(f"{d['Server']} ({ip}) DNS test: FAIL")
                else:
                    print(f" {t} ms"); logger.info(f"{d['Server']} ({ip}) DNS test: {t} ms")
                    if t < fastest_time: fastest_time, fastest = t, d

            # Fallback to ICMP
            if fastest is None:
                print("[!] DNS lookups failing. Trying ICMP fallback..."); logger.warning("DNS lookups failing; trying ICMP fallback.")
                for d in dns_servers:
                    ip = get_ip_from_rgb(d)
                    print(f"   · PING {d['Server']} ({ip}) ...", end="", flush=True)
                    t = test_icmp(ip)
                    if t == float('inf'):
                        print(" FAIL"); logger.info(f"{d['Server']} ({ip}) ICMP: FAIL")
                    else:
                        print(f" {t} ms"); logger.info(f"{d['Server']} ({ip}) ICMP: {t} ms")
                        if t < fastest_time: fastest_time, fastest = t, d

            if not fastest:
                print("[!] No responsive DNS servers found. Sleeping..."); logger.warning("No responsive DNS servers."); 
                if args.tray and HAS_TRAY: tray.update("red","No responsive DNS")
                time.sleep(CHECK_INTERVAL_SEC); continue

            ip = get_ip_from_rgb(fastest)
            print(f"\n[>>] Fastest: {ip} – {fastest['Server']} ({fastest_time} ms)"); logger.info(f"Selected: {ip} ({fastest_time} ms)")
            cur = current_dns(iface)
            is_trusted_current = print_dns_status_summary(cur, trusted_dns_list)
            if args.tray and HAS_TRAY: tray.update("green" if is_trusted_current else "yellow", f"Current: {cur or 'n/a'}")

            if cur == ip:
                print("[=] Already using the fastest server."); logger.info("Already on fastest; flushing DNS.")
                flush_dns()
            else:
                reset_dns_to_dhcp(iface)
                if set_dns(iface, ip):
                    if args.enforce_doh: enforce_doh(ip)
                    flush_dns()

            csv_mirror.write("switch", iface, ip, fastest["Server"], int(fastest_time if fastest_time!=float('inf') else -1), cur or "", is_trusted_current)
            print(f"[*] Sleeping {CHECK_INTERVAL_SEC//60} minutes...\n"); logger.info(f"Sleeping {CHECK_INTERVAL_SEC} sec.")
            time.sleep(CHECK_INTERVAL_SEC)

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user. Exiting."); logger.info("Interrupted by user."); break
        except Exception as e:
            print(f"[!] Unexpected error: {e}"); logger.exception(f"Unexpected error: {e}")
            if args.tray and HAS_TRAY: tray.update("red","Error")
            time.sleep(5)

if __name__ == "__main__":
    main()
