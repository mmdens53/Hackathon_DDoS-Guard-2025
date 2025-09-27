from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
import subprocess
import socket
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI()


def ping_device(ip: str):
    """Проверка доступности устройства через ping"""
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True, timeout=5)
        return {"success": result.returncode == 0}
    except (subprocess.TimeoutExpired, Exception) as e:
        logger.error(f"Ping error for {ip}: {e}")
        return {"success": False}


def port_scan(ip: str):
    """Простое сканирование портов (без nmap)"""
    common_ports = [21, 22, 23, 80, 443, 3389, 5900, 53]
    open_ports = []

    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception as e:
            logger.error(f"Port scan error for {ip}:{port}: {e}")

    return open_ports


def detect_os_and_protocols(ip: str, open_ports: list):
    """Определение ОС и протоколов по открытым портам"""

    os_info = "Unknown"

    port_protocol_map = {
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        3389: "RDP",
        5900: "VNC",
        53: "DNS",
    }

    protocols = []
    for port in open_ports:
        if port in port_protocol_map:
            protocols.append(port_protocol_map[port])

    if 3389 in open_ports:
        os_info = "Windows"
    elif 22 in open_ports and 3389 not in open_ports:
        os_info = "Linux/Unix"
    elif 80 in open_ports or 443 in open_ports:
        os_info = "Web Server/Network Device"
    elif 23 in open_ports:
        os_info = "Network Device (Router/Switch)"

    return os_info, protocols


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan")
async def scan_device(ip: str = Form(...)):
    logger.info(f"Scanning device: {ip}")

    ping_result = ping_device(ip)
    if not ping_result["success"]:
        return {"error": f"Устройство {ip} недоступно"}

    open_ports = port_scan(ip)
    logger.info(f"Open ports for {ip}: {open_ports}")

    if not open_ports:
        return {"error": f"Устройство {ip} доступно, но не найдено открытых портов"}

    os_info, protocols = detect_os_and_protocols(ip, open_ports)

    return {"ip": ip, "os": os_info, "protocols": protocols, "open_ports": open_ports, "status": "online"}


@app.post("/connect")
async def connect_device(
    ip: str = Form(...), protocol: str = Form(...), username: str = Form(...), password: str = Form(...)
):
    """Простая заглушка для подключения"""
    return {
        "success": True,
        "message": f"Подключение к {ip} по {protocol} установлено",
        "details": "Режим подключения будет реализован позже",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
