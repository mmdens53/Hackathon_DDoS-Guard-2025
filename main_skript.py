from fastapi import FastAPI, Request, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import subprocess
import socket
import logging
import paramiko
import asyncio
import os
from typing import List, Dict

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI()

# Монтируем статические файлы
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


def ping_device(ip: str):
    """Проверка доступности устройства через ping"""
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True, timeout=5)
        return {"success": result.returncode == 0}
    except (subprocess.TimeoutExpired, Exception) as e:
        logger.error(f"Ping error for {ip}: {e}")
        return {"success": False}


def port_scan(ip: str):
    """Простое сканирование портов"""
    common_ports = [21, 22, 23, 80, 443, 3389, 5900, 53, 5901, 5902]
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
    os_info = "Неизвестно"

    port_protocol_map = {
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        3389: "RDP",
        5900: "VNC",
        5901: "VNC",
        5902: "VNC",
        53: "DNS",
    }

    protocols = []
    for port in open_ports:
        if port in port_protocol_map:
            protocol_name = port_protocol_map[port]
            if protocol_name not in protocols:  # избегаем дубликатов
                protocols.append(protocol_name)

    # Определение ОС
    if 3389 in open_ports:
        os_info = "Windows"
    elif 22 in open_ports and 3389 not in open_ports:
        os_info = "Linux/Unix"
    elif 21 in open_ports and (80 in open_ports or 443 in open_ports):
        os_info = "Сервер (FTP + Web)"
    elif 80 in open_ports or 443 in open_ports:
        os_info = "Веб-сервер"
    elif 23 in open_ports:
        os_info = "Сетевое устройство (Роутер/Коммутатор)"
    elif 5900 in open_ports or 5901 in open_ports or 5902 in open_ports:
        os_info = "Устройство с графическим интерфейсом"

    return os_info, protocols


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/scan")
async def scan_device(ip: str = Form(...)):
    logger.info(f"Сканируем устройство: {ip}")

    ping_result = ping_device(ip)
    if not ping_result["success"]:
        return {"error": f"Устройство {ip} недоступно"}

    open_ports = port_scan(ip)
    logger.info(f"Открытые порты для {ip}: {open_ports}")

    if not open_ports:
        return {"error": f"Устройство {ip} доступно, но не найдено открытых портов"}

    os_info, protocols = detect_os_and_protocols(ip, open_ports)

    return {"ip": ip, "os": os_info, "protocols": protocols, "open_ports": open_ports, "status": "online"}


# SSH
@app.websocket("/ws/ssh/{ip}")
async def websocket_ssh(websocket: WebSocket, ip: str):
    await websocket.accept()
    ssh_client = None

    try:
        # Параметры подключения
        data = await websocket.receive_json()
        username = data.get("username")
        password = data.get("password")
        port = data.get("port", 22)

        # Подключаемся по SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(ip, port=port, username=username, password=password, timeout=10)

        ssh_shell = ssh_client.invoke_shell()
        ssh_shell.settimeout(0.1)

        ssh_shell.send(b"export TERM=xterm-256color\n")

        await websocket.send_text("\r\n\x1b[1;32mSSH подключение установлено!\x1b[0m\r\n")

        while True:

            try:
                web_data = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                if web_data:
                    ssh_shell.send(web_data.encode("utf-8"))
            except asyncio.TimeoutError:
                pass

            try:
                if ssh_shell.recv_ready():
                    ssh_data = ssh_shell.recv(1024).decode("utf-8", errors="ignore")
                    if ssh_data:
                        await websocket.send_text(ssh_data)
            except socket.timeout:
                pass

            await asyncio.sleep(0.01)

    except paramiko.AuthenticationException:
        error_msg = "\r\n\x1b[1;31m❌ Ошибка аутентификации: неверное имя пользователя или пароль\x1b[0m\r\n"
        await websocket.send_text(error_msg)
    except paramiko.SSHException as e:
        error_msg = f"\r\n\x1b[1;31m❌ Ошибка SSH: {str(e)}\x1b[0m\r\n"
        await websocket.send_text(error_msg)
    except Exception as e:
        error_msg = f"\r\n\x1b[1;31m❌ Ошибка подключения: {str(e)}\x1b[0m\r\n"
        await websocket.send_text(error_msg)
    finally:
        if ssh_client:
            ssh_client.close()
        await websocket.close()


# Генерация RDP файла
@app.post("/generate-rdp")
async def generate_rdp_file(ip: str = Form(...), username: str = Form(...)):
    rdp_content = f"""
screen mode id:i:2
use multimon:i:0
desktopwidth:i:1024
desktopheight:i:768
session bpp:i:32
winposstr:s:0,1,0,0,800,600
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:7
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
enableworkspacereconnect:i:0
disable wallpaper:i:0
allow font smoothing:i:0
allow desktop composition:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
full address:s:{ip}
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
redirectposdevices:i:0
autoreconnection enabled:i:1
authentication level:i:2
prompt for credentials:i:0
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:
gatewayusagemethod:i:4
gatewaycredentialssource:i:4
gatewayprofileusagemethod:i:0
promptcredentialonce:i:0
use redirection server name:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
username:s:{username}
"""

    filename = f"connection_{ip}.rdp"
    filepath = BASE_DIR / "static" / filename

    with open(filepath, "w") as f:
        f.write(rdp_content)

    return FileResponse(filepath, filename=filename)


# VNC через noVNC
@app.get("/vnc/{ip}")
async def vnc_proxy(request: Request, ip: str):
    return templates.TemplateResponse("vnc.html", {"request": request, "ip": ip})


@app.post("/connect")
async def connect_device(
    ip: str = Form(...),
    protocol: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    port: str = Form(...),
):
    """Общий endpoint для подключения"""
    return {
        "success": True,
        "message": f"Подключение к {ip} по {protocol} инициировано",
        "protocol": protocol,
        "ip": ip,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
