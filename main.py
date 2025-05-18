from enum import Enum
import re
import subprocess
import xml.etree.ElementTree as ET

from fastapi import FastAPI, Query, HTTPException
from pydantic import BaseModel

class ScanType(str, Enum):
    all = "all"
    top10 = "top10"
    top100 = "top100"
    custom = "custom"

class PortInfo(BaseModel):
    port: int
    state: str
    service: str | None = None
    version: str | None = None

class ScanResult(BaseModel):
    target: str
    ports: list[PortInfo]

app = FastAPI(
    title="Scanner Service",
    version="1.1.0",
    description="Port scanner with multiple modes and input sanitization."
)

def validate_target(target: str) -> str:
    # very basic check: letters, digits, dots, hyphens
    if not re.fullmatch(r"[A-Za-z0-9\.\-]+", target):
        raise HTTPException(status_code=400, detail="Invalid target format")
    return target

def sanitize_ports(ports: str) -> str:
    # only digits and commas
    if not re.fullmatch(r"[0-9,]+", ports):
        raise HTTPException(status_code=400, detail="Invalid ports format; must be comma-separated digits")
    return ports

@app.get("/scan", response_model=ScanResult)
def scan(
    target: str = Query(..., description="Target host to scan"),
    version: bool = Query(False, description="Enable service/version detection"),
    scan_type: ScanType = Query(ScanType.all, description="Scan mode: all, top10, top100, custom"),
    ports: str | None = Query(None, description="Comma-separated ports (required if scan_type=custom)")
):
    target = validate_target(target)

    # choose port argument
    if scan_type == ScanType.all:
        port_args = ["-p-"]
    elif scan_type == ScanType.top10:
        port_args = ["--top-ports", "10"]
    elif scan_type == ScanType.top100:
        port_args = ["--top-ports", "100"]
    else:  # custom
        if not ports:
            raise HTTPException(
                status_code=400,
                detail="`ports` parameter is required when scan_type is custom"
            )
        ports = sanitize_ports(ports)
        port_args = [f"-p{ports}"]

    # build the nmap command
    # cmd = ["nmap", "-Pn", *port_args]
    cmd = ["nmap", "-Pn", "-sT", *port_args] # added TCP connection
    if version:
        cmd.append("-sV")
    cmd += ["-oX", "-", target]

    # run nmap and parse the XML output
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse nmap XML: {e}")

    ports_found: list[PortInfo] = []
    for host in root.findall("host"):
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
        for port in ports_elem.findall("port"):
            pid = int(port.get("portid"))
            state = port.find("state").get("state")
            svc = port.find("service")
            svc_name = svc.get("name") if svc is not None else None
            svc_ver  = svc.get("version") if version and svc is not None else None
            ports_found.append(PortInfo(
                port=pid, state=state, service=svc_name, version=svc_ver
            ))

    return ScanResult(target=target, ports=ports_found)
