import hmac, os, socket, struct
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

app=FastAPI(title="ATLAS ClamAV Scanner",version="1.0.0")
HOST=os.getenv("CLAMD_HOST","127.0.0.1"); PORT=int(os.getenv("CLAMD_PORT","3310"))
MAX_MB=int(os.getenv("MAX_FILE_SIZE_MB","25")); MAX_BYTES=MAX_MB*1024*1024
SECRET=os.getenv("ATLAS_SCAN_SECRET",""); TIMEOUT=float(os.getenv("CLAMD_TIMEOUT_SECONDS","60"))

def command(cmd):
    with socket.create_connection((HOST,PORT),timeout=TIMEOUT) as s:
        s.sendall(cmd); return s.recv(4096)

def version():
    raw=command(b"zVERSION\0").decode("utf-8","replace").strip("\0\r\n ")
    parts=raw.split("/")
    eng=parts[0].replace("ClamAV ","").strip()
    sig="/".join(parts[1:]).strip() if len(parts)>1 else "unknown"
    return eng,sig,raw

def ping():
    return command(b"zPING\0").decode("utf-8","replace").strip("\0\r\n ")=="PONG"

def scan_bytes(data):
    with socket.create_connection((HOST,PORT),timeout=TIMEOUT) as s:
        s.sendall(b"zINSTREAM\0")
        for i in range(0,len(data),65536):
            chunk=data[i:i+65536]; s.sendall(struct.pack("!I",len(chunk))); s.sendall(chunk)
        s.sendall(struct.pack("!I",0)); out=bytearray()
        while True:
            part=s.recv(4096)
            if not part: break
            out.extend(part)
            if b"\0" in part: break
        return out.decode("utf-8","replace").strip("\0\r\n ")

def authorize(auth):
    if not SECRET: raise HTTPException(503,"scanner_secret_not_configured")
    if not auth or not auth.startswith("Bearer "): raise HTTPException(401,"unauthorized")
    if not hmac.compare_digest(auth[7:],SECRET): raise HTTPException(401,"unauthorized")

@app.get("/health")
def health():
    try:
        ok=ping(); eng,sig,raw=version()
        return {"ok":bool(ok and eng and sig),"status":"READY" if ok else "ERROR","clamd_reachable":ok,"engine_name":"ClamAV","engine_version":eng,"signature_version":sig,"version_raw":raw,"max_file_size_mb":MAX_MB}
    except Exception as e:
        return JSONResponse(status_code=503,content={"ok":False,"status":"ERROR","clamd_reachable":False,"engine_name":"ClamAV","error_code":"CLAMD_UNAVAILABLE","detail":str(e)[:200]})

@app.post("/scan")
async def scan(request:Request,authorization:str|None=Header(default=None)):
    authorize(authorization)
    data=await request.body()
    if len(data)>MAX_BYTES: raise HTTPException(413,"file_too_large")
    if not data: raise HTTPException(400,"empty_body")
    try:
        eng,sig,_=version(); result=scan_bytes(data)
    except Exception as e:
        return JSONResponse(status_code=503,content={"ok":False,"status":"ERROR","engine_name":"ClamAV","error_code":"SCAN_ENGINE_ERROR","evidence":{"scan_completed":False,"bytes_scanned":0,"detail":str(e)[:200]}})
    evidence={"bytes_scanned":len(data),"scan_completed":True,"clamd_result":result}
    if result.endswith(" OK"):
        return {"ok":True,"status":"CLEAN","engine_name":"ClamAV","engine_version":eng,"signature_version":sig,"verdict_code":"CLEAN","findings":{},"evidence":evidence}
    if result.endswith(" FOUND"):
        threat=result.split(": ",1)[-1]
        if threat.endswith(" FOUND"): threat=threat[:-6]
        threat=threat.strip() or "MALWARE_FOUND"
        return {"ok":True,"status":"INFECTED","engine_name":"ClamAV","engine_version":eng,"signature_version":sig,"verdict_code":threat,"findings":{"threat":threat},"evidence":evidence}
    return JSONResponse(status_code=503,content={"ok":False,"status":"ERROR","engine_name":"ClamAV","error_code":"UNEXPECTED_CLAMD_RESPONSE","evidence":{"scan_completed":False,"bytes_scanned":0,"clamd_result":result[:200]}})
