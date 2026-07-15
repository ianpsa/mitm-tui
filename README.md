## MITM TUI

&emsp; Tudo começou com um `tcpdump` e uma curiosidade inocente: "o que meus vizinhos tão acessando na rede?". Spoiler: não é nada muito empolgante, mas o caminho até descobrir isso foi bizarramente divertido. Comecei com um script de ARP spoof genérico, fui adicionando coisa, enfeitando, metendo whiptail pra deixar bonitinho, e quando vi tinha 1362 linhas de Bash que fazem de tudo, inclusive café (quase). A brincadeira começou despretensiosa, mas cada feature nova puxava outra: "po, se eu já tô envenenando o ARP, por que não fazer DNS spoof também?" e "já que tô com o tráfego passando por mim, por que não roubar umas creds?". E assim nasceu o **MITM TUI v2**.

<br>

&emsp; A base do framework é um loop TUI com `whiptail` que expõe um menu cheio de firula. Toda a detecção de rede é automática: interface, IP, gateway, CIDR; então é só rodar `sudo bash mitm_tui.sh` e escolher a maldade. O coração do bicho é um ARP spoof bidirecional com iptables NAT/MASQUERADE que redireciona o tráfego da vítima pra passar pela máquina atacante. Em cima disso, empilhei `dnsspoof`, `mitmdump` com addon de SSL stripping, um responder caseiro em Python (NBT-NS + LLMNR + mDNS + WPAD + SMB fake), e uma coleção de páginas de login falsas, Microsoft 365, Gmail e Adalove (plataforma do Inteli), que são assustadoramente fiéis.

<br>

&emsp; A parte mais doida foi o `responder_targeted.py`. No começo tentei usar o Responder original do lgandx, mas ele é muito genérico e barulhento. Queria algo mais cirúrgico, que envenenasse só o necessário e ainda servisse página fake na porta 80. Passei uma tarde inteira lendo a RFC do NBT-NS (sim, eu li a RFC) e aprendi mais sobre NetBIOS do que qualquer ser humano deveria saber. O resultado é um multi-poisoner com 6 servidores rodando em threads separadas: NBT-NS (UDP 137), LLMNR (UDP 5355), mDNS (UDP 5353), WPAD (TCP 3128), SMB fake (TCP 445), e o fake login server (TCP 80). Tudo ao mesmo tempo, tudo em stealth.

<br>

&emsp; As páginas de login falso foram um capítulo à parte. A da Microsoft 365 tem processo de duas etapas (email > senha), validação de campo, animação de loading, design Fluent UI, a porra toda. A da Adalove eu tive que fazer engenharia reversa no CSS da plataforma real pra copiar cada detalhe, até o toggle do olho no campo de senha. Os assets SVG estão embutidos no próprio código em base64, porque servir arquivo estático é pra quem tem estrutura. Testei com um moleque do apartamento ao lado que caiu no phishing e digitei a senha dele. Me senti o Kevin Mitnick por 5 minutos (e culpado por mais 10).

<br>

&emsp; Depois fui adicionando modulos mais exóticos: **AnyDesk Attack Suite**, descoberta de hosts na porta 7070, fingerprinting de versão por certificado TLS, avaliação de CVEs (CVE-2025-27918, CVE-2020-13160). **Enumeração SMB** com impacket pra verificar assinatura, modos de segurança, shares anônimos. **Captura VoIP** com ARP spoof entre telefones IP e extração de SIP/RTP. **Descoberta de câmeras** via RTSP/ONVIF probe. **Credential Hunter** passivo que monitora tráfego HTTP em tempo real atrás de senhas, tokens JWT, Basic Auth. **Detecção de vazamento mDNS** que captura nomes de dispositivos Bonjour expostos na LAN (iPhone, MacBook, Android). E por fim um **kit de exploração completo** que orquestra tudo em 6 fases: Recon > AnyDesk > MiTM/Responder > DNS Spoof/Cred > SMB Attack > Relatório.

<br>

&emsp; Durante os testes reais na rede aqui de casa, consegui capturar credenciais reais do Adalove (ianpereira2004vital@gmail.com / 40p2et, sim, ta no log, não julgo), descobri uma STB IPTV da operadora (ARRIS VIP4242H) com user_id exposto, e envenenei consultas mDNS de um Chromecast na rede. O `exploit_suggestions.txt` gerou recomendações baseadas nos serviços encontrados: AnyDesk, SMB, XMPP, MQTT, câmeras, Steam. Tudo documentado, tudo funcionando.

<br>



### Como rodar

```sh
# Dependências
sudo apt install arpspoof tcpdump nmap curl whiptail openssl python3 dsniff
pip install mitmproxy scapy impacket

# Interface TUI (requer root)
sudo bash mitm_tui.sh
```

**Requisitos:** Linux com `iptables`, `root` (bind <1024, ARP spoof, iptables)

### Estrutura

```
mitm-tui/
├── mitm_tui.sh              ← TUI principal (1362 linhas)
├── commands/
│   ├── scan                 Scan rápido de rede
│   ├── attack               Ataque completo automatizado
│   ├── creds                Exibir credenciais capturadas
│   └── dns-spoof            DNS spoof + fake login
├── tools/
│   ├── mitm_intercept.py    Addon mitmproxy (SSL strip + typosquat)
│   ├── adalove_fake.py      Página fake Adalove + Gmail
│   ├── fake_login_server.py Servidor fake Microsoft 365 + Gmail
│   ├── responder_targeted.py Multi-poisoner (NBT-NS, LLMNR, mDNS, WPAD, SMB)
│   └── deprecated/          Responders legados
```

### Funcionalidades

| # | Módulo | Descrição |
|---|--------|-----------|
| 1 | **ARP Spoof** | Envenenamento bidirecional vítima ↔ gateway |
| 2 | **DNS Spoof** | Redireciona domínios específicos para páginas falsas |
| 3 | **Fake Login** | Páginas Microsoft 365, Gmail, Adalove (alta fidelidade) |
| 4 | **Responder** | NBT-NS, LLMNR, mDNS, WPAD, SMB fake (multi-thread) |
| 5 | **SMB Enum** | Shares, assinatura, modos de segurança (impacket) |
| 6 | **AnyDesk Suite** | Descoberta (7070), fingerprint TLS, CVEs |
| 7 | **Credential Hunter** | Monitora HTTP em tempo real (senhas, tokens, cookies) |
| 8 | **VoIP Capture** | ARP spoof entre telefones IP, extração SIP/RTP |
| 9 | **Camera Discovery** | RTSP/ONVIF probe |
| 10 | **mDNS Leak** | Captura nomes Bonjour (iPhone, MacBook, Android) |
| 11 | **PCAP Analysis** | Protocolos, top talkers, DNS, hosts HTTP |

### Exemplos de uso

```sh
# ARP spoof + captura + colheita de creds
sudo bash mitm_tui.sh    # Menu > opção MITM Attack

# DNS spoof + página fake
sudo bash commands/dns-spoof 192.168.1.42

# Multi-poisoner standalone
sudo python3 tools/responder_targeted.py 192.168.1.100

# Proxy HTTPS transparente
sudo mitmdump --mode transparent -s tools/mitm_intercept.py
```

### Referências

https://github.com/lgandx/Responder

https://www.rfc-editor.org/rfc/rfc1001 (NetBIOS)

https://stackoverflow.com/questions/65544306/arp-spoof-iptables-nat-port-forwarding

https://docs.mitmproxy.org/stable/addons-overview/

https://github.com/mitsuhiko/typosquatting
