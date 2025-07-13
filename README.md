# 🔐 Vulnerabilidades Conhecidas em Sistemas Windows Desatualizados

## 📋 Menu

- [🪟 Windows XP](#-windows-xp)
- [🪟 Windows 7](#-windows-7)
- [🪟 Windows 10 (Desatualizado)](#-windows-10-desatualizado)
- [🪟 Windows 11 (Desatualizado)](#-windows-11-desatualizado)

---

## 🪟 Windows XP

### 🔸 MS08-067 (CVE-2008-4250)
- **Serviço:** Server Service (SMB)  
- **Porta:** 445/TCP  
- **Descrição:** Vulnerabilidade crítica de execução remota de código via falha no serviço Server, explorada pelo worm Conficker.  
- **Exploit/PoC:**  
  - [Metasploit Module](https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi/)  
  - [Exploit Code (Exploit-DB)](https://www.exploit-db.com/exploits/7132)

### 🔸 Blaster Worm (MS03-026, CVE-2003-0352)
- **Serviço:** DCOM RPC  
- **Porta:** 135/TCP  
- **Descrição:** Execução remota de código via falha no serviço DCOM, explorada pelo worm Blaster.  
- **Exploit/PoC:**  
  - [Metasploit Module](https://github.com/rapid7/metasploit-framework)  
  - [Exploit Code (Exploit-DB)](https://www.exploit-db.com/exploits/146)

### 🔸 Sasser Worm (MS04-011, CVE-2004-0115)
- **Serviço:** LSASS  
- **Porta:** 445/TCP  
- **Descrição:** Execução remota de código no serviço LSASS, explorada pelo worm Sasser.  
- **Exploit/PoC:**  
  - [Metasploit Module](https://www.rapid7.com/db/modules/exploit/windows/dcerpc/ms03_026_dcom/)  
  - [Exploit Code (Exploit-DB)](https://www.exploit-db.com/exploits/122)

### 🔸 RPC DCOM Buffer Overflow (CVE-2003-0352)
- **Serviço:** RPC DCOM  
- **Porta:** 135/TCP  
- **Descrição:** Buffer overflow que permite execução remota de código via falha no serviço RPC DCOM.  
- **Exploit/PoC:**  
  - [Metasploit Module](https://github.com/rapid7/metasploit-framework)  
  - [Exploit Code (Exploit-DB)](https://www.exploit-db.com/exploits/146)

### 🔸 Windows XP SMBv1 Vulnerability (CVE-2017-0143 a 0148)
- **Serviço:** SMBv1  
- **Porta:** 445/TCP  
- **Descrição:** Vulnerabilidades críticas no SMBv1 que permitem execução remota de código, base para o exploit EternalBlue.  
- **Exploit/PoC:**  
  - [Metasploit Module (EternalBlue)](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/smb/ms17_010_eternalblue.rb)  
  - [GitHub PoC (PowerSploit)](https://github.com/PowerShellMafia/PowerSploit)

---

## 🪟 Windows 7

### 🔸 EternalBlue (CVE-2017-0144)
- **Serviço:** SMBv1  
- **Porta:** 445/TCP  
- **Descrição:** Execução remota de código via falha no SMBv1, explorada por WannaCry e NotPetya.  
- **Exploit/PoC:**  
  - [Metasploit Module](https://github.com/rapid7/metasploit-framework)  
  - [GitHub PoC](https://github.com/worawit/MS17-010)  
  - [Shadow Brokers Leak](https://github.com/misterch0c/shadowbroker)

### 🔸 BlueKeep (CVE-2019-0708)
- **Serviço:** RDP  
- **Porta:** 3389/TCP  
- **Descrição:** RCE sem autenticação via RDP, worm-like.  
- **Exploit/PoC:**  
  - [Metasploit Module](https://github.com/rapid7/metasploit-framework)  
  - [GitHub PoC](https://github.com/zerosum0x0/CVE-2019-0708)

### 🔸 SMBGhost (CVE-2020-0796)
- **Serviço:** SMBv3  
- **Porta:** 445/TCP  
- **Descrição:** RCE e DoS via SMBv3.  
- **Exploit/PoC:**  
  - [GitHub PoC](https://github.com/chompie1337/SMBGhost_RCE_PoC)  
  - [Technical Analysis](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0796)

### 🔸 Zerologon (CVE-2020-1472)
- **Serviço:** Netlogon  
- **Portas:** 135/TCP, 445/TCP, RPC dinâmico  
- **Descrição:** Elevação de privilégios e controle de domínio via falha no Netlogon.  
- **Exploit/PoC:**  
  - [Metasploit Module](https://github.com/rapid7/metasploit-framework)  
  - [GitHub PoC](https://github.com/SecuraBV/CVE-2020-1472)

### 🔸 CVE-2020-0601 (CurveBall)
- **Serviço:** Validação de certificados TLS/SSL  
- **Portas:** 443/TCP, 636/TCP  
- **Descrição:** Spoofing de certificados, ataques MITM.  
- **Exploit/PoC:**  
  - [PoC (GitHub)](https://github.com/ollypwn/curveball)  
  - [Microsoft Advisory](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0601)

---

## 🪟 Windows 10 Desatualizado

### 🔸 PrintNightmare (CVE-2021-34527)
- **Serviço:** Spooler de Impressão  
- **Portas:** RPC dinâmico, 445/TCP  
- **Descrição:** RCE via serviço de spooler, permite controle remoto.  
- **Exploit/PoC:**  
  - [Metasploit Module](https://github.com/rapid7/metasploit-framework)  
  - [GitHub PoC](https://github.com/afwu/PrintNightmare)

### 🔸 Zerologon (CVE-2020-1472)  
**Mesma descrição e fontes do Windows 7**

### 🔸 SMBGhost (CVE-2020-0796)  
**Mesma descrição e fontes do Windows 7**

### 🔸 CVE-2021-40444
- **Serviço:** MSHTML (Internet Explorer)  
- **Porta:** Não aplicável  
- **Descrição:** RCE via documentos Office maliciosos.  
- **Exploit/PoC:**  
  - [GitHub PoC](https://github.com/lockedbyte/CVE-2021-40444)  
  - [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444)

### 🔸 Follina (CVE-2022-30190)
- **Serviço:** MSDT via documentos Office  
- **Porta:** Não aplicável  
- **Descrição:** RCE via documentos Office sem macros.  
- **Exploit/PoC:**  
  - [GitHub PoC](https://github.com/JohnHammond/msdt-follina)  
  - [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190)

---

## 🪟 Windows 11 Desatualizado

### 🔸 CVE-2023-23397
- **Serviço:** Outlook (Exchange/SMTP/IMAP)  
- **Portas:** 25/TCP, 143/TCP, 443/TCP  
- **Descrição:** Roubo de credenciais NTLM via convites de calendário maliciosos.  
- **Exploit/PoC:**  
  - [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397)  
  - PoCs públicos limitados.

### 🔸 CVE-2023-21608
- **Serviço:** Kernel do Windows  
- **Porta:** Não aplicável  
- **Descrição:** Elevação de privilégios local, contorna CFG.  
- **Exploit/PoC:**  
  - [GitHub PoC](https://github.com/hacksysteam/CVE-2023-21608)

### 🔸 ProxyNotShell (CVE-2022-41040/41082)
- **Serviço:** Microsoft Exchange Server  
- **Portas:** 443/TCP, 25/TCP, 135/TCP, RPC dinâmico  
- **Descrição:** RCE e elevação de privilégios em Exchange via ataques zero-click.  
- **Exploit/PoC:**  
  - [GitHub PoC](https://github.com/n3r0sec/ProxyNotShell)  
  - [Microsoft Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040)

### 🔸 CVE-2023-28252
- **Serviço:** Windows CLFS  
- **Porta:** Não aplicável  
- **Descrição:** Elevação de privilégios local via manipulação do sistema de logs.  
- **Exploit/PoC:**  
  - [GitHub PoC](https://github.com/hacksysteam/CVE-2023-28252)

### 🔸 CVE-2023-36884
- **Serviço:** Arquivos Office  
- **Porta:** Não aplicável  
- **Descrição:** RCE via documentos Office maliciosos, zero-click.  
- **Exploit/PoC:**  
  - [GitHub PoC](https://github.com/b1tg/CVE-2023-36884)

---
