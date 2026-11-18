;<div align="center">

# 🌐 Network Stuff

A collection of lightweight, standalone C network servers, daemons, clients, protocols, and utility tools curated by **Hugo**. Most tools include pre-compiled Windows executables (`.exe`) alongside their source code (`.c`).

</div>

## 🗂️ Component Directory

Here is an overview of the network tools, servers, and utilities included in this repository, categorized by function:

### 💬 Chat & Communication
* **`chatclient.c` / `chatclient.exe`**: Lightweight client for connecting to chat daemons.
* **`chatd.c` / `chatd.exe`**: Standalone chat daemon/server.
* **`eliza_statistical.c`**: Statistical ELIZA conversational agent implementation.

### 🗄️ File Sharing & Storage Servers
* **`ftpserver.c` / `ftpserver.exe` & `ftpservergui.c` / `ftpservergui.exe`**: FTP server core and GUI variant.
* **`ftpsearch.c` / `ftpsearch.exe`**: Utility to search FTP servers.
* **`smb1server.c` / `smb1server.exe`**: SMBv1 protocol server implementation.
* **`smb2c.c` / `smb2c.exe` & `smb2d.c` / `smb2d.exe` & `smb2server.c` / `smb2server.exe`**: SMBv2 client, daemon, and server utilities.
* **`dlna_server.c` / `dlna_server.exe` & `dlna2c.c` / `dlna2c.exe`**: DLNA media streaming servers.

### 📧 Mail, Calendar & Web Daemons
* **`imapd.c` / `imapd.exe` & `imapd.ini`**: IMAP mail server daemon and config.
* **`smtpd.c` / `smtpd.exe` & `smtpd.ini`**: SMTP mail server daemon and config.
* **`webmaild.c` / `webmaild.exe`**: Webmail daemon interface.
* **`caldavd.c` / `caldavd.exe`**: CalDAV calendar server daemon.
* **`dnsd.c` / `dnsd.exe`**: Lightweight DNS server/daemon.

### 🖥️ Web Assets & Frontend UI
* **`index.html` / `calendar.html`**: HTML frontends for web-based tools/calendars.
* **`app.js` / `calendar.js`**: JavaScript client-side scripts.
* **`style.css`**: Styling sheets for the web interfaces.

### 🛠️ System Utilities & Tools
* **`wificon.c` / `wificon.exe`**: Wi-Fi connection utility.
* **`make_certs.c` / `make_certs.exe`**: Utility for generating TLS/SSL certificates (`.pem` / `.crt`).
* **`sync.c` / `sync.exe`**: Data or file synchronization utility.
* **`shortcutc.c` / `shortcutc.exe`**: Shortcut creation utility.
* **`gui_compiler.c` / `gui_compiler.exe`**: GUI compilation helper.
* **`wordis.c` / `wordis.exe`**: Runs a command on secret word: launchpad.
* **`Smd2d.c`**: Additional modular component utility.
* **`config.ini`**: Global configuration file template.

---

## 🚀 Getting Started

Clone the repository to explore the source code or run the pre-compiled binaries:

```bash
git clone https://github.com/hugodraker/Network-Stuff.git
cd Network-Stuff
```

## 📋 Compilation

Most `.c` files are written as standalone applications and can be compiled easily using standard C compilers (such as GCC):

```bash
gcc chatd.c -o chatd.exe
```

## 📝 License

Distributed under the Unlicense.
