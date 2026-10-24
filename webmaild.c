/* ============================================================================
 * webmaild - Win32 HTTP to IMAP/SMTP Bridge
 * 
 * COMPILATION:
 *   gcc -Os -s -Wl,--subsystem,windows -mwindows webmaild.c -o webmaild.exe -lws2_32 -lcomctl32 -ladvapi32
 *
 * FEATURES:
 *  - Auto-generated INI Configuration (webmaild.ini)
 *  - Multi-threaded stateless IMAP/SMTP socket bridging
 *  - Modern 3-Pane Webmail UI (Left-pane navigation)
 *  - HTML Formatting, Toolbar, and Draft saving
 *  - Client-side sorting/filtering & Server-side IMAP searching
 *  - Collapsible message headers
 *
 *  2026 HUGO
 *
 * THIS WORK IS NOT FIT FOR ANY FUNCTION OR PURPOSE, COMES WITH NO WARRANTY,
 * AND IS BEING RELEASED INTO THE PUBLIC DOMAIN.
 * ============================================================================ */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_EXIT 1001
#define INI_FILE ".\\webmaild.ini"
typedef struct {
    int http_port;
    char imap_host[256];
    int imap_port;
    char smtp_host[256];
    int smtp_port;
} AppConfig;

AppConfig g_config = {0};
BOOL g_running = TRUE;
NOTIFYICONDATA g_nid = {0};

// ----------------------------------------------------------------------------
// EMBEDDED FRONTEND (HTML / CSS / JS)
// ----------------------------------------------------------------------------
const char* g_html_payload = 
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/html\r\n"
"Connection: close\r\n\r\n"
"<!DOCTYPE html><html><head><title>Webmail</title>\n"
"<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
"<style>\n"
"body { margin: 0; font-family: 'Segoe UI', sans-serif; height: 100vh; display: flex; flex-direction: column; overflow: hidden; background: #f3f2f1; }\n"
".main { display: flex; flex: 1; height: 100vh; }\n"
".sidebar { width: 220px; background: #f3f2f1; border-right: 1px solid #e1dfdd; padding: 15px 10px; display: flex; flex-direction: column; box-sizing: border-box; }\n"
".sidebar-folders { flex: 1; }\n"
".sidebar-actions { border-top: 1px solid #e1dfdd; padding-top: 15px; margin-top: 15px; font-size: 14px; display: flex; flex-direction: column; gap: 8px; }\n"
".sidebar-actions button { margin: 0 0 10px 0; }\n"
".sidebar-actions a { color: #0078D7; text-decoration: none; font-weight: 600; padding: 5px; border-radius: 4px; }\n"
".sidebar-actions a:hover { background: #e1dfdd; }\n"
".folder { padding: 10px; cursor: pointer; border-radius: 4px; margin-bottom: 5px; color: #323130; }\n"
".folder:hover { background: #edebe9; }\n"
".folder.active { background: #e1dfdd; font-weight: 600; }\n"
".list-pane { width: 320px; border-right: 1px solid #e1dfdd; background: white; display: flex; flex-direction: column; }\n"
".list-toolbar { padding: 10px; background: #faf9f8; border-bottom: 1px solid #e1dfdd; font-size: 12px; }\n"
".list-toolbar input, .list-toolbar select { width: 100%; padding: 6px; margin-bottom: 5px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 3px; }\n"
".search-row, .action-row { display: flex; gap: 5px; align-items: center; margin-bottom: 5px; flex-wrap: wrap; }\n"
".search-row input { flex: 1; margin: 0; }\n"
".action-row button, .action-row select { padding: 4px 8px; font-size: 11px; margin: 0; width: auto; height: 26px; }\n"
"#list { flex: 1; overflow-y: auto; }\n"
".mail-item { padding: 10px 15px; border-bottom: 1px solid #f3f2f1; cursor: pointer; display: flex; gap: 10px; align-items: center; }\n"
".mail-item:hover { background: #f9f9f9; }\n"
".mail-item.active { background: #f3f2f1; border-left: 3px solid #0078D7; padding-left: 12px; }\n"
".mail-item-content { flex: 1; overflow: hidden; }\n"
".mail-checkbox { margin: 0; width: auto; cursor: pointer; }\n"
".mail-subj { font-weight: 600; font-size: 14px; margin-bottom: 5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n"
".mail-from { font-size: 12px; color: #605e5c; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }\n"
".view-pane { flex: 1; padding: 30px; overflow-y: auto; background: white; font-size: 14px; line-height: 1.5; box-sizing: border-box; }\n"
".msg-actions { margin-bottom: 15px; border-bottom: 1px solid #eee; padding-bottom: 10px; }\n"
".msg-actions a { color: #0078D7; text-decoration: none; font-size: 13px; margin-right: 15px; font-weight: 600; }\n"
".msg-actions a:hover { text-decoration: underline; }\n"
"#headers-block { background: #f9f9f9; border: 1px solid #ddd; padding: 10px; font-size: 12px; margin-bottom: 15px; white-space: pre-wrap; word-break: break-all; font-family: monospace; }\n"
".overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 99; }\n"
".modal { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 25px; border-radius: 6px; box-shadow: 0 4px 20px rgba(0,0,0,0.2); width: 90%; max-width: 550px; z-index: 100; box-sizing: border-box; }\n"
".hidden { display: none !important; }\n"
"input, textarea, button { width: 100%; padding: 10px; margin-top: 8px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }\n"
"button { background: #0078D7; color: white; border: none; cursor: pointer; font-weight: 600; }\n"
"button:hover { background: #005A9E; }\n"
".btn-cancel { background: #e1dfdd; color: #323130; }\n"
".btn-cancel:hover { background: #c8c6c4; }\n"
".editor-toolbar { display: flex; gap: 5px; margin-bottom: 5px; margin-top: 8px; flex-wrap: wrap; }\n"
".editor-toolbar button { width: auto; padding: 5px 12px; margin: 0; background: #e1dfdd; color: #323130; border-radius: 4px; }\n"
".editor-toolbar button:hover { background: #c8c6c4; }\n"
"#body { height: 220px; overflow-y: auto; border: 1px solid #ccc; padding: 10px; background: white; margin-bottom: 15px; border-radius: 4px; }\n"
"#loginBox { max-width: 400px; margin: 100px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 90%; box-sizing: border-box; }\n"
"@media (max-width: 768px) {\n"
"  .main { flex-direction: column; }\n"
"  .sidebar { width: 100%; padding: 5px; border-right: none; border-bottom: 1px solid #e1dfdd; display: flex; flex-direction: row; overflow-x: auto; gap: 10px; align-items: center; }\n"
"  .sidebar-folders { display: flex; flex-direction: row; gap: 5px; }\n"
"  .sidebar-actions { display: flex; flex-direction: row; border-top: none; padding-top: 0; margin-top: 0; border-left: 1px solid #ccc; padding-left: 10px; gap: 10px; align-items: center; }\n"
"  .sidebar-actions button { margin: 0; padding: 6px 10px; white-space: nowrap; width: auto; font-size: 12px; }\n"
"  .sidebar-actions a { white-space: nowrap; font-size: 12px; }\n"
"  .folder { margin: 0; white-space: nowrap; padding: 6px 10px; font-size: 12px; }\n"
"  .list-pane { width: 100%; flex: 1; border-right: none; border-bottom: 1px solid #e1dfdd; }\n"
"  .list-toolbar { padding: 4px; display: flex; gap: 4px; flex-wrap: wrap; }\n"
"  .list-toolbar input, .list-toolbar select { flex: 1 1 30%; padding: 4px; margin: 0; font-size: 11px; height: 26px; }\n"
"  .search-row { flex: 1 1 30%; margin: 0; display: flex; }\n"
"  .search-row input { flex: 1; margin: 0; }\n"
"  .view-pane { width: 100%; padding: 10px; height: 30vh; font-size: 13px; }\n"
"}\n"
"</style></head><body>\n"
"<div id='loginBox'>\n"
"  <h2 style='margin-top:0'>Webmail Login</h2>\n"
"  <input id='u' placeholder='Username'>\n"
"  <input id='p' type='password' placeholder='Password'>\n"
"  <button onclick='login()'>Sign In</button>\n"
"  <div id='status' style='color:red; font-weight:600;'></div>\n"
"</div>\n"
"<div id='app' class='hidden'>\n"
"  <div class='main'>\n"
"    <div class='sidebar'>\n"
"      <div class='sidebar-folders'>\n"
"        <div class='folder active' id='f_INBOX' onclick=\"loadFolder('INBOX')\">Inbox</div>\n"
"        <div class='folder' id='f_Drafts' onclick=\"loadFolder('Drafts')\">Drafts</div>\n"
"        <div class='folder' id='f_Sent' onclick=\"loadFolder('Sent')\">Sent</div>\n"
"        <div class='folder' id='f_Trash' onclick=\"loadFolder('Trash')\">Trash</div>\n"
"      </div>\n"
"      <div class='sidebar-actions'>\n"
"        <button onclick=\"showModal('m-compose')\">Compose Message</button>\n"
"        <a href='#' onclick=\"showModal('m-reply')\">Auto-Replies</a>\n"
"        <a href='#' onclick=\"showModal('m-pwd')\">Password</a>\n"
"        <a href='#' onclick=\"location.reload()\">Logout</a>\n"
"      </div>\n"
"    </div>\n"
"    <div class='list-pane'>\n"
"      <div class='list-toolbar'>\n"
"        <div class='action-row'>\n"
"          <input type='checkbox' id='selectAll' onclick='toggleSelectAll()' title='Select All Rendered' style='width:auto; margin:0;'>\n"
"          <button onclick='deleteSelected()'>Delete</button>\n"
"          <select id='moveTarget'>\n"
"            <option value='INBOX'>Inbox</option>\n"
"            <option value='Drafts'>Drafts</option>\n"
"            <option value='Sent'>Sent</option>\n"
"            <option value='Trash'>Trash</option>\n"
"          </select>\n"
"          <button onclick='moveSelected()'>Move</button>\n"
"        </div>\n"
"        <div style='display:flex; gap:5px;'>\n"
"          <input id='localFilter' placeholder='Filter current view...' oninput='renderList()' style='margin:0;'>\n"
"          <select id='sortMode' onchange='renderList()' style='margin:0;'>\n"
"            <option value='id_desc'>Newest First (ID)</option>\n"
"            <option value='id_asc'>Oldest First (ID)</option>\n"
"            <option value='date_desc'>Newest First (Date)</option>\n"
"            <option value='date_asc'>Oldest First (Date)</option>\n"
"            <option value='from'>Sort by Sender</option>\n"
"            <option value='subj'>Sort by Subject</option>\n"
"          </select>\n"
"        </div>\n"
"        <div class='search-row' style='margin-top:5px;'>\n"
"          <input id='serverSearch' placeholder='Search' oninput='debounceSearch()'>\n"
"        </div>\n"
"      </div>\n"
"      <div id='list'></div>\n"
"    </div>\n"
"    <div class='view-pane' id='view'><div style='color:#999; margin-top:50px; text-align:center;'>Select a message to read</div></div>\n"
"  </div>\n"
"</div>\n"
"<!-- Modals -->\n"
"<div class='overlay hidden' id='m-compose'><div class='modal'>\n"
"  <h3 style='margin-top:0; margin-bottom:5px;'>Compose Email</h3>\n"
"  <input id='to' placeholder='To:' list='recentEmails'>\n"
"  <datalist id='recentEmails'></datalist>\n"
"  <input id='sub' placeholder='Subject:'>\n"
"  <div class='editor-toolbar'>\n"
"    <button onclick=\"document.execCommand('bold', false, null)\"><b>B</b></button>\n"
"    <button onclick=\"document.execCommand('italic', false, null)\"><i>I</i></button>\n"
"    <button onclick=\"document.execCommand('underline', false, null)\"><u>U</u></button>\n"
"  </div>\n"
"  <div id='body' contenteditable='true'></div>\n"
"  <div style='display:flex; gap:10px;'>\n"
"    <button onclick='sendMail()'>Send</button>\n"
"    <button onclick='saveDraft()' style='background:#107c41;'>Save Draft</button>\n"
"    <button class='btn-cancel' onclick=\"hideModal('m-compose')\">Cancel</button>\n"
"  </div>\n"
"</div></div>\n"
"<div class='overlay hidden' id='m-reply'><div class='modal'>\n"
"  <h3 style='margin-top:0'>Automatic Replies</h3>\n"
"  <textarea id='ar_text' rows='5' placeholder=\"I am out of the office...\"></textarea>\n"
"  <button onclick='saveAutoReply()'>Save Settings</button>\n"
"  <button class='btn-cancel' onclick=\"hideModal('m-reply')\">Cancel</button>\n"
"</div></div>\n"
"<div class='overlay hidden' id='m-pwd'><div class='modal'>\n"
"  <h3 style='margin-top:0'>Change Password</h3>\n"
"  <input type='password' id='new_pwd' placeholder='New Password'>\n"
"  <button onclick='changePwd()'>Update Password</button>\n"
"  <button class='btn-cancel' onclick=\"hideModal('m-pwd')\">Cancel</button>\n"
"</div></div>\n"
"<script>\n"
"let creds = {};\n"
"let curFolder = 'INBOX', curSender = '', curSubj = '', curBodyHTML = '';\n"
"let mailItems = [];\n"
"let searchTimeout = null;\n"
"let recentEmails = new Set();\n"
"function escapeHtml(t) { return t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }\n"
"function updateRecentEmails(text) {\n"
"  let matches = text.match(/[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z0-9_-]+/g);\n"
"  if (matches) {\n"
"    let dl = document.getElementById('recentEmails');\n"
"    matches.forEach(e => {\n"
"      let lower = e.toLowerCase();\n"
"      if (!recentEmails.has(lower)) {\n"
"        recentEmails.add(lower);\n"
"        let opt = document.createElement('option');\n"
"        opt.value = lower;\n"
"        dl.appendChild(opt);\n"
"      }\n"
"    });\n"
"  }\n"
"}\n"
"function showModal(id) { \n"
"  if(id === 'm-compose') { document.getElementById('to').value = ''; document.getElementById('sub').value = ''; document.getElementById('body').innerHTML = ''; }\n"
"  document.getElementById(id).classList.remove('hidden'); \n"
"}\n"
"function hideModal(id) { document.getElementById(id).classList.add('hidden'); }\n"
"function toggleHeaders() { document.getElementById('headers-block').classList.toggle('hidden'); }\n"
"function replyMail() {\n"
"  document.getElementById('to').value = curSender;\n"
"  document.getElementById('sub').value = curSubj.startsWith('Re:') ? curSubj : 'Re: ' + curSubj;\n"
"  document.getElementById('body').innerHTML = '<br><br><hr><b>From:</b> ' + escapeHtml(curSender) + '<br><b>Subject:</b> ' + escapeHtml(curSubj) + '<br><br>' + curBodyHTML;\n"
"  document.getElementById('m-compose').classList.remove('hidden');\n"
"}\n"
"function debounceSearch() {\n"
"  clearTimeout(searchTimeout);\n"
"  searchTimeout = setTimeout(doServerSearch, 1000);\n"
"}\n"
"function toggleSelectAll() {\n"
"  let st = document.getElementById('selectAll').checked;\n"
"  document.querySelectorAll('.mail-checkbox').forEach(cb => cb.checked = st);\n"
"}\n"
"async function deleteSelected() {\n"
"  let ids = Array.from(document.querySelectorAll('.mail-checkbox:checked')).map(cb => cb.value).join(',');\n"
"  if (!ids) return;\n"
"  document.getElementById('list').innerHTML = '<div style=\"padding:20px\">Deleting...</div>';\n"
"  await apiCall('/api/imap', curFolder + '\\nSTORE ' + ids + ' +FLAGS (\\\\Deleted)');\n"
"  await apiCall('/api/imap', curFolder + '\\nEXPUNGE');\n"
"  loadFolder(curFolder);\n"
"}\n"
"async function moveSelected() {\n"
"  let ids = Array.from(document.querySelectorAll('.mail-checkbox:checked')).map(cb => cb.value).join(',');\n"
"  let target = document.getElementById('moveTarget').value;\n"
"  if (!ids || !target || target === curFolder) return;\n"
"  document.getElementById('list').innerHTML = '<div style=\"padding:20px\">Moving...</div>';\n"
"  await apiCall('/api/imap', curFolder + '\\nCOPY ' + ids + ' \"' + target + '\"');\n"
"  await apiCall('/api/imap', curFolder + '\\nSTORE ' + ids + ' +FLAGS (\\\\Deleted)');\n"
"  await apiCall('/api/imap', curFolder + '\\nEXPUNGE');\n"
"  loadFolder(curFolder);\n"
"}\n"
"async function apiCall(endpoint, payload) {\n"
"  try {\n"
"    let reqBody = creds.u + '\\n' + creds.p + '\\n' + payload;\n"
"    let res = await fetch(endpoint, { method: 'POST', body: reqBody });\n"
"    if (!res.ok) throw new Error('HTTP ' + res.status);\n"
"    return await res.text();\n"
"  } catch(e) { return 'ERROR: ' + e.message; }\n"
"}\n"
"async function login() {\n"
"  creds = { u: document.getElementById('u').value, p: document.getElementById('p').value };\n"
"  document.getElementById('status').innerText = 'Connecting...';\n"
"  let res = await apiCall('/api/imap', 'INBOX\\nSTATUS INBOX (MESSAGES)');\n"
"  if (res.includes('OK')) {\n"
"    document.title = 'Webmail - ' + creds.u;\n"
"    document.getElementById('loginBox').classList.add('hidden');\n"
"    document.getElementById('app').classList.remove('hidden');\n"
"    loadFolder('INBOX');\n"
"  } else document.getElementById('status').innerText = 'Login Failed: ' + res;\n"
"}\n"
"async function loadFolder(f) {\n"
"  curFolder = f;\n"
"  document.querySelectorAll('.folder').forEach(el => el.classList.remove('active'));\n"
"  document.getElementById('f_' + f).classList.add('active');\n"
"  document.getElementById('serverSearch').value = '';\n"
"  document.getElementById('localFilter').value = '';\n"
"  document.getElementById('selectAll').checked = false;\n"
"  document.getElementById('list').innerHTML = '<div style=\"padding:20px\">Loading messages...</div>';\n"
"  document.getElementById('view').innerHTML = '<div style=\"color:#999; text-align:center; margin-top:50px;\">Select a message to read</div>';\n"
"  let res = await apiCall('/api/imap', f + '\\nFETCH 1:* (BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO DATE)])');\n"
"  parseAndRender(res);\n"
"}\n"
"async function doServerSearch() {\n"
"  let q = document.getElementById('serverSearch').value.trim();\n"
"  if (!q) return loadFolder(curFolder);\n"
"  document.getElementById('list').innerHTML = '<div style=\"padding:20px\">Searching server...</div>';\n"
"  let res = await apiCall('/api/imap', curFolder + '\\nSEARCH ' + q);\n"
"  let match = res.match(/\\*\\s+SEARCH\\s+([\\d\\s]+)/i);\n"
"  if (match && match[1].trim()) {\n"
"    let ids = match[1].trim().split(/\\s+/).join(',');\n"
"    let fetchRes = await apiCall('/api/imap', curFolder + '\\nFETCH ' + ids + ' (BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO DATE)])');\n"
"    parseAndRender(fetchRes);\n"
"  } else {\n"
"    document.getElementById('list').innerHTML = '<div style=\"padding:20px\">No results from server.</div>';\n"
"  }\n"
"}\n"
"function parseAndRender(res) {\n"
"  mailItems = [];\n"
"  let blocks = res.split(/\\r?\\n\\*\\s+/);\n"
"  if(blocks.length > 0 && blocks[0].startsWith('* ')) blocks[0] = blocks[0].substring(2);\n"
"  blocks.forEach(b => {\n"
"    let idMatch = b.match(/^(\\d+)/);\n"
"    if(!idMatch) return;\n"
"    let id = parseInt(idMatch[1]);\n"
"    let subj = (b.match(/Subject:\\s*([^\\r\\n]+)/i) || ['','(No Subject)'])[1];\n"
"    let from = (b.match(/From:\\s*([^\\r\\n]+)/i) || ['','Unknown Sender'])[1];\n"
"    let to = (b.match(/To:\\s*([^\\r\\n]+)/i) || ['',''])[1];\n"
"    let date = (b.match(/Date:\\s*([^\\r\\n]+)/i) || ['',''])[1];\n"
"    let ts = 0; if(date) { let d = new Date(date); if(!isNaN(d)) ts = d.getTime(); }\n"
"    updateRecentEmails(from + ' ' + to);\n"
"    mailItems.push({ id, subj, from, date, ts });\n"
"  });\n"
"  renderList();\n"
"}\n"
"function renderList() {\n"
"  let filterTxt = document.getElementById('localFilter').value.toLowerCase();\n"
"  let sortMode = document.getElementById('sortMode').value;\n"
"  let filtered = mailItems.filter(m => \n"
"      m.subj.toLowerCase().includes(filterTxt) || \n"
"      m.from.toLowerCase().includes(filterTxt) ||\n"
"      m.date.toLowerCase().includes(filterTxt)\n"
"  );\n"
"  filtered.sort((a,b) => {\n"
"     if (sortMode === 'id_desc') return b.id - a.id;\n"
"     if (sortMode === 'id_asc') return a.id - b.id;\n"
"     if (sortMode === 'from') return a.from.localeCompare(b.from);\n"
"     if (sortMode === 'subj') return a.subj.localeCompare(b.subj);\n"
"     if (sortMode === 'date_desc') return b.ts - a.ts;\n"
"     if (sortMode === 'date_asc') return a.ts - b.ts;\n"
"     return 0;\n"
"  });\n"
"  let html = '';\n"
"  filtered.forEach(m => {\n"
"    html += `<div class=\"mail-item\" id=\"mi_${m.id}\" onclick=\"loadMail('${m.id}')\">` +\n"
"            `<input type=\"checkbox\" class=\"mail-checkbox\" value=\"${m.id}\" onclick=\"event.stopPropagation()\">` +\n"
"            `<div class=\"mail-item-content\">` +\n"
"            `<div class=\"mail-subj\">${escapeHtml(m.subj)}</div>` +\n"
"            `<div class=\"mail-from\">${escapeHtml(m.from)}</div>` +\n"
"            `<div style=\"font-size:10px;color:#999;margin-top:4px;\">${escapeHtml(m.date)}</div>` +\n"
"            `</div></div>`;\n"
"  });\n"
"  if(html === '') html = '<div style=\"padding:20px\">No messages found.</div>';\n"
"  document.getElementById('list').innerHTML = html;\n"
"  document.getElementById('selectAll').checked = false;\n"
"}\n"
"async function loadMail(id) {\n"
"  document.querySelectorAll('.mail-item').forEach(i => i.classList.remove('active'));\n"
"  let el = document.getElementById('mi_' + id);\n"
"  if(el) el.classList.add('active');\n"
"  document.getElementById('view').innerHTML = 'Loading message payload...';\n"
"  let res = await apiCall('/api/imap', curFolder + '\\nFETCH ' + id + ' BODY.PEEK[]');\n"
"  \n"
"  let bodyStart = res.indexOf('\\r\\n\\r\\n', res.indexOf('FETCH (BODY[]'));\n"
"  if (bodyStart === -1) bodyStart = res.indexOf('\\n\\n', res.indexOf('FETCH (BODY[]'));\n"
"  let headers = '', content = '';\n"
"  if(bodyStart > -1) {\n"
"    headers = res.substring(res.indexOf('FETCH (BODY[]'), bodyStart).trim();\n"
"    content = res.substring(bodyStart).trim();\n"
"    let endIdx = content.lastIndexOf(')');\n"
"    if(endIdx > -1) content = content.substring(0, endIdx).trim();\n"
"  } else { content = res; }\n"
"  \n"
"  curSender = (headers.match(/From:\\s*([^\\r\\n]+)/i) || ['',''])[1];\n"
"  curSubj = (headers.match(/Subject:\\s*([^\\r\\n]+)/i) || ['',''])[1];\n"
"  curBodyHTML = content;\n"
"  \n"
"  let html = '<div class=\"msg-actions\">' +\n"
"             '<a href=\"#\" onclick=\"replyMail()\">Reply</a>' +\n"
"             '<a href=\"#\" onclick=\"toggleHeaders()\">Show/Hide Headers</a>' +\n"
"             '</div>' +\n"
"             '<div id=\"headers-block\" class=\"hidden\">' + escapeHtml(headers) + '</div>' +\n"
"             '<div id=\"mail-content\">' + content + '</div>';\n"
"  document.getElementById('view').innerHTML = html;\n"
"}\n"
"async function sendMail() {\n"
"  let payload = document.getElementById('to').value + '\\n' + document.getElementById('sub').value + '\\n' + document.getElementById('body').innerHTML;\n"
"  await apiCall('/api/smtp', payload);\n"
"  hideModal('m-compose');\n"
"  loadFolder(curFolder);\n"
"}\n"
"async function saveDraft() {\n"
"  let payload = document.getElementById('to').value + '\\n' + document.getElementById('sub').value + '\\n' + document.getElementById('body').innerHTML;\n"
"  await apiCall('/api/draft', payload);\n"
"  hideModal('m-compose');\n"
"  if (curFolder === 'Drafts') loadFolder('Drafts');\n"
"}\n"
"async function saveAutoReply() {\n"
"  let text = document.getElementById('ar_text').value.replace(/\\n/g, ' [BR] ');\n"
"  let res = await apiCall('/api/settings', text);\n"
"  alert(res);\n"
"  hideModal('m-reply');\n"
"}\n"
"async function changePwd() {\n"
"  let pwd = document.getElementById('new_pwd').value;\n"
"  let res = await apiCall('/api/pwd', pwd);\n"
"  alert(res);\n"
"  hideModal('m-pwd');\n"
"}\n"
"</script></body></html>";

// ----------------------------------------------------------------------------
// SERVER LOGIC
// ----------------------------------------------------------------------------
void LoadConfig() {
    FILE* f = fopen(INI_FILE, "r");
    if (!f) {
        f = fopen(INI_FILE, "w");
        if (f) {
            fprintf(f, "[Server]\nHttpPort=8080\n\n[Target]\nImapHost=127.0.0.1\nImapPort=143\nSmtpHost=127.0.0.1\nSmtpPort=2525\n");
            fclose(f);
        }
    } else {
        fclose(f);
    }
    
    g_config.http_port = GetPrivateProfileInt("Server", "HttpPort", 8080, INI_FILE);
    GetPrivateProfileString("Target", "ImapHost", "127.0.0.1", g_config.imap_host, 256, INI_FILE);
    g_config.imap_port = GetPrivateProfileInt("Target", "ImapPort", 143, INI_FILE);
    GetPrivateProfileString("Target", "SmtpHost", "127.0.0.1", g_config.smtp_host, 256, INI_FILE);
    g_config.smtp_port = GetPrivateProfileInt("Target", "SmtpPort", 2525, INI_FILE);
}

void TrimCR(char* str) {
    char* p = str + strlen(str) - 1;
    while(p >= str && (*p == '\r' || *p == '\n')) { *p = '\0'; p--; }
}

BOOL SafeSocketRecv(SOCKET sock, const char* expected, char* out_buf, int out_size) {
    int total = 0;
    out_buf[0] = '\0';
    while (total < out_size - 1) {
        int n = recv(sock, out_buf + total, out_size - total - 1, 0);
        if (n <= 0) return FALSE;
        total += n;
        out_buf[total] = '\0';
        if (strstr(out_buf, expected) != NULL) return TRUE;
        if (total >= out_size - 256) {
            memmove(out_buf, out_buf + total - 128, 128);
            total = 128;
            out_buf[total] = '\0';
        }
    }
    return FALSE;
}

void ExecuteImapCommand(const char* user, const char* pass, const char* folder, const char* imap_cmd, SOCKET http_client) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(g_config.imap_port);
    inet_pton(AF_INET, g_config.imap_host, &server.sin_addr);

    char http_resp[1024] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n";
    send(http_client, http_resp, strlen(http_resp), 0);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) != SOCKET_ERROR) {
        char buffer[8192];
        SafeSocketRecv(sock, "\r\n", buffer, sizeof(buffer)); 
        
        char login_cmd[512];
        sprintf(login_cmd, "A01 LOGIN \"%s\" \"%s\"\r\n", user, pass);
        send(sock, login_cmd, strlen(login_cmd), 0);
        
        if (SafeSocketRecv(sock, "A01 ", buffer, sizeof(buffer)) && strstr(buffer, "A01 OK")) {
            char select_cmd[512];
            sprintf(select_cmd, "A02 SELECT \"%s\"\r\n", folder);
            send(sock, select_cmd, strlen(select_cmd), 0);
            SafeSocketRecv(sock, "A02 OK", buffer, sizeof(buffer));

            char action_cmd[1024];
            sprintf(action_cmd, "A03 %s\r\n", imap_cmd);
            send(sock, action_cmd, strlen(action_cmd), 0);
            
            char tail[32] = {0};
            while (1) {
                int n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (n <= 0) break;
                buffer[n] = '\0';
                send(http_client, buffer, n, 0);
                
                if (n >= 16) {
                    strncpy(tail, buffer + n - 16, 15);
                    tail[15] = '\0';
                } else {
                    char temp[64];
                    sprintf(temp, "%s%s", tail, buffer);
                    int len = (int)strlen(temp);
                    if (len > 16) strcpy(tail, temp + len - 16);
                    else strcpy(tail, temp);
                }
                
                if (strstr(buffer, "A03 OK") || strstr(buffer, "A03 BAD") || strstr(buffer, "A03 NO") ||
                    strstr(tail, "A03 OK") || strstr(tail, "A03 BAD") || strstr(tail, "A03 NO")) {
                    break;
                }
            }
        } else {
            send(http_client, "LOGIN FAILED", 12, 0);
        }
        send(sock, "A04 LOGOUT\r\n", 12, 0);
    } else {
        send(http_client, "IMAP SERVER OFFLINE", 19, 0);
    }
    closesocket(sock);
}

void ExecuteDraftCommand(const char* user, const char* pass, char* payload, SOCKET http_client) {
    char to[256] = {0}, sub[256] = {0}, body[24000] = {0};
    
    char* n1 = strchr(payload, '\n');
    if (n1) {
        *n1 = '\0'; strncpy(to, payload, 255);
        char* n2 = strchr(n1 + 1, '\n');
        if (n2) {
            *n2 = '\0'; strncpy(sub, n1 + 1, 255);
            strncpy(body, n2 + 1, 23999);
        }
    }
    TrimCR(to); TrimCR(sub);

    char* eml = (char*)malloc(32000);
    if (!eml) return;
    sprintf(eml, "From: %s\r\nSubject: %s\r\nTo: %s\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n%s", user, sub, to, body);
    int eml_len = (int)strlen(eml);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(g_config.imap_port);
    inet_pton(AF_INET, g_config.imap_host, &server.sin_addr);

    char http_resp[1024] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n";
    send(http_client, http_resp, strlen(http_resp), 0);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) != SOCKET_ERROR) {
        char buffer[8192];
        SafeSocketRecv(sock, "\r\n", buffer, sizeof(buffer)); 
        
        char login_cmd[512];
        sprintf(login_cmd, "A01 LOGIN \"%s\" \"%s\"\r\n", user, pass);
        send(sock, login_cmd, strlen(login_cmd), 0);
        
        if (SafeSocketRecv(sock, "A01 ", buffer, sizeof(buffer)) && strstr(buffer, "A01 OK")) {
            char append_cmd[512];
            sprintf(append_cmd, "A02 APPEND \"Drafts\" (\\Draft) {%d}\r\n", eml_len);
            send(sock, append_cmd, strlen(append_cmd), 0);
            
            if (SafeSocketRecv(sock, "+", buffer, sizeof(buffer))) {
                send(sock, eml, eml_len, 0);
                send(sock, "\r\n", 2, 0);
                SafeSocketRecv(sock, "A02 ", buffer, sizeof(buffer));
            }
        }
        send(sock, "A03 LOGOUT\r\n", 12, 0);
        send(http_client, "Draft Saved", 11, 0);
    } else {
        send(http_client, "IMAP SERVER OFFLINE", 19, 0);
    }
    closesocket(sock);
    free(eml);
}

void ExecuteSmtpCommand(const char* user, const char* pass, char* payload, SOCKET http_client) {
    char to[256] = {0}, sub[256] = {0}, body[24000] = {0};
    
    char* n1 = strchr(payload, '\n');
    if (n1) {
        *n1 = '\0'; strncpy(to, payload, 255);
        char* n2 = strchr(n1 + 1, '\n');
        if (n2) {
            *n2 = '\0'; strncpy(sub, n1 + 1, 255);
            strncpy(body, n2 + 1, 23999);
        }
    }
    TrimCR(to); TrimCR(sub);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(g_config.smtp_port);
    inet_pton(AF_INET, g_config.smtp_host, &server.sin_addr);

    char http_resp[1024] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n";
    send(http_client, http_resp, strlen(http_resp), 0);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) != SOCKET_ERROR) {
        char buf[1024];
        SafeSocketRecv(sock, "\r\n", buf, sizeof(buf));
        send(sock, "EHLO webmaild\r\n", 15, 0);
        SafeSocketRecv(sock, "250 ", buf, sizeof(buf));
        
        char mail_cmd[512];
        sprintf(mail_cmd, "MAIL FROM:<%s>\r\n", user);
        send(sock, mail_cmd, strlen(mail_cmd), 0);
        SafeSocketRecv(sock, "250 ", buf, sizeof(buf));

        sprintf(mail_cmd, "RCPT TO:<%s>\r\n", to);
        send(sock, mail_cmd, strlen(mail_cmd), 0);
        SafeSocketRecv(sock, "250 ", buf, sizeof(buf));

        send(sock, "DATA\r\n", 6, 0);
        SafeSocketRecv(sock, "354 ", buf, sizeof(buf));

        char* data_payload = (char*)malloc(32000);
        if (data_payload) {
            sprintf(data_payload, "From: %s\r\nSubject: %s\r\nTo: %s\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n%s\r\n.\r\n", user, sub, to, body);
            send(sock, data_payload, strlen(data_payload), 0);
            free(data_payload);
        }
        
        SafeSocketRecv(sock, "250 ", buf, sizeof(buf));
        
        send(http_client, "Message Sent", 12, 0);
        send(sock, "QUIT\r\n", 6, 0);
        closesocket(sock);
        
        char* eml = (char*)malloc(32000);
        if (eml) {
            sprintf(eml, "From: %s\r\nSubject: %s\r\nTo: %s\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n%s", user, sub, to, body);
            int eml_len = (int)strlen(eml);

            SOCKET isock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            struct sockaddr_in iserver = {0};
            iserver.sin_family = AF_INET;
            iserver.sin_port = htons(g_config.imap_port);
            inet_pton(AF_INET, g_config.imap_host, &iserver.sin_addr);

            if (connect(isock, (struct sockaddr*)&iserver, sizeof(iserver)) != SOCKET_ERROR) {
                char ibuf[8192];
                SafeSocketRecv(isock, "\r\n", ibuf, sizeof(ibuf)); 
                
                char login_cmd[512];
                sprintf(login_cmd, "A01 LOGIN \"%s\" \"%s\"\r\n", user, pass);
                send(isock, login_cmd, strlen(login_cmd), 0);
                
                if (SafeSocketRecv(isock, "A01 ", ibuf, sizeof(ibuf)) && strstr(ibuf, "A01 OK")) {
                    char append_cmd[512];
                    sprintf(append_cmd, "A02 APPEND \"Sent\" (\\Seen) {%d}\r\n", eml_len);
                    send(isock, append_cmd, strlen(append_cmd), 0);
                    
                    if (SafeSocketRecv(isock, "+", ibuf, sizeof(ibuf))) {
                        send(isock, eml, eml_len, 0);
                        send(isock, "\r\n", 2, 0);
                        SafeSocketRecv(isock, "A02 ", ibuf, sizeof(ibuf));
                    }
                }
                send(isock, "A03 LOGOUT\r\n", 12, 0);
            }
            closesocket(isock);
            free(eml);
        }
    } else {
        send(http_client, "SMTP SERVER OFFLINE", 19, 0);
        closesocket(sock);
    }
}
DWORD WINAPI HttpClientHandler(LPVOID lpParam) {
    SOCKET client = (SOCKET)lpParam;
    char buffer[32768] = {0};
    int total = 0;
    
    while (total < 32767) {
        int n = recv(client, buffer + total, 32767 - total, 0);
        if (n <= 0) break;
        total += n;
        if (strstr(buffer, "\r\n\r\n")) break;
    }

    if (strncmp(buffer, "GET / ", 6) == 0) {
        send(client, g_html_payload, strlen(g_html_payload), 0);
    } 
    else if (strncmp(buffer, "POST /api/", 10) == 0) {
        char* body_start = strstr(buffer, "\r\n\r\n");
        if (body_start) {
            body_start += 4;
            
            char user[256] = {0}, pass[256] = {0}, payload[24000] = {0};
            char* n1 = strchr(body_start, '\n');
            if (n1) {
                *n1 = '\0'; strncpy(user, body_start, 255);
                char* n2 = strchr(n1 + 1, '\n');
                if (n2) {
                    *n2 = '\0'; strncpy(pass, n1 + 1, 255);
                    strncpy(payload, n2 + 1, 23999);
                }
            }
            TrimCR(user); TrimCR(pass);
            
            if (strncmp(buffer, "POST /api/imap", 14) == 0) {
                char folder[256] = {0}, imap_cmd[4096] = {0};
                char* n3 = strchr(payload, '\n');
                if (n3) {
                    *n3 = '\0'; strncpy(folder, payload, 255);
                    strncpy(imap_cmd, n3 + 1, 4095);
                }
                TrimCR(folder);
                ExecuteImapCommand(user, pass, folder, imap_cmd, client);
            } 
            else if (strncmp(buffer, "POST /api/draft", 15) == 0) {
                ExecuteDraftCommand(user, pass, payload, client);
            }
            else if (strncmp(buffer, "POST /api/smtp", 14) == 0) {
                ExecuteSmtpCommand(user, pass, payload, client);
            }
            else if (strncmp(buffer, "POST /api/settings", 18) == 0) {
                char section[256];
                sprintf(section, "AutoReply_%s", user);
                WritePrivateProfileString(section, "Text", payload, INI_FILE);
                WritePrivateProfileString(section, "Enabled", "1", INI_FILE);
                send(client, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nAuto-Reply configuration saved to webmaild.ini.", 86, 0);
            }
            else if (strncmp(buffer, "POST /api/pwd", 13) == 0) {
                const char* err_msg = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
                                      "ERROR: Password changes require background file re-encryption.\n"
                                      "Please use the imapd.exe GUI (Server Settings) to safely update user passwords.";
                send(client, err_msg, strlen(err_msg), 0);
            }
        }
    }
    closesocket(client);
    return 0;
}

DWORD WINAPI HttpWorkerThread(LPVOID lpParam) {
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(g_config.http_port);
    
    bind(listen_sock, (struct sockaddr*)&server, sizeof(server));
    listen(listen_sock, SOMAXCONN);

    while (g_running) {
        struct sockaddr_in cli; int csize = sizeof(cli);
        SOCKET client = accept(listen_sock, (struct sockaddr*)&cli, &csize);
        if (client != INVALID_SOCKET) {
            CreateThread(NULL, 0, HttpClientHandler, (LPVOID)client, 0, NULL);
        }
    }
    closesocket(listen_sock);
    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_TRAYICON) {
        if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP) {
            HMENU hMenu = CreatePopupMenu();
            AppendMenu(hMenu, MF_STRING, ID_TRAY_EXIT, "Exit Webmaild");
            POINT pt; GetCursorPos(&pt);
            SetForegroundWindow(hwnd);
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
            DestroyMenu(hMenu);
        }
    } else if (uMsg == WM_COMMAND && LOWORD(wParam) == ID_TRAY_EXIT) {
        PostQuitMessage(0);
    } else if (uMsg == WM_DESTROY) {
        Shell_NotifyIcon(NIM_DELETE, &g_nid);
        PostQuitMessage(0);
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow) {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    LoadConfig();
    
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "WebmaildClass";
    RegisterClass(&wc);
    HWND hwnd = CreateWindow("WebmaildClass", "webmaild", 0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
    
    g_nid.cbSize = sizeof(NOTIFYICONDATA);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    sprintf(g_nid.szTip, "webmaild (Port %d)", g_config.http_port);
    Shell_NotifyIcon(NIM_ADD, &g_nid);

    CreateThread(NULL, 0, HttpWorkerThread, NULL, 0, NULL);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    g_running = FALSE;
    WSACleanup();
    return 0;
}