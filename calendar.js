const CALDAV_URL = `http://${window.location.hostname}:8080/calendar/`;
let zoom = 1.0;
let viewMode = 3; 
let currentDate = new Date();
let selectedEventId = null;
let events = [];

let people = ["Jack", "Bob", "Charlie", "David", "Eve", "Frank", "Grace"];
for (let i = 7; i < 255; i++) people.push("Person " + (i + 1));
const colors = ["#039BE5", "#33B679", "#8E24AA", "#F4511E", "#E67C73"];

const scrollArea = document.getElementById('scroll-area');
const headerRow = document.getElementById('header-row');
const timelineLabels = document.getElementById('timeline-labels');
const gridBg = document.getElementById('grid-bg');
const eventsLayer = document.getElementById('events-layer');
const lblDateTitle = document.getElementById('lblDateTitle');

function formatDate(d) { return `${d.getFullYear()}/${String(d.getMonth()+1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`; }
function minToTimeStr(min) {
    let h = Math.floor(min / 60), m = min % 60;
    return `${h > 12 ? h - 12 : (h === 0 ? 12 : h)}:${String(m).padStart(2, '0')} ${h >= 12 ? 'PM' : 'AM'}`;
}

function getColCount() {
    if (viewMode === 1) return 1;
    if (viewMode === 2) return 4;
    if (viewMode === 3) return 7;
    if (viewMode === 4) {
        let availableWidth = scrollArea.clientWidth - 65;
        return Math.max(1, Math.min(255, Math.floor(availableWidth / 120)));
    }
    return 7;
}
function isPeopleView() { return viewMode === 4; }

// --- CalDAV Integration ---
setInterval(downloadUpdates, 60000);

async function downloadUpdates() {
    try {
        const response = await fetch(`${CALDAV_URL}all`);
        if (response.ok) {
            events = await response.json();
        }
        const pRes = await fetch(`${CALDAV_URL}people.json`);
        if (pRes.ok) {
            let serverPeople = await pRes.json();
            for(let i=0; i<serverPeople.length; i++) people[i] = serverPeople[i];
        }
        render(); 
    } catch (e) { console.error("CalDAV Sync Download Error", e); }
}

async function putPeopleToCalDAV() {
    try {
        await fetch(`${CALDAV_URL}people.json`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(people)
        });
    } catch (e) { console.error("CalDAV People PUT Error", e); }
}

async function putEventToCalDAV(ev) {
    try {
        await fetch(`${CALDAV_URL}${ev.id}.json`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(ev)
        });
    } catch (e) { console.error("CalDAV PUT Error", e); }
}

async function deleteEventFromCalDAV(id) {
    try { await fetch(`${CALDAV_URL}${id}.json`, { method: 'DELETE' }); } 
    catch (e) { console.error("CalDAV DELETE Error", e); }
}

// --- Render Engine ---
function renderTimeline() {
    let cols = getColCount();
    lblDateTitle.innerText = currentDate.toLocaleDateString(undefined, { month: 'long', day: 'numeric', year: 'numeric' });
    
    headerRow.innerHTML = '';
    for(let i=0; i<cols; i++) {
        let div = document.createElement('div');
        div.className = 'col-header';
        
        if (isPeopleView()) {
            div.innerText = people[i];
            div.ondblclick = () => {
                let input = document.createElement('input');
                input.className = 'edit-person-input';
                input.value = people[i];
                div.innerHTML = '';
                div.appendChild(input);
                input.focus();
                
                input.onblur = input.onkeydown = (ev) => {
                    if (ev.type === 'keydown' && ev.key !== 'Enter') return;
                    people[i] = input.value || `Person ${i + 1}`;
                    putPeopleToCalDAV();
                    render();
                };
            };
        } else {
            let d = new Date(currentDate);
            d.setDate(d.getDate() + i);
            div.innerText = d.toLocaleDateString(undefined, { weekday: 'short', month: 'numeric', day: 'numeric' });
        }
        headerRow.appendChild(div);
    }

    timelineLabels.innerHTML = '';
    for(let i=0; i<=24; i++) {
        let lbl = document.createElement('div');
        lbl.className = 'time-label';
        lbl.style.top = `${i * 60 * zoom}px`;
        if(i > 0 && i < 24) lbl.innerText = minToTimeStr(i * 60);
        timelineLabels.appendChild(lbl);
    }

    gridBg.innerHTML = ''; 
    gridBg.style.backgroundSize = `calc(100% / ${cols}) ${60 * zoom}px`;
    eventsLayer.innerHTML = '';

    events.forEach(ev => {
        let colIdx = -1;
        if (isPeopleView()) {
            if (ev.date === formatDate(currentDate)) colIdx = ev.personIdx;
        } else {
            let evDate = new Date(ev.date);
            let diffDays = Math.round((evDate.getTime() - currentDate.getTime()) / 86400000);
            if (diffDays >= 0 && diffDays < cols) colIdx = diffDays;
        }

        if (colIdx >= 0 && colIdx < cols) {
            let card = document.createElement('div');
            card.className = 'event-card' + (selectedEventId === ev.id ? ' selected' : '');
            card.style.top = `${ev.startMin * zoom}px`;
            card.style.height = `${ev.duration * zoom}px`;
            card.style.left = `${(colIdx / cols) * 100}%`;
            card.style.width = `calc(${100 / cols}% - 10px)`;
            card.style.marginLeft = '5px';
            card.style.backgroundColor = ev.color;
            card.dataset.id = ev.id;
            
            card.innerHTML = `
                <div class="event-title">${ev.title}</div>
                <div class="event-time">${minToTimeStr(ev.startMin)} - ${minToTimeStr(ev.startMin + ev.duration)}</div>
                <div class="resize-handle"></div>
            `;
            
            card.onmousedown = handleDrag;
            card.querySelector('.resize-handle').onmousedown = handleResize;
            eventsLayer.appendChild(card);
        }
    });
}

function renderMonth() {
    lblDateTitle.innerText = currentDate.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
    headerRow.innerHTML = '';
    const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    days.forEach(d => {
        let div = document.createElement('div');
        div.className = 'col-header';
        div.innerText = d;
        headerRow.appendChild(div);
    });

    timelineLabels.innerHTML = '';
    gridBg.style.background = 'none';
    gridBg.innerHTML = '';
    eventsLayer.innerHTML = '';
    
    let grid = document.createElement('div');
    grid.className = 'month-grid';
    
    let y = currentDate.getFullYear();
    let m = currentDate.getMonth();
    let firstDay = new Date(y, m, 1).getDay();
    let daysInMonth = new Date(y, m + 1, 0).getDate();
    
    let cellCount = 0;
    for (let row = 0; row < 6; row++) {
        for (let col = 0; col < 7; col++) {
            let cell = document.createElement('div');
            cell.className = 'month-cell';
            
            let dayNum = cellCount - firstDay + 1;
            if (dayNum > 0 && dayNum <= daysInMonth) {
                let cellDate = `${y}/${String(m+1).padStart(2,'0')}/${String(dayNum).padStart(2,'0')}`;
                cell.innerHTML = `<div class="month-day-num">${dayNum}</div>`;
                
                events.filter(e => e.date === cellDate).forEach(ev => {
                    let evDiv = document.createElement('div');
                    evDiv.className = 'month-event';
                    evDiv.style.backgroundColor = ev.color;
                    evDiv.innerText = ev.title;
                    if(selectedEventId === ev.id) evDiv.style.outline = "2px solid #000";
                    evDiv.onclick = (e) => { e.stopPropagation(); selectedEventId = ev.id; render(); };
                    cell.appendChild(evDiv);
                });
                
                cell.ondblclick = () => {
                    let newEv = { id: Date.now().toString(), title: "New Event", startMin: 540, duration: 60, color: colors[events.length % colors.length], date: cellDate, personIdx: 0 };
                    events.push(newEv);
                    putEventToCalDAV(newEv);
                    render();
                };
            } else {
                cell.style.backgroundColor = '#f1f3f4';
            }
            grid.appendChild(cell);
            cellCount++;
        }
    }
    gridBg.appendChild(grid);
}

function renderUpcoming() {
    lblDateTitle.innerText = "Upcoming Schedule";
    headerRow.innerHTML = '';
    timelineLabels.innerHTML = '';
    gridBg.style.background = 'none';
    gridBg.innerHTML = '';
    eventsLayer.innerHTML = '';

    let container = document.createElement('div');
    container.className = 'upcoming-list';
    
    let sorted = events.filter(e => e.date >= formatDate(new Date())).sort((a,b) => a.date.localeCompare(b.date) || a.startMin - b.startMin);
    
    sorted.forEach(ev => {
        let card = document.createElement('div');
        card.className = 'upcoming-card';
        let p = people[ev.personIdx] || "";
        card.innerHTML = `
            <div class="upcoming-color" style="background:${ev.color}"></div>
            <div class="upcoming-details">
                <h3>${ev.title}</h3>
                <p>${ev.date} &nbsp;|&nbsp; ${minToTimeStr(ev.startMin)} - ${minToTimeStr(ev.startMin + ev.duration)} &nbsp;|&nbsp; ${p}</p>
            </div>
        `;
        container.appendChild(card);
    });
    
    gridBg.appendChild(container);
}

function render() {
    if (viewMode === 6) renderMonth();
    else if (viewMode === 7) renderUpcoming();
    else renderTimeline();
}

window.addEventListener('resize', render);

// --- Drag & Drop / Resize Engine ---
let isDragging = false, isResizing = false, activeCard = null, activeEv = null;
let startMouseY = 0, originalStartMin = 0, originalDuration = 0;

function handleDrag(e) {
    if (e.target.classList.contains('resize-handle')) return;
    
    selectedEventId = e.currentTarget.dataset.id;
    activeEv = events.find(ev => ev.id === selectedEventId);
    
    if (e.ctrlKey) {
        let clonedEv = { ...activeEv, id: Date.now().toString() };
        events.push(clonedEv);
        activeEv = clonedEv;
        selectedEventId = clonedEv.id;
    }

    originalStartMin = activeEv.startMin;
    startMouseY = e.clientY;
    isDragging = true;
    
    render(); 
    activeCard = document.querySelector(`.event-card[data-id='${selectedEventId}']`);
}

function handleResize(e) {
    e.stopPropagation();
    isResizing = true;
    startMouseY = e.clientY;
    activeCard = e.target.parentElement;
    selectedEventId = activeCard.dataset.id;
    activeEv = events.find(ev => ev.id === selectedEventId);
    originalDuration = activeEv.duration;
}

window.addEventListener('mousemove', e => {
    if (!activeCard || !activeEv) return;
    
    if (isDragging) {
        let deltaY = e.clientY - startMouseY;
        let deltaMins = Math.round(deltaY / zoom / 15) * 15; 
        let newMin = Math.max(0, Math.min(1440 - activeEv.duration, originalStartMin + deltaMins));
        activeEv.startMin = newMin;
        activeCard.style.top = `${newMin * zoom}px`;
        activeCard.querySelector('.event-time').innerText = `${minToTimeStr(newMin)} - ${minToTimeStr(newMin + activeEv.duration)}`;

        let rect = gridBg.getBoundingClientRect();
        let cols = getColCount();
        let xOffset = e.clientX - rect.left;
        let newColIdx = Math.max(0, Math.min(cols - 1, Math.floor(xOffset / (rect.width / cols))));
        
        if (isPeopleView()) {
            activeEv.personIdx = newColIdx;
        } else {
            let dt = new Date(currentDate);
            dt.setDate(dt.getDate() + newColIdx);
            activeEv.date = formatDate(dt);
        }
        activeCard.style.left = `${(newColIdx / cols) * 100}%`;
        
    } else if (isResizing) {
        let deltaY = e.clientY - startMouseY;
        let deltaMins = Math.round(deltaY / zoom / 15) * 15;
        let newDur = Math.max(15, Math.min(1440 - activeEv.startMin, originalDuration + deltaMins));
        activeEv.duration = newDur;
        activeCard.style.height = `${newDur * zoom}px`;
        activeCard.querySelector('.event-time').innerText = `${minToTimeStr(activeEv.startMin)} - ${minToTimeStr(activeEv.startMin + newDur)}`;
    }
});

window.addEventListener('mouseup', () => {
    if ((isDragging || isResizing) && activeEv) putEventToCalDAV(activeEv);
    isDragging = false;
    isResizing = false;
    activeCard = null;
    activeEv = null;
});

gridBg.addEventListener('dblclick', e => {
    if (viewMode >= 6) return; 
    let rect = gridBg.getBoundingClientRect();
    let y = e.clientY - rect.top + scrollArea.scrollTop;
    let x = e.clientX - rect.left;
    
    let stMin = Math.max(0, Math.min(1440 - 60, Math.floor(y / zoom / 30) * 30));
    let cols = getColCount();
    let colIdx = Math.floor(x / (rect.width / cols));
    
    let dt = new Date(currentDate);
    if (!isPeopleView()) dt.setDate(dt.getDate() + colIdx);
    
    let newEv = {
        id: Date.now().toString(), title: "New Event", startMin: stMin, duration: 60,
        color: colors[events.length % colors.length], date: formatDate(dt), personIdx: isPeopleView() ? colIdx : 0
    };
    events.push(newEv);
    putEventToCalDAV(newEv);
    render();
});

// Toolbars & Interactions
document.getElementById('comboView').addEventListener('change', e => { viewMode = parseInt(e.target.value); render(); });
document.getElementById('btnPrev').addEventListener('click', () => { 
    if (viewMode === 6) currentDate.setMonth(currentDate.getMonth() - 1);
    else currentDate.setDate(currentDate.getDate() - (viewMode === 1 ? 1 : (viewMode === 2 ? 4 : 7))); 
    render(); 
});
document.getElementById('btnNext').addEventListener('click', () => { 
    if (viewMode === 6) currentDate.setMonth(currentDate.getMonth() + 1);
    else currentDate.setDate(currentDate.getDate() + (viewMode === 1 ? 1 : (viewMode === 2 ? 4 : 7))); 
    render(); 
});
document.getElementById('btnZoomIn').addEventListener('click', () => { zoom = Math.min(2.5, zoom + 0.2); render(); });
document.getElementById('btnZoomOut').addEventListener('click', () => { zoom = Math.max(0.6, zoom - 0.2); render(); });
document.getElementById('btnSync').addEventListener('click', downloadUpdates);

document.getElementById('btnCopy').addEventListener('click', () => {
    if (selectedEventId) {
        let ev = events.find(e => e.id === selectedEventId);
        if (ev) {
            let newEv = { ...ev, id: Date.now().toString(), startMin: Math.min(1440 - ev.duration, ev.startMin + 30) };
            events.push(newEv);
            putEventToCalDAV(newEv);
            selectedEventId = newEv.id;
            render();
        }
    }
});

document.getElementById('btnDelete').addEventListener('click', () => {
    if (selectedEventId) {
        events = events.filter(e => e.id !== selectedEventId);
        deleteEventFromCalDAV(selectedEventId);
        selectedEventId = null;
        render();
    }
});

document.getElementById('btnPrint').addEventListener('click', () => {
    if (viewMode >= 6) { window.print(); return; }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'letter' });
    
    let w = 612, h = 792; 
    let rPage = { left: 18, top: 18, right: w - 18, bottom: h - 18 };
    
    let titleH = 32, subH = 25;
    let gridTop = rPage.top + titleH + subH;
    let gridH = rPage.bottom - gridTop;
    
    let cols = getColCount();
    let timeColW = 54;
    let dayColW = (rPage.right - rPage.left - timeColW) / cols;

    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(32, 33, 36);
    doc.text(lblDateTitle.innerText, rPage.left, rPage.top + 18);

    doc.setFillColor(248, 249, 250);
    doc.rect(rPage.left + timeColW, rPage.top + titleH, rPage.right - (rPage.left + timeColW), subH, "F");

    doc.setLineWidth(0.5);
    
    for (let i = 0; i <= 24; i++) {
        let y = gridTop + (i * 60) * (gridH / 1440.0);
        doc.setDrawColor(204, 204, 204);
        doc.line(rPage.left + timeColW, y, rPage.right, y);
        
        if (i > 0 && i < 24) {
            doc.setFont("helvetica", "normal");
            doc.setFontSize(9);
            doc.setTextColor(112, 117, 122);
            doc.text(minToTimeStr(i * 60), rPage.left + timeColW - 6, y + 3, { align: "right" });
        }
        
        if (i < 24) {
            let hy = gridTop + (i * 60 + 30) * (gridH / 1440.0);
            doc.setDrawColor(232, 232, 232); 
            doc.line(rPage.left + timeColW, hy, rPage.right, hy);
        }
    }

    doc.setDrawColor(204, 204, 204);
    for (let c = 0; c <= cols; c++) {
        let x = rPage.left + timeColW + (c * dayColW);
        doc.line(x, rPage.top + titleH, x, rPage.bottom);
        
        if (c < cols) {
            let hdr = isPeopleView() ? people[c] : (() => { let d = new Date(currentDate); d.setDate(d.getDate() + c); return d.toLocaleDateString(undefined, {weekday:'short', month:'numeric', day:'numeric'}); })();
            doc.setFont("helvetica", "bold");
            doc.setFontSize(11);
            doc.setTextColor(60, 64, 67);
            doc.text(hdr, x + (dayColW/2), rPage.top + titleH + 16, { align: "center" });
        }
    }

    events.forEach(ev => {
        let colIdx = -1;
        if (isPeopleView()) { if (ev.date === formatDate(currentDate)) colIdx = ev.personIdx; }
        else {
            let evDate = new Date(ev.date);
            let diffDays = Math.round((evDate.getTime() - currentDate.getTime()) / 86400000);
            if (diffDays >= 0 && diffDays < cols) colIdx = diffDays;
        }

        if (colIdx >= 0 && colIdx < cols) {
            let top = gridTop + (ev.startMin * (gridH / 1440.0));
            let bot = gridTop + ((ev.startMin + ev.duration) * (gridH / 1440.0));
            let left = rPage.left + timeColW + (colIdx * dayColW) + 2;
            let right = left + dayColW - 4;
            let ew = right - left;
            let eh = bot - top;
            
            doc.setFillColor(ev.color);
            doc.roundedRect(left, top, ew, eh, 3, 3, "F");
            
            if (eh > 18) {
                doc.setFont("helvetica", "bold");
                doc.setFontSize(9);
                doc.setTextColor(255, 255, 255);
                doc.text(ev.title, left + 4, top + 10, { maxWidth: ew - 8 });
                doc.setFont("helvetica", "normal");
                doc.text(`${minToTimeStr(ev.startMin)} - ${minToTimeStr(ev.startMin+ev.duration)}`, left + 4, top + 20);
            }
        }
    });

    doc.save("Calendar_Schedule_Vector.pdf");
});

document.getElementById('btnExport').addEventListener('click', () => {
    let content = "========================================\r\n           UPCOMING SCHEDULE            \r\n========================================\r\n\r\n";
    let sorted = events.filter(e => e.date >= formatDate(new Date())).sort((a,b) => a.date.localeCompare(b.date) || a.startMin - b.startMin);
    
    sorted.forEach(e => {
        let p = people[e.personIdx] || "";
        content += `${e.title}\r\n${e.date}       ${minToTimeStr(e.startMin)} - ${minToTimeStr(e.startMin+e.duration)}       ${p}\r\n----------------------------------------\r\n`;
    });
    
    let blob = new Blob([content], {type: "text/plain"});
    let url = URL.createObjectURL(blob);
    let a = document.createElement('a');
    a.href = url;
    a.download = "Upcoming_Schedule.txt";
    a.click();
    URL.revokeObjectURL(url);
});

downloadUpdates();