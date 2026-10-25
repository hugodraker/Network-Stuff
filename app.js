// Global State mirroring calendar.c
let zoom = 1.0;
let viewMode = 3; // 1: 1-Day, 2: 4-Day, 3: Week, 4: 4-Person, 5: 7-Person, 6: Month, 7: Upcoming
let currentDate = new Date();
let selectedEventId = null;
let showAll = true;

const people = ["Jack", "Bob", "Charlie", "David", "Eve", "Frank", "Grace"];
const colors = ["#039BE5", "#33B679", "#8E24AA", "#F4511E", "#E67C73"];

// Mock Event Data Store
let events = [
    { id: "17219424000001", title: "Team Sync", startMin: 600, duration: 60, color: colors[0], date: formatDate(new Date()), personIdx: 0, version: 1, lastModifiedBy: 1 },
    { id: "17219424000002", title: "Project Review", startMin: 840, duration: 90, color: colors[1], date: formatDate(new Date()), personIdx: 1, version: 1, lastModifiedBy: 1 }
];

// Utility: Format Date to YYYY/MM/DD
function formatDate(d) {
    return `${d.getFullYear()}/${String(d.getMonth()+1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`;
}

function minToTimeStr(min) {
    let h = Math.floor(min / 60);
    let m = min % 60;
    let ampm = h >= 12 ? 'PM' : 'AM';
    let dispH = h > 12 ? h - 12 : (h === 0 ? 12 : h);
    return `${dispH}:${String(m).padStart(2, '0')} ${ampm}`;
}

// UI Elements
const scrollArea = document.getElementById('scroll-area');
const headerRow = document.getElementById('header-row');
const timelineLabels = document.getElementById('timeline-labels');
const gridBg = document.getElementById('grid-bg');
const eventsLayer = document.getElementById('events-layer');
const lblDateTitle = document.getElementById('lblDateTitle');

function getColCount() {
    if (viewMode === 1) return 1;
    if (viewMode === 2 || viewMode === 4) return 4;
    if (viewMode === 3 || viewMode === 5) return 7;
    return 7; // Default fallback
}

function isPeopleView() { return viewMode === 4 || viewMode === 5; }

function updateDateTitle() {
    const opts = { month: 'long', day: 'numeric', year: 'numeric' };
    if (viewMode === 6) {
        lblDateTitle.innerText = currentDate.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
    } else if (viewMode === 7) {
        lblDateTitle.innerText = "Upcoming Schedule";
    } else {
        lblDateTitle.innerText = currentDate.toLocaleDateString(undefined, opts);
    }
}

function renderTimeline() {
    scrollArea.style.display = 'flex';
    gridBg.className = '';
    gridBg.innerHTML = '';
    
    let cols = getColCount();
    
    // Draw Headers
    headerRow.innerHTML = '';
    for(let i=0; i<cols; i++) {
        let div = document.createElement('div');
        div.className = 'col-header';
        if (isPeopleView()) {
            div.innerText = people[i] || `Person ${i+1}`;
        } else {
            let d = new Date(currentDate);
            d.setDate(d.getDate() + i);
            div.innerText = d.toLocaleDateString(undefined, { weekday: 'short', month: 'numeric', day: 'numeric' });
        }
        headerRow.appendChild(div);
    }

    // Draw Times
    timelineLabels.innerHTML = '';
    for(let i=0; i<=24; i++) {
        let y = i * 60 * zoom;
        let lbl = document.createElement('div');
        lbl.className = 'time-label';
        lbl.style.top = `${y}px`;
        if(i > 0 && i < 24) lbl.innerText = minToTimeStr(i * 60);
        timelineLabels.appendChild(lbl);
    }

    // Adjust Grid Background
    gridBg.style.backgroundSize = `calc(100% / ${cols}) ${60 * zoom}px`;
    eventsLayer.innerHTML = '';

    // Draw Events
    events.forEach(ev => {
        let colIdx = -1;
        if (isPeopleView()) {
            if (ev.date === formatDate(currentDate)) colIdx = ev.personIdx;
        } else {
            let evDate = new Date(ev.date);
            let diffDays = Math.round((evDate - currentDate) / (1000 * 60 * 60 * 24));
            if (diffDays >= 0 && diffDays < cols) colIdx = diffDays;
        }

        if (colIdx >= 0 && colIdx < cols) {
            let top = ev.startMin * zoom;
            let height = ev.duration * zoom;
            let left = (colIdx / cols) * 100;
            let width = 100 / cols;

            let card = document.createElement('div');
            card.className = 'event-card' + (selectedEventId === ev.id ? ' selected' : '');
            card.style.top = `${top}px`;
            card.style.height = `${height}px`;
            card.style.left = `${left}%`;
            card.style.width = `calc(${width}% - 10px)`;
            card.style.marginLeft = '5px';
            card.style.backgroundColor = ev.color;
            
            card.innerHTML = `
                <div class="event-title">${ev.title}</div>
                <div class="event-time">${minToTimeStr(ev.startMin)} - ${minToTimeStr(ev.startMin + ev.duration)}</div>
            `;
            
            card.onclick = () => { selectedEventId = ev.id; render(); };
            eventsLayer.appendChild(card);
        }
    });
}

function renderMonth() {
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
                
                // Add tiny events
                events.filter(e => e.date === cellDate).forEach(ev => {
                    let evDiv = document.createElement('div');
                    evDiv.className = 'month-event';
                    evDiv.style.backgroundColor = ev.color;
                    evDiv.innerText = ev.title;
                    cell.appendChild(evDiv);
                });
                
                cell.ondblclick = () => {
                    let stMin = 540; // 9:00 AM
                    events.push({ id: Date.now().toString(), title: "New Event", startMin: stMin, duration: 60, color: colors[events.length % colors.length], date: cellDate, personIdx: 0, version: 1, lastModifiedBy: 1 });
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

function render() {
    updateDateTitle();
    if (viewMode === 6) renderMonth();
    else renderTimeline();
}

// Bind Toolbar
document.getElementById('comboView').addEventListener('change', e => {
    viewMode = parseInt(e.target.value);
    render();
});

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

document.getElementById('btnDelete').addEventListener('click', () => {
    if (selectedEventId) {
        events = events.filter(e => e.id !== selectedEventId);
        selectedEventId = null;
        render();
    }
});

// Canvas Interaction (Double Click to Add Event)
gridBg.addEventListener('dblclick', e => {
    if (viewMode === 6) return; // Handled in renderMonth
    let rect = gridBg.getBoundingClientRect();
    let y = e.clientY - rect.top + scrollArea.scrollTop;
    let x = e.clientX - rect.left;
    
    let stMin = Math.floor(y / zoom / 30) * 30;
    stMin = Math.max(0, Math.min(1440 - 60, stMin));
    
    let cols = getColCount();
    let colIdx = Math.floor(x / (rect.width / cols));
    
    let dt = new Date(currentDate);
    if (!isPeopleView()) dt.setDate(dt.getDate() + colIdx);
    
    let pIdx = isPeopleView() ? colIdx : 0;
    
    events.push({
        id: Date.now().toString(),
        title: "New Event",
        startMin: stMin,
        duration: 60,
        color: colors[events.length % colors.length],
        date: formatDate(dt),
        personIdx: pIdx,
        version: 1,
        lastModifiedBy: 1
    });
    render();
});

// Initial Render
render();