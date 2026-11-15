/**
 * NO ENTRY Academy Frontend Module
 * Renders the 80-room curriculum catalog across 4 tracks.
 * Handles track switching, statistics, and room card rendering.
 */

let allRooms = [];
let activeTrack = 'red';

async function initAcademy() {
  await Promise.all([loadStats(), loadRooms()]);
  setupTrackTabs();
}

async function loadStats() {
  try {
    const res = await fetch('/api/academy/tracks');
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById('statTotalRooms').textContent = data.total_rooms || 80;
    document.getElementById('statAvailableRooms').textContent = data.total_implemented || 1;
    document.getElementById('statCompletedRooms').textContent = data.total_completed || 0;
    document.getElementById('statTotalXP').textContent = (data.total_xp_earned || 0) + ' XP';
  } catch (err) {
    console.error('Failed to load academy stats:', err);
  }
}

async function loadRooms() {
  try {
    const res = await fetch('/api/academy/rooms');
    if (!res.ok) return;
    allRooms = await res.json();
    renderRooms(activeTrack);
  } catch (err) {
    console.error('Failed to load rooms:', err);
  }
}

function setupTrackTabs() {
  const tabs = document.querySelectorAll('.track-tab-btn');
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      tabs.forEach(b => {
        b.classList.remove('active', 'active-red', 'active-blue', 'active-purple', 'active-detection');
      });
      activeTrack = btn.dataset.track;
      btn.classList.add('active', `active-${activeTrack}`);
      renderRooms(activeTrack);
    });
  });
}

function renderRooms(track) {
  const grid = document.getElementById('roomsGrid');
  if (!grid) return;

  const filtered = allRooms.filter(r => r.track === track);
  grid.innerHTML = '';

  if (filtered.length === 0) {
    grid.innerHTML = '<div style="color:var(--color-text-muted);font-family:var(--font-mono);grid-column: 1 / -1;padding: 30px;text-align: center;">No rooms loaded.</div>';
    return;
  }

  filtered.forEach(room => {
    const card = document.createElement('div');
    const isImplemented = room.status === 'implemented';
    const isCompleted = room.user_status === 'COMPLETED';

    card.className = `room-card ${isImplemented ? 'implemented' : ''} ${isCompleted ? 'completed' : ''}`;

    let statusPill = '';
    if (isCompleted) {
      statusPill = '<span class="status-badge completed-badge">&#10003; COMPLETED</span>';
    } else if (isImplemented) {
      statusPill = '<span class="status-badge available">&#9654; READY TO DEPLOY</span>';
    } else {
      statusPill = '<span class="status-badge planned">&#128274; COMING SOON</span>';
    }

    const padNum = String(room.room_number).padStart(2, '0');

    let buttonHtml = '';
    if (isImplemented) {
      buttonHtml = `<a href="/academy/rooms/${room.room_id}" class="btn-enter-room">${isCompleted ? 'REVIEW ROOM' : 'ENTER ROOM'} &rarr;</a>`;
    } else {
      buttonHtml = `<button class="btn-disabled" disabled>PLANNED // COMING SOON</button>`;
    }

    card.innerHTML = `
      <div>
        <div class="room-card-header">
          <span class="room-number-pill">${track.toUpperCase()} // ROOM ${padNum}</span>
          ${statusPill}
        </div>
        <h3 class="room-title">${room.title}</h3>
        <p class="room-desc">${room.short_description}</p>
        <div class="room-meta-tags">
          <span class="meta-tag">${room.difficulty}</span>
          <span class="meta-tag">${room.estimated_duration}</span>
          ${isImplemented ? `<span class="meta-tag" style="color:var(--color-cyan);border-color:rgba(0,229,255,0.3);">${room.task_count} Practical Tasks</span>` : ''}
        </div>
      </div>
      <div class="room-card-footer">
        <span class="room-xp">+${room.total_xp} XP</span>
        ${buttonHtml}
      </div>
    `;

    grid.appendChild(card);
  });
}

document.addEventListener('DOMContentLoaded', initAcademy);

