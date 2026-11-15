/**
 * NO ENTRY - Threat Intel Screen Controller (Screen 11)
 * Manages IOC database, feed synchronization bars, scanning animation with
 * deterministic verdict lookup, and 3D orbitable force-directed campaign graph.
 */

import * as THREE from 'three';
import { initAppShell } from '../core/appShell.js';
import { api } from '../core/api.js';
import { sound } from '../core/sound.js';
import { toast } from '../core/ui.js';

class IntelController {
  constructor() {
    this.state = null;
    this.graphData = null;
    this.threeScene = null;
    this.nodesMap = new Map();
  }

  async init() {
    initAppShell('intel');
    this.bindSearchEvents();
    await this.loadIntelData();
  }

  async loadIntelData() {
    try {
      const data = await api.get('/api/intel');
      this.state = data;
      this.graphData = data.graph;
      this.renderFeeds();
      this.renderIndicators();
      this.init3DGraph();
    } catch (err) {
      console.error('Failed to load threat intel data:', err);
      toast('Failed to load threat intel state', 'error');
    }
  }

  renderFeeds() {
    const container = document.getElementById('feedGridContainer');
    if (!container || !this.state.feeds) return;

    container.innerHTML = '';
    this.state.feeds.forEach(feed => {
      const card = document.createElement('div');
      card.className = 'feed-card';
      const isOnline = feed.status === 'ONLINE';

      card.innerHTML = `
        <div class="feed-header">
          <span style="font-weight: 700; color: #FFFFFF;">${feed.name}</span>
          <span style="color: ${feed.color}; font-size: 10px;">
            <span class="pulse-dot" style="background: ${feed.color};"></span> ${feed.status}
          </span>
        </div>
        <div style="display: flex; justify-content: space-between; font-size: 10px; color: var(--color-muted); font-family: var(--font-mono); margin-bottom: 4px;">
          <span>HEALTH: ${feed.score}%</span>
          <span>${feed.latency}</span>
        </div>
        <div class="area-bar-track" style="height: 4px;">
          <div class="area-bar-fill" style="width: ${feed.score}%; background: ${feed.color}; box-shadow: 0 0 6px ${feed.color};"></div>
        </div>
      `;
      container.appendChild(card);
    });
  }

  renderIndicators() {
    const tbody = document.getElementById('indicatorsTbody');
    if (!tbody || !this.state.indicators) return;

    tbody.innerHTML = '';
    this.state.indicators.forEach(ioc => {
      const tr = document.createElement('tr');
      const scoreColor = ioc.score >= 90 ? 'var(--color-red)' : (ioc.score >= 80 ? '#FFB800' : 'var(--color-cyan)');

      tr.innerHTML = `
        <td style="color: #FFFFFF; font-weight: 700;">${ioc.value}</td>
        <td style="color: var(--color-cyan);">${ioc.type}</td>
        <td>
          <div class="score-bar-mini">
            <div class="score-bar-mini-fill" style="width: ${ioc.score}%; background: ${scoreColor};"></div>
          </div>
          <span style="color: ${scoreColor}; font-weight: 700;">${ioc.score}</span>
        </td>
        <td style="color: #FFB800;">${ioc.campaign}</td>
        <td style="color: var(--color-muted);">${ioc.source}</td>
      `;

      tr.addEventListener('click', () => {
        const input = document.getElementById('iocSearchInput');
        if (input) {
          input.value = ioc.value;
          this.performLookup(ioc.value);
        }
      });

      tbody.appendChild(tr);
    });
  }

  bindSearchEvents() {
    const btn = document.getElementById('iocSearchBtn');
    const input = document.getElementById('iocSearchInput');

    if (btn) {
      btn.addEventListener('click', () => {
        if (input && input.value.trim()) {
          this.performLookup(input.value.trim());
        }
      });
    }

    if (input) {
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && input.value.trim()) {
          this.performLookup(input.value.trim());
        }
      });
    }
  }

  async performLookup(query) {
    const strip = document.getElementById('scanningStrip');
    const stripText = document.getElementById('scanningText');
    const verdictBox = document.getElementById('verdictBox');

    if (strip && stripText) {
      strip.style.display = 'block';
      stripText.textContent = `> hashing IOC query: "${query}" to SHA-256...`;
      sound.blip();
    }
    if (verdictBox) verdictBox.style.display = 'none';

    await new Promise(r => setTimeout(r, 450));
    if (stripText) stripText.textContent = `> cross-referencing AbuseIPDB, VirusTotal & AlienVault feeds...`;
    await new Promise(r => setTimeout(r, 550));

    try {
      const res = await api.get(`/api/intel/lookup?ioc=${encodeURIComponent(query)}`);
      sound.panelOpen();

      if (strip) strip.style.display = 'none';

      if (verdictBox) {
        const isMal = res.verdict === 'MALICIOUS';
        const vColor = isMal ? 'var(--color-red)' : '#FFB800';

        verdictBox.style.display = 'block';
        verdictBox.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--color-border); padding-bottom: 8px; margin-bottom: 10px;">
            <div>
              <span style="font-weight: 700; color: #FFFFFF; font-size: 14px;">${res.query}</span>
              <span style="font-size: 11px; color: var(--color-muted); margin-left: 8px;">[${res.category}]</span>
            </div>
            <div>
              <span class="badge" style="background: ${isMal ? 'rgba(255,31,61,0.2)' : 'rgba(255,184,0,0.2)'}; border: 1px solid ${vColor}; color: ${vColor}; font-weight: 700;">
                ${res.verdict} &bull; SCORE ${res.score}/100
              </span>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-family: var(--font-mono); font-size: 11px;">
            <div><span style="color: var(--color-muted);">Campaign:</span> <span style="color: #FFB800;">${res.campaign}</span></div>
            <div><span style="color: var(--color-muted);">Malware:</span> <span style="color: #FFFFFF;">${res.malware}</span></div>
            <div><span style="color: var(--color-muted);">Origin:</span> <span style="color: var(--color-cyan);">${res.country}</span></div>
            <div><span style="color: var(--color-muted);">ASN:</span> <span style="color: #FFFFFF;">${res.asn}</span></div>
            <div><span style="color: var(--color-muted);">Confidence:</span> <span style="color: var(--color-green);">${res.confidence}%</span></div>
            <div><span style="color: var(--color-muted);">Last Seen:</span> <span style="color: #FFFFFF;">${res.last_seen}</span></div>
          </div>
        `;
      }
    } catch (err) {
      console.error('Failed to lookup IOC:', err);
      toast('Failed to retrieve IOC verdict', 'error');
      if (strip) strip.style.display = 'none';
    }
  }

  init3DGraph() {
    const container = document.getElementById('graphCanvasContainer');
    if (!container || !this.graphData) return;

    const width = container.clientWidth || 450;
    const height = container.clientHeight || 520;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 100);
    camera.position.set(0, 0, 16);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
    container.appendChild(renderer.domElement);

    const graphGroup = new THREE.Group();
    scene.add(graphGroup);

    // Position Nodes in 3D Orbital Constellation
    const nodeCount = this.graphData.nodes.length;
    const nodePositions = new Map();

    this.graphData.nodes.forEach((node, idx) => {
      let x, y, z;
      if (node.group === 'campaign') {
        // Center-cluster for campaigns
        const ang = (idx * 2 * Math.PI) / 3;
        x = Math.cos(ang) * 2.8;
        y = Math.sin(ang) * 2.8;
        z = (Math.random() - 0.5) * 1.5;
      } else {
        // Outer shell
        const phi = Math.acos(-1 + (2 * idx) / nodeCount);
        const theta = Math.sqrt(nodeCount * Math.PI) * phi;
        const rad = 6.5;
        x = rad * Math.cos(theta) * Math.sin(phi);
        y = rad * Math.sin(theta) * Math.sin(phi);
        z = rad * Math.cos(phi);
      }

      nodePositions.set(node.id, new THREE.Vector3(x, y, z));

      // Node Geometry & Material
      const geo = new THREE.SphereGeometry(node.group === 'campaign' ? 0.45 : 0.28, 16, 16);
      const colorHex = node.color ? parseInt(node.color.replace('#', '0x')) : 0x00E5FF;
      const mat = new THREE.MeshBasicMaterial({ color: colorHex, wireframe: true });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.set(x, y, z);
      graphGroup.add(mesh);
    });

    // Links between Nodes
    const lineMat = new THREE.LineBasicMaterial({
      color: 0x00E5FF,
      transparent: true,
      opacity: 0.35
    });

    this.graphData.links.forEach(link => {
      const p1 = nodePositions.get(link.source);
      const p2 = nodePositions.get(link.target);
      if (p1 && p2) {
        const lineGeo = new THREE.BufferGeometry().setFromPoints([p1, p2]);
        const line = new THREE.Line(lineGeo, lineMat);
        graphGroup.add(line);
      }
    });

    // Mouse Drag Orbit Controls
    let isDragging = false;
    let prevMouseX = 0;
    let prevMouseY = 0;

    container.addEventListener('mousedown', (e) => {
      isDragging = true;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;
    });

    window.addEventListener('mouseup', () => {
      isDragging = false;
    });

    window.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      const deltaX = e.clientX - prevMouseX;
      const deltaY = e.clientY - prevMouseY;
      prevMouseX = e.clientX;
      prevMouseY = e.clientY;

      graphGroup.rotation.y += deltaX * 0.008;
      graphGroup.rotation.x += deltaY * 0.008;
    });

    // Scroll to Zoom
    container.addEventListener('wheel', (e) => {
      e.preventDefault();
      camera.position.z = Math.min(26, Math.max(8, camera.position.z + e.deltaY * 0.02));
    }, { passive: false });

    // Animation Loop
    let clock = new THREE.Clock();
    const animate = () => {
      requestAnimationFrame(animate);
      const delta = clock.getElapsedTime();

      if (!isDragging) {
        graphGroup.rotation.y += 0.002;
        graphGroup.rotation.x = Math.sin(delta * 0.2) * 0.15;
      }

      renderer.render(scene, camera);
    };
    animate();

    window.addEventListener('resize', () => {
      const w = container.clientWidth || 450;
      const h = container.clientHeight || 520;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const controller = new IntelController();
  controller.init();
});
