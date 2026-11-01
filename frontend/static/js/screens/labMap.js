/**
 * NO ENTRY - 3D Lab Map Screen Controller
 * Screen 5: The Hero 3D cyber range network topology:
 * 1. 9 Glowing wireframe hosts across 5 translucent floating zone platforms
 * 2. Animated cyan data packets travelling constantly along network links
 * 3. Dynamic red attack path lighting (Kali -> pfSense -> Switch -> Target) during attacks
 * 4. Shockwave rings and compromised pulse on victim nodes
 * 5. Reflex isolation cutting links with spark particle burst and grey-green dimming
 * 6. Smooth orbit camera with damping & GSAP fly-to on node click
 * 7. Real-time host inspector panel with POST /api/hosts/{id}/isolate
 * 8. RUN ATTACK trigger calling POST /api/scenarios/web-breach/start
 */

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import gsap from 'gsap';

import { initAppShell } from '../core/appShell.js';
import { wsClient } from '../core/ws.js';
import { api } from '../core/api.js';
import { store } from '../core/store.js';
import { sound } from '../core/sound.js';
import { CyberScene } from '../three/scene.js';

// Topology 3D layout coordinates
const NODE_CONFIGS = [
  // Attacker Zone
  { id: 'kali', name: 'Kali + C2', zone: 'attacker', pos: [-11, 2.0, -5], color: 0xFF1F3D },

  // Perimeter Zone
  { id: 'pfsense', name: 'pfSense', zone: 'perimeter', pos: [-5.5, 0.5, -2], color: 0x00E5FF },

  // Core Switch
  { id: 'switch', name: 'Switch 10.0.0.0/24', zone: 'core', pos: [0, 0, 0], color: 0x00E5FF },

  // DMZ Zone
  { id: 'web01', name: 'web01', zone: 'dmz', pos: [4.5, 2.2, -6], color: 0x00E5FF },
  { id: 'mail01', name: 'mail01', zone: 'dmz', pos: [8.5, 2.2, -6], color: 0x00E5FF },

  // Corp LAN Zone
  { id: 'ad01', name: 'AD server', zone: 'lan', pos: [4.5, -1.8, 5], color: 0x00E5FF },
  { id: 'ws-01', name: 'Workstations x2', zone: 'lan', pos: [8.5, -1.8, 3.5], color: 0x00E5FF },
  { id: 'ws-02', name: 'Workstation 02', zone: 'lan', pos: [8.5, -1.8, 6.5], color: 0x00E5FF },

  // Security Zone
  { id: 'siem', name: 'Wazuh + Suricata + MISP', zone: 'security', pos: [0, 4.2, 3], color: 0x00FF6A }
];

const ZONE_PLATFORMS = [
  { name: 'ATTACKER ZONE (EXTERNAL)', center: [-11, 1.2, -5], w: 5.5, d: 4.5, color: 0xFF1F3D },
  { name: 'PERIMETER (WAN / FIREWALL)', center: [-5.5, -0.3, -2], w: 4.5, d: 3.5, color: 0x00E5FF },
  { name: 'DMZ (PUBLIC SERVICES)', center: [6.5, 1.4, -6], w: 8.5, d: 4.5, color: 0x00E5FF },
  { name: 'CORP LAN (10.0.2.0/24)', center: [6.5, -2.6, 5], w: 8.5, d: 6.5, color: 0x00E5FF },
  { name: 'SECURITY OPERATIONS (10.0.3.0/24)', center: [0, 3.4, 3], w: 6.5, d: 4.0, color: 0x00FF6A }
];

const LINKS_CONFIG = [
  { from: 'kali', to: 'pfsense' },
  { from: 'pfsense', to: 'switch' },
  { from: 'switch', to: 'web01' },
  { from: 'switch', to: 'mail01' },
  { from: 'switch', to: 'ad01' },
  { from: 'switch', to: 'ws-01' },
  { from: 'switch', to: 'ws-02' },
  { from: 'switch', to: 'siem' }
];

function createBillboardSprite(text, colorHex = '#00E5FF') {
  const canvas = document.createElement('canvas');
  canvas.width = 320;
  canvas.height = 70;
  const ctx = canvas.getContext('2d');

  ctx.fillStyle = 'rgba(8, 11, 16, 0.85)';
  ctx.fillRect(0, 0, 320, 70);
  ctx.strokeStyle = colorHex;
  ctx.lineWidth = 2;
  ctx.strokeRect(1, 1, 318, 68);

  ctx.font = 'bold 22px "JetBrains Mono", monospace';
  ctx.fillStyle = '#FFFFFF';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, 160, 35);

  const texture = new THREE.CanvasTexture(canvas);
  texture.minFilter = THREE.LinearFilter;

  const mat = new THREE.SpriteMaterial({
    map: texture,
    transparent: true,
    depthTest: false
  });
  const sprite = new THREE.Sprite(mat);
  sprite.scale.set(3.2, 0.7, 1);
  return sprite;
}

class LabMapController {
  constructor() {
    this.nodes = new Map();
    this.links = [];
    this.sparkEmitters = [];
    this.activeAttackTargets = new Set();
    this.selectedHostId = 'web01';
    this.activeScenarioRunning = false;
  }

  async init() {
    // 1. Initialize shared App Shell
    initAppShell('lab_map');

    // 2. Setup 3D Scene & OrbitControls
    this.init3DScene();

    // 3. Build Topology: Platforms, Nodes, Links & Data Packets
    this.buildTopology();

    // 4. Setup User Interactions (Click selection, buttons)
    this.setupInteractions();

    // 5. Setup WebSocket listener for real-time host changes & attack arcs
    this.bindWebSocket();

    // 6. Fetch initial host states from REST API
    await this.loadInitialHosts();
  }

  init3DScene() {
    const container = document.getElementById('lab3DCanvasContainer');
    if (!container) return;

    // Use CyberScene controller (Bloom, DPR capped, Film)
    this.cyberScene = new CyberScene(container);
    this.camera = this.cyberScene.camera;
    this.camera.position.set(0, 14, 26);
    this.camera.lookAt(0, 0, 0);

    // Setup OrbitControls with smooth damping
    this.controls = new OrbitControls(this.camera, this.cyberScene.renderer.domElement);
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.05;
    this.controls.maxDistance = 55;
    this.controls.minDistance = 5;
    this.controls.maxPolarAngle = Math.PI / 2 + 0.1;

    this.cyberScene.addUpdatable(() => {
      this.controls.update();
    });

    this.cyberScene.start();
  }

  buildTopology() {
    // 1. Floating Zone Platforms
    ZONE_PLATFORMS.forEach(p => {
      const group = new THREE.Group();
      group.position.set(...p.center);

      // Translucent platform surface
      const geo = new THREE.BoxGeometry(p.w, 0.15, p.d);
      const mat = new THREE.MeshBasicMaterial({
        color: 0x080B10,
        transparent: true,
        opacity: 0.75
      });
      const mesh = new THREE.Mesh(geo, mat);
      group.add(mesh);

      // Glowing Wireframe Outline
      const edges = new THREE.EdgesGeometry(geo);
      const edgeMat = new THREE.LineBasicMaterial({
        color: p.color,
        transparent: true,
        opacity: 0.55
      });
      const wire = new THREE.LineSegments(edges, edgeMat);
      group.add(wire);

      // Floating Zone Label Billboard
      const hexStr = '#' + new THREE.Color(p.color).getHexString();
      const label = createBillboardSprite(p.name, hexStr);
      label.position.set(0, 0.6, p.d / 2);
      label.scale.set(4.0, 0.8, 1);
      group.add(label);

      this.cyberScene.scene.add(group);
    });

    // 2. Topology Nodes
    NODE_CONFIGS.forEach(cfg => {
      const group = new THREE.Group();
      group.position.set(...cfg.pos);

      // Wireframe Box
      const boxSize = cfg.id === 'switch' ? 1.0 : cfg.id === 'kali' ? 1.1 : 0.9;
      const boxGeo = new THREE.BoxGeometry(boxSize, boxSize, boxSize);
      const edges = new THREE.EdgesGeometry(boxGeo);
      const wireMat = new THREE.LineBasicMaterial({
        color: cfg.color,
        transparent: true,
        opacity: 0.9
      });
      const wireMesh = new THREE.LineSegments(edges, wireMat);
      group.add(wireMesh);

      // Dark Inner Core (captures raycast hits)
      const coreMat = new THREE.MeshBasicMaterial({
        color: 0x04060A,
        transparent: true,
        opacity: 0.85
      });
      const coreMesh = new THREE.Mesh(boxGeo, coreMat);
      coreMesh.userData = { hostId: cfg.id };
      group.add(coreMesh);

      // Billboard Text Label
      const hex = '#' + new THREE.Color(cfg.color).getHexString();
      const label = createBillboardSprite(cfg.name, hex);
      label.position.set(0, boxSize * 0.8 + 0.35, 0);
      group.add(label);

      // Shockwave Pulse Ring (for compromised/attack state)
      const ringGeo = new THREE.RingGeometry(0.6, 0.9, 32);
      const ringMat = new THREE.MeshBasicMaterial({
        color: 0xFF1F3D,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.0,
        blending: THREE.AdditiveBlending
      });
      const ringMesh = new THREE.Mesh(ringGeo, ringMat);
      ringMesh.rotation.x = Math.PI / 2;
      group.add(ringMesh);

      this.cyberScene.scene.add(group);

      this.nodes.set(cfg.id, {
        id: cfg.id,
        name: cfg.name,
        group: group,
        wireMesh: wireMesh,
        wireMat: wireMat,
        coreMesh: coreMesh,
        ringMesh: ringMesh,
        ringMat: ringMat,
        label: label,
        color: cfg.color,
        pos: new THREE.Vector3(...cfg.pos),
        status: 'healthy',
        isCompromised: false,
        isIsolated: false
      });
    });

    // 3. Network Links and Animated Traveling Packets
    LINKS_CONFIG.forEach(cfg => {
      const fromNode = this.nodes.get(cfg.from);
      const toNode = this.nodes.get(cfg.to);
      if (!fromNode || !toNode) return;

      const p1 = fromNode.pos;
      const p2 = toNode.pos;

      // Link Line
      const points = [p1, p2];
      const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
      const lineMat = new THREE.LineBasicMaterial({
        color: 0x00E5FF,
        transparent: true,
        opacity: 0.3,
        blending: THREE.AdditiveBlending
      });
      const line = new THREE.Line(lineGeo, lineMat);
      this.cyberScene.scene.add(line);

      // Continuous animated data packets along this link
      const packetCount = 2;
      const packets = [];

      for (let i = 0; i < packetCount; i++) {
        const pGeo = new THREE.SphereGeometry(0.08, 12, 12);
        const pMat = new THREE.MeshBasicMaterial({
          color: 0x00E5FF,
          blending: THREE.AdditiveBlending
        });
        const packetMesh = new THREE.Mesh(pGeo, pMat);
        this.cyberScene.scene.add(packetMesh);

        packets.push({
          mesh: packetMesh,
          mat: pMat,
          progress: i / packetCount,
          speed: 0.45
        });
      }

      this.links.push({
        from: cfg.from,
        to: cfg.to,
        line: line,
        lineMat: lineMat,
        packets: packets,
        p1: p1,
        p2: p2,
        isAttackPath: false,
        isSevered: false
      });
    });

    // Animation Loop for nodes, packets, rings, and sparks
    this.cyberScene.addUpdatable((delta, time) => {
      // 1. Rotate nodes gently & pulse compromised targets
      this.nodes.forEach(node => {
        node.wireMesh.rotation.y += delta * 0.3;
        node.wireMesh.rotation.x += delta * 0.15;

        if (node.isCompromised) {
          // Pulse shockwave ring
          const ringPhase = (time * 2.5) % 1.0;
          node.ringMesh.scale.setScalar(1.0 + ringPhase * 2.2);
          node.ringMat.opacity = Math.max(0, 0.9 - ringPhase);
        } else {
          node.ringMat.opacity = 0.0;
        }
      });

      // 2. Animate packets along links
      this.links.forEach(link => {
        if (link.isSevered) {
          link.packets.forEach(p => p.mesh.visible = false);
          return;
        }

        link.packets.forEach(p => {
          p.mesh.visible = true;
          p.progress += delta * p.speed;
          if (p.progress > 1.0) p.progress -= 1.0;

          // Interpolate position along link line
          p.mesh.position.lerpVectors(link.p1, link.p2, p.progress);
        });
      });

      // 3. Update spark particle bursts
      for (let i = this.sparkEmitters.length - 1; i >= 0; i--) {
        const emitter = this.sparkEmitters[i];
        emitter.update(delta);
        if (emitter.isDead) {
          this.cyberScene.scene.remove(emitter.points);
          this.sparkEmitters.splice(i, 1);
        }
      }
    });
  }

  setupInteractions() {
    const container = document.getElementById('lab3DCanvasContainer');
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    // Node click selection
    container.addEventListener('click', (e) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

      raycaster.setFromCamera(mouse, this.camera);
      const meshes = Array.from(this.nodes.values()).map(n => n.coreMesh);
      const intersects = raycaster.intersectObjects(meshes, false);

      if (intersects.length > 0) {
        const hit = intersects[0].object;
        if (hit.userData && hit.userData.hostId) {
          this.selectHost(hit.userData.hostId);
        }
      }
    });

    // Reset Camera button
    const resetCamBtn = document.getElementById('resetCameraBtn');
    if (resetCamBtn) {
      resetCamBtn.addEventListener('click', () => {
        sound.keyClick();
        gsap.to(this.camera.position, { x: 0, y: 14, z: 26, duration: 1.2, ease: 'power2.inOut' });
        gsap.to(this.controls.target, { x: 0, y: 0, z: 0, duration: 1.2, ease: 'power2.inOut' });
      });
    }

    // RUN ATTACK button
    const runAttackBtn = document.getElementById('runAttackBtn');
    if (runAttackBtn) {
      runAttackBtn.addEventListener('click', () => this.runAttackScenario());
    }

    // ISOLATE HOST button
    const isolateBtn = document.getElementById('isolateHostBtn');
    if (isolateBtn) {
      isolateBtn.addEventListener('click', () => this.isolateSelectedHost());
    }
  }

  selectHost(hostId) {
    const node = this.nodes.get(hostId);
    if (!node) return;

    this.selectedHostId = hostId;
    sound.panelOpen();

    // Smoothly fly camera to face the selected node
    const targetPos = node.pos.clone();
    const camOffset = new THREE.Vector3(node.pos.x + 3.5, node.pos.y + 2.5, node.pos.z + 5.5);

    gsap.to(this.camera.position, {
      x: camOffset.x,
      y: camOffset.y,
      z: camOffset.z,
      duration: 1.2,
      ease: 'power2.out'
    });

    gsap.to(this.controls.target, {
      x: targetPos.x,
      y: targetPos.y,
      z: targetPos.z,
      duration: 1.2,
      ease: 'power2.out'
    });

    // Fill the inspector panel with host details
    this.updateInspector(node.data || { id: hostId, name: node.name, status: node.status });
  }

  updateInspector(host) {
    if (!host) return;

    document.getElementById('inspNodeName').innerText = `${host.name || host.id} (${host.id})`;
    document.getElementById('inspNodeIp').innerText = host.ip || '10.0.X.X';
    document.getElementById('inspNodeRole').innerText = host.role || 'Range Host';
    document.getElementById('inspNodeOs').innerText = host.os || 'Linux';
    document.getElementById('inspNodeAgent').innerText = host.agent || 'Telemetry Active';

    const statusBadge = document.getElementById('inspNodeStatus');
    const status = (host.status || 'healthy').toLowerCase();
    statusBadge.innerText = status.toUpperCase();
    statusBadge.className = 'host-status-badge';

    if (status === 'compromised') {
      statusBadge.classList.add('host-status-compromised');
    } else if (status === 'suspicious') {
      statusBadge.classList.add('host-status-suspicious');
    } else if (status === 'isolated') {
      statusBadge.classList.add('host-status-isolated');
    } else {
      statusBadge.classList.add('host-status-healthy');
    }

    const alertEl = document.getElementById('inspNodeAlert');
    if (host.last_alert) {
      alertEl.innerText = host.last_alert;
      alertEl.style.color = 'var(--color-red)';
    } else {
      alertEl.innerText = 'No active alerts on this node.';
      alertEl.style.color = 'var(--color-text-dim)';
    }

    const isolateBtn = document.getElementById('isolateHostBtn');
    if (isolateBtn) {
      if (status === 'isolated') {
        isolateBtn.innerText = 'HOST ISOLATED (QUARANTINED)';
        isolateBtn.disabled = true;
        isolateBtn.style.opacity = '0.5';
      } else {
        isolateBtn.innerText = 'ISOLATE HOST (QUARANTINE)';
        isolateBtn.disabled = false;
        isolateBtn.style.opacity = '1.0';
      }
    }
  }

  async loadInitialHosts() {
    try {
      const data = await api.get('/hosts');
      if (data) {
        Object.values(data).forEach(host => {
          this.applyHostUpdate(host);
        });
      }

      // Default selection to web01
      if (this.nodes.has(this.selectedHostId)) {
        const node = this.nodes.get(this.selectedHostId);
        this.updateInspector(node.data || { id: this.selectedHostId, name: node.name });
      }
    } catch (err) {
      console.warn('Initial hosts load warning:', err.message);
    }
  }

  bindWebSocket() {
    wsClient.on('message', (msg) => {
      if (!msg) return;

      if (msg.type === 'snapshot') {
        if (msg.data && msg.data.hosts) {
          Object.values(msg.data.hosts).forEach(host => {
            this.applyHostUpdate(host);
          });
        }
      } else if (msg.type === 'host') {
        this.applyHostUpdate(msg.data);
      } else if (msg.type === 'event') {
        this.handleSimEvent(msg.data);
      } else if (msg.type === 'scenario_step') {
        this.handleScenarioStep(msg.data);
      }
    });
  }

  applyHostUpdate(host) {
    if (!host || !this.nodes.has(host.id)) return;
    const node = this.nodes.get(host.id);
    node.data = host;
    node.status = host.status;

    // Apply 3D visual changes
    if (host.status === 'compromised') {
      node.isCompromised = true;
      node.wireMat.color.set(0xFF1F3D);
    } else if (host.status === 'isolated') {
      node.isCompromised = false;
      node.isIsolated = true;
      node.wireMat.color.set(0x78909c); // grey-green
      this.severLinksForHost(host.id);
      this.spawnSparkBurst(node.pos);
    } else if (host.status === 'suspicious') {
      node.isCompromised = false;
      node.wireMat.color.set(0xFFB800);
    } else {
      node.isCompromised = false;
      node.wireMat.color.set(node.color);
    }

    if (this.selectedHostId === host.id) {
      this.updateInspector(host);
    }
  }

  handleSimEvent(evt) {
    if (!evt) return;

    if (evt.target_host && this.nodes.has(evt.target_host)) {
      // Light up the attack path to target
      this.lightAttackPath(evt.target_host);

      if (evt.breach || evt.severity === 'CRITICAL') {
        const node = this.nodes.get(evt.target_host);
        node.isCompromised = true;
        node.wireMat.color.set(0xFF1F3D);
      }
    }
  }

  lightAttackPath(targetId) {
    // Attack travels from Kali -> pfSense -> Switch -> Target
    const pathLinks = [
      { from: 'kali', to: 'pfsense' },
      { from: 'pfsense', to: 'switch' },
      { from: 'switch', to: targetId }
    ];

    pathLinks.forEach(p => {
      const link = this.links.find(l =>
        (l.from === p.from && l.to === p.to) || (l.from === p.to && l.to === p.from)
      );

      if (link && !link.isSevered) {
        link.isAttackPath = true;
        link.lineMat.color.set(0xFF1F3D);
        link.lineMat.opacity = 0.85;

        link.packets.forEach(pkt => {
          pkt.mat.color.set(0xFF1F3D);
          pkt.speed = 1.2; // faster attack stream
        });

        // Reset to normal after 3 seconds
        setTimeout(() => {
          if (!link.isSevered) {
            link.lineMat.color.set(0x00E5FF);
            link.lineMat.opacity = 0.3;
            link.packets.forEach(pkt => {
              pkt.mat.color.set(0x00E5FF);
              pkt.speed = 0.45;
            });
          }
        }, 3200);
      }
    });
  }

  severLinksForHost(hostId) {
    this.links.forEach(link => {
      if (link.from === hostId || link.to === hostId) {
        link.isSevered = true;
        link.lineMat.color.set(0x334455);
        link.lineMat.opacity = 0.12;
      }
    });
  }

  spawnSparkBurst(pos) {
    const count = 45;
    const geo = new THREE.BufferGeometry();
    const positions = new Float32Array(count * 3);
    const velocities = [];

    for (let i = 0; i < count; i++) {
      positions[i * 3] = pos.x;
      positions[i * 3 + 1] = pos.y;
      positions[i * 3 + 2] = pos.z;

      velocities.push(new THREE.Vector3(
        (Math.random() - 0.5) * 4,
        Math.random() * 4 + 1,
        (Math.random() - 0.5) * 4
      ));
    }

    geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const mat = new THREE.PointsMaterial({
      color: 0xFFAA00,
      size: 0.14,
      transparent: true,
      opacity: 1.0,
      blending: THREE.AdditiveBlending
    });

    const points = new THREE.Points(geo, mat);
    this.cyberScene.scene.add(points);

    let life = 1.0;
    const emitter = {
      points,
      isDead: false,
      update: (delta) => {
        life -= delta;
        if (life <= 0) {
          emitter.isDead = true;
          return;
        }

        mat.opacity = life;
        const posAttr = geo.attributes.position;
        for (let i = 0; i < count; i++) {
          velocities[i].y -= delta * 6.0; // gravity
          posAttr.array[i * 3] += velocities[i].x * delta;
          posAttr.array[i * 3 + 1] += velocities[i].y * delta;
          posAttr.array[i * 3 + 2] += velocities[i].z * delta;
        }
        posAttr.needsUpdate = true;
      }
    };

    this.sparkEmitters.push(emitter);
  }

  async runAttackScenario() {
    const banner = document.getElementById('scenarioBanner');
    const runBtn = document.getElementById('runAttackBtn');

    if (runBtn) {
      runBtn.disabled = true;
      runBtn.innerText = 'RUNNING ATTACK...';
    }

    if (banner) {
      banner.classList.add('active');
    }

    sound.threatAlert();

    try {
      await api.post('/scenarios/web-breach/start');
      this.lightAttackPath('web01');

      setTimeout(() => {
        if (banner) banner.classList.remove('active');
        if (runBtn) {
          runBtn.disabled = false;
          runBtn.innerText = 'RUN ATTACK (WEB-BREACH)';
        }
      }, 8000);
    } catch (err) {
      console.error('Failed to run attack scenario:', err);
      if (runBtn) {
        runBtn.disabled = false;
        runBtn.innerText = 'RUN ATTACK (WEB-BREACH)';
      }
    }
  }

  async isolateSelectedHost() {
    const hostId = this.selectedHostId;
    if (!hostId) return;

    sound.threatAlert();

    try {
      await api.post(`/hosts/${hostId}/isolate`);
      const node = this.nodes.get(hostId);
      if (node) {
        this.applyHostUpdate({
          id: hostId,
          name: node.name,
          status: 'isolated',
          role: node.data?.role || 'Quarantined Host',
          os: node.data?.os || 'Linux',
          agent: 'SOAR Policy Enforced',
          last_alert: 'Reflex host isolation applied.',
          ip: node.data?.ip || '0.0.0.0'
        });
      }
    } catch (err) {
      console.error('Failed to isolate host:', err);
    }
  }
}

// Instantiate on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  const lab = new LabMapController();
  lab.init();
});
