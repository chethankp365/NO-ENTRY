/**
 * NO ENTRY - Tactical Data Packet
 * Glowing cyber packet traveling along a 3D path with subtle light emission.
 */

import * as THREE from 'three';

export function createDataPacket(curve, options = {}) {
  const color = options.color || 0x00E5FF;
  const speed = options.speed || 1.2;
  const size = options.size || 0.15;

  const group = new THREE.Group();

  // Core packet
  const packetGeo = new THREE.SphereGeometry(size, 16, 16);
  const packetMat = new THREE.MeshBasicMaterial({
    color: color,
    blending: THREE.AdditiveBlending
  });
  const packetMesh = new THREE.Mesh(packetGeo, packetMat);
  group.add(packetMesh);

  // Outer glow aura
  const auraGeo = new THREE.SphereGeometry(size * 1.8, 12, 12);
  const auraMat = new THREE.MeshBasicMaterial({
    color: color,
    transparent: true,
    opacity: 0.35,
    blending: THREE.AdditiveBlending
  });
  const auraMesh = new THREE.Mesh(auraGeo, auraMat);
  group.add(auraMesh);

  let progress = Math.random(); // Start at random offset

  function update(delta) {
    progress += delta * speed * 0.25;
    if (progress > 1.0) progress -= 1.0;

    const pt = curve.getPoint(progress);
    group.position.copy(pt);
  }

  return { object: group, update };
}
