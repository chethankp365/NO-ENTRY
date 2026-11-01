/**
 * NO ENTRY - Holographic Globe
 * Dotted 3D cyber Earth with dim cyan lat/long wireframe, slow rotation,
 * and coordinate mapping utilities.
 */

import * as THREE from 'three';

export function latLongToVector3(lat, lon, radius = 5.0) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  const x = -(radius * Math.sin(phi) * Math.cos(theta));
  const z = radius * Math.sin(phi) * Math.sin(theta);
  const y = radius * Math.cos(phi);
  return new THREE.Vector3(x, y, z);
}

export function createHoloGlobe(radius = 5.0, dotCount = 1800) {
  const globeGroup = new THREE.Group();

  // 1. Dotted Surface Points (Fibonacci Sphere algorithm)
  const dotGeometry = new THREE.BufferGeometry();
  const positions = new Float32Array(dotCount * 3);
  const phiSpan = Math.PI * (3 - Math.sqrt(5)); // Golden angle

  for (let i = 0; i < dotCount; i++) {
    const y = 1 - (i / (dotCount - 1)) * 2; // -1 to 1
    const r = Math.sqrt(1 - y * y);
    const theta = phiSpan * i;

    positions[i * 3] = Math.cos(theta) * r * radius;
    positions[i * 3 + 1] = y * radius;
    positions[i * 3 + 2] = Math.sin(theta) * r * radius;
  }

  dotGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

  const dotMaterial = new THREE.PointsMaterial({
    color: 0x00E5FF,
    size: 0.08,
    transparent: true,
    opacity: 0.65,
    blending: THREE.AdditiveBlending
  });

  const dots = new THREE.Points(dotGeometry, dotMaterial);
  globeGroup.add(dots);

  // 2. Dim Cyan Lat/Long Wireframe Rings
  const wireGeometry = new THREE.SphereGeometry(radius * 0.99, 16, 12);
  const wireMaterial = new THREE.MeshBasicMaterial({
    color: 0x00E5FF,
    wireframe: true,
    transparent: true,
    opacity: 0.12
  });
  const wireframeSphere = new THREE.Mesh(wireGeometry, wireMaterial);
  globeGroup.add(wireframeSphere);

  // 3. Inner Dark Occlusion Core (prevents seeing through back of globe completely)
  const coreGeometry = new THREE.SphereGeometry(radius * 0.95, 32, 32);
  const coreMaterial = new THREE.MeshBasicMaterial({
    color: 0x04060A,
    transparent: true,
    opacity: 0.85
  });
  const coreMesh = new THREE.Mesh(coreGeometry, coreMaterial);
  globeGroup.add(coreMesh);

  // 4. Subtle Outer Atmosphere Glow Ring
  const atmosGeometry = new THREE.RingGeometry(radius * 1.01, radius * 1.08, 64);
  const atmosMaterial = new THREE.MeshBasicMaterial({
    color: 0x00E5FF,
    side: THREE.DoubleSide,
    transparent: true,
    opacity: 0.25,
    blending: THREE.AdditiveBlending
  });
  const atmosRing = new THREE.Mesh(atmosGeometry, atmosMaterial);
  atmosRing.rotation.x = Math.PI / 2;
  globeGroup.add(atmosRing);

  function update(delta, time) {
    // Slow cinematic rotation
    globeGroup.rotation.y += delta * 0.12;
  }

  return { object: globeGroup, update, latLongToVector3 };
}
