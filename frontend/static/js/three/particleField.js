/**
 * NO ENTRY - Instanced Particle Field
 * Atmospheric cyber dust floating across the 3D viewport.
 */

import * as THREE from 'three';

export function createParticleField(count = 600, range = 50) {
  const geometry = new THREE.BufferGeometry();
  const positions = new Float32Array(count * 3);
  const velocities = new Float32Array(count * 3);

  for (let i = 0; i < count; i++) {
    positions[i * 3] = (Math.random() - 0.5) * range;
    positions[i * 3 + 1] = (Math.random() - 0.5) * range * 0.7;
    positions[i * 3 + 2] = (Math.random() - 0.5) * range;

    velocities[i * 3] = (Math.random() - 0.5) * 0.02;
    velocities[i * 3 + 1] = (Math.random() - 0.5) * 0.02 + 0.01;
    velocities[i * 3 + 2] = (Math.random() - 0.5) * 0.02;
  }

  geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

  const material = new THREE.PointsMaterial({
    color: 0x00E5FF,
    size: 0.16,
    transparent: true,
    opacity: 0.6,
    blending: THREE.AdditiveBlending
  });

  const points = new THREE.Points(geometry, material);

  function update() {
    const pos = geometry.attributes.position.array;
    for (let i = 0; i < count; i++) {
      pos[i * 3] += velocities[i * 3];
      pos[i * 3 + 1] += velocities[i * 3 + 1];
      pos[i * 3 + 2] += velocities[i * 3 + 2];

      const halfRange = range / 2;
      if (pos[i * 3 + 1] > halfRange * 0.7) pos[i * 3 + 1] = -halfRange * 0.7;
      if (pos[i * 3] > halfRange) pos[i * 3] = -halfRange;
      if (pos[i * 3] < -halfRange) pos[i * 3] = halfRange;
    }
    geometry.attributes.position.needsUpdate = true;
  }

  return { object: points, update };
}
