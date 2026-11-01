/**
 * NO ENTRY - Neon Grid Floor
 * Infinite perspective grid receding into the background fog.
 */

import * as THREE from 'three';

export function createGridFloor(size = 80, divisions = 40, yPos = -6) {
  const gridHelper = new THREE.GridHelper(size, divisions, 0xFF1F3D, 0x1A1F29);
  gridHelper.position.y = yPos;

  // Make materials glow slightly
  if (Array.isArray(gridHelper.material)) {
    gridHelper.material.forEach(m => {
      m.transparent = true;
      m.opacity = 0.55;
    });
  } else {
    gridHelper.material.transparent = true;
    gridHelper.material.opacity = 0.55;
  }

  function update(delta, time) {
    // Subtle pulsating grid brightness
    const pulse = 0.45 + Math.sin(time * 1.5) * 0.1;
    if (Array.isArray(gridHelper.material)) {
      gridHelper.material[0].opacity = pulse;
    }
  }

  return { object: gridHelper, update };
}
