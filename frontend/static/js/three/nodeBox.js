/**
 * NO ENTRY - Glowing Tactical Node Box
 * Wireframe server node with billboard text label that dynamically tracks camera orientation.
 */

import * as THREE from 'three';

function createTextSprite(text, color = '#00E5FF') {
  const canvas = document.createElement('canvas');
  canvas.width = 256;
  canvas.height = 64;
  const ctx = canvas.getContext('2d');

  ctx.fillStyle = 'rgba(8, 11, 16, 0.75)';
  ctx.fillRect(0, 0, 256, 64);
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.strokeRect(1, 1, 254, 62);

  ctx.font = 'bold 22px "JetBrains Mono", monospace';
  ctx.fillStyle = '#FFFFFF';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, 128, 32);

  const texture = new THREE.CanvasTexture(canvas);
  texture.minFilter = THREE.LinearFilter;

  const spriteMat = new THREE.SpriteMaterial({
    map: texture,
    transparent: true,
    depthTest: false
  });
  const sprite = new THREE.Sprite(spriteMat);
  sprite.scale.set(2.4, 0.6, 1);
  return sprite;
}

export function createNodeBox(label, position, options = {}) {
  const color = options.color || 0x00E5FF;
  const size = options.size || 0.7;

  const group = new THREE.Group();
  group.position.copy(position);

  // 1. Wireframe Box
  const boxGeo = new THREE.BoxGeometry(size, size, size);
  const edges = new THREE.EdgesGeometry(boxGeo);
  const lineMat = new THREE.LineBasicMaterial({
    color: color,
    transparent: true,
    opacity: 0.85
  });
  const wireBox = new THREE.LineSegments(edges, lineMat);
  group.add(wireBox);

  // 2. Solid Inner Core
  const coreMat = new THREE.MeshBasicMaterial({
    color: 0x04060A,
    transparent: true,
    opacity: 0.75
  });
  const coreBox = new THREE.Mesh(boxGeo, coreMat);
  coreBox.scale.setScalar(0.96);
  group.add(coreBox);

  // 3. Billboard Text Label
  const hexStr = '#' + new THREE.Color(color).getHexString();
  const labelSprite = createTextSprite(label, hexStr);
  labelSprite.position.set(0, size * 0.9 + 0.3, 0);
  group.add(labelSprite);

  function setStatusColor(newColor) {
    lineMat.color.set(newColor);
  }

  function update(delta, time) {
    // Subtle node floating / breathing
    wireBox.rotation.y += delta * 0.4;
    wireBox.rotation.x += delta * 0.2;
  }

  return { object: group, update, setStatusColor };
}
