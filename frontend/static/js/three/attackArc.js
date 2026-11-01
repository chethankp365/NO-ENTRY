/**
 * NO ENTRY - Tactical Attack Arc
 * Red ballistic 3D bezier arc connecting source and target nodes with traveling pulse and target impact ripple.
 */

import * as THREE from 'three';

export function createAttackArc(startVec, endVec, options = {}) {
  const group = new THREE.Group();
  const color = options.color || 0xFF1F3D;
  const speed = options.speed || 0.8; // cycle speed

  // Calculate high arched midpoint
  const midVec = new THREE.Vector3().addVectors(startVec, endVec).multiplyScalar(0.5);
  const distance = startVec.distanceTo(endVec);
  const elevation = options.altitude || Math.max(1.5, distance * 0.45);
  // Extrude mid outward along normal
  midVec.normalize().multiplyScalar(startVec.length() + elevation);

  // Build quadratic bezier curve
  const curve = new THREE.QuadraticBezierCurve3(startVec, midVec, endVec);
  const pointCount = 64;
  const points = curve.getPoints(pointCount);

  // 1. Static Dim Arc Path
  const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
  const lineMat = new THREE.LineBasicMaterial({
    color: color,
    transparent: true,
    opacity: 0.25,
    blending: THREE.AdditiveBlending
  });
  const arcLine = new THREE.Line(lineGeo, lineMat);
  group.add(arcLine);

  // 2. Bright Glowing Pulse Head traveling along the arc
  const pulseGeo = new THREE.SphereGeometry(0.12, 12, 12);
  const pulseMat = new THREE.MeshBasicMaterial({
    color: color,
    blending: THREE.AdditiveBlending
  });
  const pulse = new THREE.Mesh(pulseGeo, pulseMat);
  group.add(pulse);

  // 3. Impact Ripple Circle at end point
  const rippleGeo = new THREE.RingGeometry(0.05, 0.12, 24);
  const rippleMat = new THREE.MeshBasicMaterial({
    color: color,
    side: THREE.DoubleSide,
    transparent: true,
    opacity: 0.0,
    blending: THREE.AdditiveBlending
  });
  const ripple = new THREE.Mesh(rippleGeo, rippleMat);
  ripple.position.copy(endVec);
  ripple.lookAt(new THREE.Vector3(0, 0, 0)); // align tangent to globe
  group.add(ripple);

  let progress = 0;

  function update(delta) {
    progress += delta * speed;

    if (progress <= 1.0) {
      // Traveling along curve
      const pt = curve.getPoint(progress);
      pulse.position.copy(pt);
      pulse.visible = true;
      ripple.material.opacity = 0.0;
    } else if (progress <= 1.4) {
      // Impact phase: expanding ripple
      pulse.visible = false;
      const ripplePhase = (progress - 1.0) / 0.4;
      ripple.scale.setScalar(1.0 + ripplePhase * 4.0);
      ripple.material.opacity = (1.0 - ripplePhase) * 0.8;
    } else {
      // Reset cycle
      progress = 0;
      ripple.scale.setScalar(1.0);
    }
  }

  return { object: group, update, curve };
}
