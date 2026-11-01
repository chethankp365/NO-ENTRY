/**
 * NO ENTRY - Tactical 3D Scene Controller
 * WebGL renderer with DPR cap 1.5, Post-Processing (Bloom, RGB Shift, Film),
 * auto-pauses when tab is hidden or in performance mode.
 */

import * as THREE from 'three';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { ShaderPass } from 'three/addons/postprocessing/ShaderPass.js';
import { RGBShiftShader } from 'three/addons/shaders/RGBShiftShader.js';
import { FilmShader } from 'three/addons/shaders/FilmShader.js';

import { store } from '../core/store.js';

export class CyberScene {
  constructor(canvasContainer) {
    this.container = canvasContainer;
    this.width = canvasContainer.clientWidth || window.innerWidth;
    this.height = canvasContainer.clientHeight || window.innerHeight;

    this.scene = new THREE.Scene();
    this.scene.fog = new THREE.FogExp2(0x04060A, 0.025);

    // Camera
    this.camera = new THREE.PerspectiveCamera(45, this.width / this.height, 0.1, 1000);
    this.camera.position.set(0, 5, 25);
    this.camera.lookAt(0, 0, 0);

    // WebGL Renderer with capped DPR
    this.renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance'
    });
    this.renderer.setSize(this.width, this.height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
    this.renderer.setClearColor(0x04060A, 0.0); // Transparent so matrix rain shows through
    this.container.appendChild(this.renderer.domElement);

    // Post-processing EffectComposer
    this.initPostProcessing();

    this.updatables = [];
    this.clock = new THREE.Clock();
    this.isRunning = false;
    this.animId = null;

    // Window Resize Handling
    window.addEventListener('resize', () => this.onResize());

    // Auto-pause when tab is hidden
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.stop();
      } else if (!store.get('performanceMode')) {
        this.start();
      }
    });

    // Store subscribers for Threat Level and Perf Mode
    store.subscribe('threatLevel', (level) => {
      this.updateThreatFx(level);
    });

    store.subscribe('performanceMode', (perf) => {
      if (perf) {
        this.renderer.setPixelRatio(1.0);
        this.bloomPass.strength = 0.3;
      } else {
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
        this.bloomPass.strength = 0.8;
      }
    });
  }

  initPostProcessing() {
    this.composer = new EffectComposer(this.renderer);

    // 1. Render Pass
    const renderPass = new RenderPass(this.scene, this.camera);
    this.composer.addPass(renderPass);

    // 2. Unreal Bloom Pass
    this.bloomPass = new UnrealBloomPass(
      new THREE.Vector2(this.width, this.height),
      0.85,  // strength
      0.4,   // radius
      0.75   // threshold
    );
    this.composer.addPass(this.bloomPass);

    // 3. RGB Shift / Chromatic Aberration
    this.rgbShiftPass = new ShaderPass(RGBShiftShader);
    this.rgbShiftPass.uniforms['amount'].value = 0.0014;
    this.composer.addPass(this.rgbShiftPass);

    // 4. Subtle Film Noise Pass
    this.filmPass = new ShaderPass(FilmShader);
    this.filmPass.uniforms['intensity'].value = 0.25;
    this.filmPass.uniforms['grayscale'].value = 0;
    this.composer.addPass(this.filmPass);
  }

  updateThreatFx(threatLevel) {
    if (!this.rgbShiftPass || !this.bloomPass) return;
    if (threatLevel === 'CRITICAL') {
      this.rgbShiftPass.uniforms['amount'].value = 0.0045;
      this.bloomPass.strength = 1.3;
    } else if (threatLevel === 'ELEVATED') {
      this.rgbShiftPass.uniforms['amount'].value = 0.002;
      this.bloomPass.strength = 0.85;
    } else {
      this.rgbShiftPass.uniforms['amount'].value = 0.001;
      this.bloomPass.strength = 0.6;
    }
  }

  onResize() {
    this.width = this.container.clientWidth || window.innerWidth;
    this.height = this.container.clientHeight || window.innerHeight;

    this.camera.aspect = this.width / this.height;
    this.camera.updateProjectionMatrix();

    this.renderer.setSize(this.width, this.height);
    this.composer.setSize(this.width, this.height);
  }

  addUpdatable(fn) {
    this.updatables.push(fn);
  }

  start() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.clock.start();
    this.loop();
  }

  stop() {
    this.isRunning = false;
    this.clock.stop();
    if (this.animId) {
      cancelAnimationFrame(this.animId);
      this.animId = null;
    }
  }

  loop() {
    if (!this.isRunning) return;
    this.animId = requestAnimationFrame(() => this.loop());

    const delta = this.clock.getDelta();
    const time = this.clock.getElapsedTime();

    // Update all registered updatables
    for (let i = 0; i < this.updatables.length; i++) {
      this.updatables[i](delta, time);
    }

    // Render post-processed scene
    this.composer.render();
  }
}
