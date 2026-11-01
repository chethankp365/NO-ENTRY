/**
 * NO ENTRY - <ne-logo> Web Component
 * Prohibition circle + keyhole emblem with animated pulse and glitch states.
 */

class NeLogo extends HTMLElement {
  static get observedAttributes() {
    return ['size', 'pulse', 'glitch'];
  }

  connectedCallback() {
    this.render();
  }

  attributeChangedCallback() {
    this.render();
  }

  render() {
    const size = this.getAttribute('size') || '64';
    const isPulse = this.hasAttribute('pulse');
    const isGlitch = this.hasAttribute('glitch');

    this.innerHTML = `
      <style>
        ne-logo {
          display: inline-block;
          vertical-align: middle;
          position: relative;
        }

        .ne-logo-svg {
          width: ${size}px;
          height: ${size}px;
          display: block;
          overflow: visible;
          filter: drop-shadow(0 0 10px rgba(255, 31, 61, 0.4));
        }

        .ne-logo-pulse {
          animation: nePulse 2.4s infinite ease-in-out;
        }

        @keyframes nePulse {
          0%, 100% {
            filter: drop-shadow(0 0 8px rgba(255, 31, 61, 0.4));
            transform: scale(1);
          }
          50% {
            filter: drop-shadow(0 0 22px rgba(255, 31, 61, 0.85));
            transform: scale(1.025);
          }
        }

        .ne-logo-glitch {
          animation: neGlitch 0.4s infinite steps(2);
        }

        @keyframes neGlitch {
          0% {
            transform: translate(0);
            filter: drop-shadow(-2px 0 #00e5ff) drop-shadow(2px 0 #ff1f3d);
          }
          50% {
            transform: translate(-2px, 1px);
            filter: drop-shadow(2px -1px #00e5ff) drop-shadow(-2px 1px #ff1f3d);
          }
          100% {
            transform: translate(0);
            filter: drop-shadow(0 0 10px rgba(255, 31, 61, 0.5));
          }
        }
      </style>

      <svg
        class="ne-logo-svg ${isPulse ? 'ne-logo-pulse' : ''} ${isGlitch ? 'ne-logo-glitch' : ''}"
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <!-- Outer Glowing Glow Ring -->
        <circle cx="50" cy="50" r="44" stroke="#FF1F3D" stroke-width="1.5" stroke-opacity="0.3" stroke-dasharray="3 3"/>

        <!-- Main Prohibition Circle Ring -->
        <circle cx="50" cy="50" r="40" stroke="#FF1F3D" stroke-width="10" />

        <!-- Diagonal Prohibition Slash -->
        <line x1="21.7" y1="21.7" x2="78.3" y2="78.3" stroke="#FF1F3D" stroke-width="10" stroke-linecap="round"/>

        <!-- Central Keyhole Badge Background -->
        <circle cx="50" cy="50" r="17" fill="#04060A" stroke="#FF1F3D" stroke-width="3" />

        <!-- Keyhole Shape (White) -->
        <!-- Upper circle of keyhole -->
        <circle cx="50" cy="46" r="4.8" fill="#FFFFFF" />
        <!-- Lower trapezoid of keyhole -->
        <polygon points="47,47 53,47 55,57 45,57" fill="#FFFFFF" />
      </svg>
    `;
  }
}

if (!customElements.get('ne-logo')) {
  customElements.define('ne-logo', NeLogo);
}

export { NeLogo };
