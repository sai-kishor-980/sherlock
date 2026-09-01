/* ==========================================================================
   Sherlock AI — 3D Glass Badge Floating & Perspective Tilt Motion Engine
   - 3-Layer Transform Separation (tilt-wrapper -> float-layer -> tilt-3d-img)
   - Perspective: 1000px
   - Idle Suspension: translateY(-4px) -> translateY(4px) over 5s (CSS animation only)
   - Cursor Tilt: rotateX/Y max ±4deg via requestAnimationFrame
   - Image Depth: translateZ(16px)
   - Zero Diagonal Clipping: Strict overflow: visible 3D hierarchy
   - Accessibility: Respects prefers-reduced-motion
   ========================================================================== */

class Sherlock3DMotionEngine {
  constructor() {
    this.maxTilt = 4; // Maximum tilt angle in degrees (±4°)
    this.perspective = 1000; // Perspective depth in pixels
    this.depthZ = 16; // Image 3D depth offset in pixels
    this.prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    this.init();
  }

  init() {
    if (this.prefersReducedMotion) return;

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => this.setup());
    } else {
      this.setup();
    }

    // Refresh hook for dynamic DOM updates
    window.HMACFR_Refresh3DEffects = () => this.setup();

    // Listen for reduced motion preference changes
    window.matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", (e) => {
      this.prefersReducedMotion = e.matches;
      if (e.matches) {
        this.disableAll();
      } else {
        this.setup();
      }
    });
  }

  setup() {
    if (this.prefersReducedMotion) return;

    // Target card and graphic tilt wrappers
    const selectors = [
      ".hero-right-visual",
      ".preservation-right-visual",
      ".custody-right-visual",
      ".signin-left-visual",
      ".preservation-card",
      ".agent-card",
      ".custody-step-card"
    ].join(", ");

    const elements = document.querySelectorAll(selectors);

    elements.forEach(wrapper => {
      if (wrapper.dataset.tiltEngineBound) return;
      wrapper.dataset.tiltEngineBound = "true";

      // Layer 1: Wrapper receives perspective & JS rotation
      wrapper.style.perspective = `${this.perspective}px`;
      wrapper.style.transformStyle = "preserve-3d";
      wrapper.style.overflow = "visible";

      // Layer 2: float-layer receives pure CSS idle floating suspension animation ONLY
      let floatLayer = wrapper.querySelector(".float-layer, .hero-landing-image-container, .preservation-p1i1-container, .custody-chain-container, .signin-img-container, .card-visual-illustration");
      if (!floatLayer) return;

      floatLayer.classList.add("idle-floating-3d");
      floatLayer.style.transformStyle = "preserve-3d";
      floatLayer.style.overflow = "visible";

      // Layer 3: Inner 3D image receives translateZ depth offset ONLY
      const img = floatLayer.querySelector("img");
      if (img) {
        img.classList.add("tilt-3d-img");
        img.style.transformStyle = "preserve-3d";
        img.style.transform = `translateZ(${this.depthZ}px)`;
        img.style.overflow = "visible";
      }

      // State for requestAnimationFrame smoothing
      const state = {
        wrapper: wrapper,
        targetX: 0,
        targetY: 0,
        currentX: 0,
        currentY: 0,
        animating: false,
        hovered: false
      };

      // Mouse Events
      wrapper.addEventListener("mouseenter", () => {
        if (this.prefersReducedMotion) return;
        state.hovered = true;
        if (!state.animating) {
          state.animating = true;
          this.updateLoop(state);
        }
      });

      wrapper.addEventListener("mousemove", (e) => {
        if (this.prefersReducedMotion || !state.hovered) return;

        const rect = wrapper.getBoundingClientRect();
        const width = rect.width;
        const height = rect.height;

        // Normalized positions (-1 to +1) relative to wrapper center
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;
        const normX = (mouseX - width / 2) / (width / 2);
        const normY = (mouseY - height / 2) / (height / 2);

        // Calculate target angles (±4° max)
        state.targetX = -normY * this.maxTilt;
        state.targetY = normX * this.maxTilt;
      });

      wrapper.addEventListener("mouseleave", () => {
        state.hovered = false;
        state.targetX = 0;
        state.targetY = 0;
      });
    });
  }

  updateLoop(state) {
    if (this.prefersReducedMotion) {
      state.wrapper.style.transform = "none";
      state.animating = false;
      return;
    }

    // Smooth interpolation (lerp factor 0.1 for restrained, premium feel)
    state.currentX += (state.targetX - state.currentX) * 0.1;
    state.currentY += (state.targetY - state.currentY) * 0.1;

    // Apply 3D cursor tilt transform ONLY to Layer 1 wrapper (never on float-layer)
    state.wrapper.style.transform = `perspective(${this.perspective}px) rotateX(${state.currentX.toFixed(2)}deg) rotateY(${state.currentY.toFixed(2)}deg)`;

    // Continue loop if hovered or if returning to rest (threshold 0.01deg)
    const deltaX = Math.abs(state.targetX - state.currentX);
    const deltaY = Math.abs(state.targetY - state.currentY);

    if (state.hovered || deltaX > 0.01 || deltaY > 0.01) {
      requestAnimationFrame(() => this.updateLoop(state));
    } else {
      state.wrapper.style.transform = `perspective(${this.perspective}px) rotateX(0deg) rotateY(0deg)`;
      state.animating = false;
    }
  }

  disableAll() {
    const selectors = ".hero-right-visual, .preservation-right-visual, .preservation-card, .agent-card, .custody-step-card";
    document.querySelectorAll(selectors).forEach(el => {
      el.style.transform = "none";
      el.style.perspective = "none";
    });
  }
}

// Initialize global Sherlock 3D Motion Engine
window.sherlock3DMotionEngine = new Sherlock3DMotionEngine();

/* ==========================================================================
   Sherlock AI — Scroll-Triggered Staggered Card Reveal Engine
   - 75ms Stagger Delay per Card
   - Opacity: 0 to 1, Slide-Up: 24px to 0px
   - Easing: cubic-bezier(0.16, 1, 0.3, 1)
   - IntersectionObserver triggered
   ========================================================================== */

class SherlockScrollRevealEngine {
  constructor() {
    this.staggerMs = 75;
    this.prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    this.init();
  }

  init() {
    if (this.prefersReducedMotion) {
      this.revealImmediately();
      return;
    }

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => this.setupObserver());
    } else {
      this.setupObserver();
    }

    window.HMACFR_RefreshScrollReveal = () => this.setupObserver();
  }

  setupObserver() {
    if (this.prefersReducedMotion) {
      this.revealImmediately();
      return;
    }

    const cardGrids = document.querySelectorAll(".preservation-cards-row, .agent-cards-grid, .custody-cards-grid, .features-grid-3, .features-grid-4");

    cardGrids.forEach(grid => {
      const cards = grid.querySelectorAll(".preservation-card, .agent-card, .custody-step-card, .feature-card-glass");
      cards.forEach((card, idx) => {
        if (!card.classList.contains("scroll-reveal-card")) {
          card.classList.add("scroll-reveal-card");
        }
        card.style.transitionDelay = `${idx * this.staggerMs}ms`;
      });

      const observer = new IntersectionObserver((entries, obs) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            const gridCards = entry.target.querySelectorAll(".scroll-reveal-card");
            gridCards.forEach(card => card.classList.add("is-revealed"));
            obs.unobserve(entry.target);
          }
        });
      }, {
        threshold: 0.05,
        rootMargin: "0px 0px -30px 0px"
      });

      observer.observe(grid);
    });
  }

  revealImmediately() {
    document.querySelectorAll(".preservation-card, .agent-card, .custody-step-card, .feature-card-glass").forEach(card => {
      card.classList.add("is-revealed");
    });
  }
}

// Initialize global Scroll Reveal Engine
window.sherlockScrollRevealEngine = new SherlockScrollRevealEngine();

/* ==========================================================================
   Sherlock AI — Cross-Page Route Transition Engine (Morphing Fade & Scale)
   - Incoming Section: scale(0.98) to scale(1.0) & opacity 0 to 1 over 280ms
   - Fixed Header (#landing-navbar) maintained in place without layout jarring
   - Easing: cubic-bezier(0.16, 1, 0.3, 1)
   ========================================================================== */

class SherlockTabRouteTransitionEngine {
  constructor() {
    this.durationMs = 280;
    this.prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    this.init();
  }

  init() {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => this.setupRouteNavigation());
    } else {
      this.setupRouteNavigation();
    }
  }

  setupRouteNavigation() {
    const navItems = document.querySelectorAll(".landing-nav-links button, .landing-nav-links a");

    // Directional Smooth Scroll Handler to Target Element
    const scrollToTarget = (targetSection) => {
      if (!targetSection) return;

      const navHeight = 72;
      const targetPos = targetSection.getBoundingClientRect().top + window.pageYOffset - navHeight;

      if (!this.prefersReducedMotion) {
        targetSection.classList.remove("route-transition-active");
        void targetSection.offsetWidth; // Force reflow
        targetSection.classList.add("route-transition-active");
      }

      window.scrollTo({
        top: Math.max(0, targetPos),
        behavior: this.prefersReducedMotion ? "auto" : "smooth"
      });

      if (!this.prefersReducedMotion) {
        setTimeout(() => {
          targetSection.classList.remove("route-transition-active");
        }, this.durationMs + 20);
      }
    };

    // 1. Explore Buttons Click -> Smooth Scroll Down to Preservation Vault
    const exploreButtons = document.querySelectorAll("#btn-nav-launch, #btn-hero-explore");
    exploreButtons.forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        const targetSection = document.querySelector("#landing-preservation");
        scrollToTarget(targetSection);
      });
    });

    // 2. Navbar Links Click -> Smooth Directional Scroll (Up or Down depending on section location)
    if (navItems.length) {
      navItems.forEach(item => {
        item.addEventListener("click", (e) => {
          const targetId = item.getAttribute("data-target") || item.getAttribute("href");
          if (!targetId || !targetId.startsWith("#")) return;

          e.preventDefault();

          // Active state update on nav items
          navItems.forEach(i => i.classList.remove("active"));
          item.classList.add("active");

          const targetSection = document.querySelector(targetId);
          scrollToTarget(targetSection);
        });
      });
    }

    // 3. Dynamic active link highlight on scroll (Scoped strictly to landing page sections)
    const landingSections = document.querySelectorAll("#landing-page-container section[id]");
    if (landingSections.length && navItems.length) {
      const updateLandingNavActive = () => {
        let currentId = "";
        const scrollPosition = window.pageYOffset + 220;

        landingSections.forEach(sec => {
          if (scrollPosition >= sec.offsetTop) {
            currentId = sec.getAttribute("id");
          }
        });

        if (currentId) {
          navItems.forEach(item => {
            const targetId = item.getAttribute("data-target") || item.getAttribute("href");
            if (targetId === `#${currentId}`) {
              item.classList.add("active");
            } else {
              item.classList.remove("active");
            }
          });
        }
      };

      window.addEventListener("scroll", updateLandingNavActive, { passive: true });
      updateLandingNavActive();
    }
  }
}

// Initialize global Tab Route Transition Engine
window.sherlockTabRouteTransitionEngine = new SherlockTabRouteTransitionEngine();
