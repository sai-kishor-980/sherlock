/* HMACFR 3D WebGL Engine - Ambient Background & Interactive Holographic Evidence Vault */

class HMACFR_3DEngine {
  constructor() {
    this.bgCanvas = null;
    this.bgScene = null;
    this.bgCamera = null;
    this.bgRenderer = null;
    this.bgParticles = null;
    this.bgGrid = null;
    this.bgObjects = [];

    this.vaultCanvas = null;
    this.vaultScene = null;
    this.vaultCamera = null;
    this.vaultRenderer = null;
    this.vaultCore = null;
    this.vaultRings = [];
    this.vaultNodes = [];
    this.vaultLaserLines = [];
    this.raycaster = null;
    this.mouse = null;
    this.hoveredNode = null;
    this.selectedNode = null;

    this.mouseX = 0;
    this.mouseY = 0;

    this.activeTheme = "cyber-grid"; // "cyber-grid", "quantum-cloud", "holo-vault"
    this.evidenceData = [];

    this.isVaultActive = false;

    this.initWhenReady();
  }

  initWhenReady() {
    const check = () => {
      if (window.THREE && !this.isInitialized) {
        this.isInitialized = true;
        this.init();
        return true;
      }
      return false;
    };

    if (!check()) {
      const timer = setInterval(() => {
        if (check()) clearInterval(timer);
      }, 50);
      window.addEventListener("load", () => {
        if (check()) clearInterval(timer);
      });
      setTimeout(() => clearInterval(timer), 5000);
    }
  }

  init() {
    this.initBackgroundScene();
    this.setupEventListeners();
    this.animate();
  }

  /* ==================== 1. AMBIENT 3D BACKGROUND SCENE ==================== */
  initBackgroundScene() {
    this.bgCanvas = document.getElementById("three-bg-canvas");
    if (!this.bgCanvas) return;

    this.bgScene = new THREE.Scene();
    this.bgScene.fog = new THREE.FogExp2(0x080c14, 0.0012);

    this.bgCamera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 1, 1000);
    this.bgCamera.position.set(0, 15, 60);

    this.bgRenderer = new THREE.WebGLRenderer({
      canvas: this.bgCanvas,
      alpha: true,
      antialias: true
    });
    this.bgRenderer.setSize(window.innerWidth, window.innerHeight);
    this.bgRenderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Soft Cybersecurity Ambient & Directional Lights
    const ambientLight = new THREE.AmbientLight(0x10b981, 0.5);
    this.bgScene.add(ambientLight);

    const pointLight1 = new THREE.PointLight(0x10b981, 1.8, 100);
    pointLight1.position.set(20, 20, 20);
    this.bgScene.add(pointLight1);

    const pointLight2 = new THREE.PointLight(0x14b8a6, 1.4, 100);
    pointLight2.position.set(-20, -20, -20);
    this.bgScene.add(pointLight2);

    // Subtle Flowing Cybersecurity Network Particles (Clean & Minimal)
    const particleCount = 700;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    const colorOlive = new THREE.Color(0xa4b82a); // Olive/Green Emblem Branding Accent
    const colorBlue = new THREE.Color(0x1b8fff);  // Primary Cyber Blue
    const colorCyan = new THREE.Color(0x06b6d4);  // Soft Cyan Accent

    for (let i = 0; i < particleCount; i++) {
      const x = (Math.random() - 0.5) * 160;
      const y = (Math.random() - 0.5) * 120;
      const z = (Math.random() - 0.5) * 160;
      positions[i * 3] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;

      // Higher chance of olive green near center emblem, dominant blue farther out
      const distFromCenter = Math.sqrt(x*x + y*y + z*z);
      const isGreen = distFromCenter < 35 && Math.random() < 0.45;
      const mixedColor = isGreen ? colorOlive : (Math.random() > 0.35 ? colorBlue : colorCyan);
      colors[i * 3] = mixedColor.r;
      colors[i * 3 + 1] = mixedColor.g;
      colors[i * 3 + 2] = mixedColor.b;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const particleMaterial = new THREE.PointsMaterial({
      size: 0.7,
      vertexColors: true,
      transparent: true,
      opacity: 0.45,
      blending: THREE.AdditiveBlending
    });

    this.bgParticles = new THREE.Points(geometry, particleMaterial);
    this.bgScene.add(this.bgParticles);

    // Faint Moving Grid Floor
    const gridHelper = new THREE.GridHelper(200, 40, 0x10b981, 0x0f172a);
    gridHelper.position.y = -30;
    gridHelper.material.transparent = true;
    gridHelper.material.opacity = 0.18;
    this.bgGrid = gridHelper;
    this.bgScene.add(gridHelper);

    // Ambient Floating Polyhedra (Subtle & Non-distracting)
    const shapes = [
      new THREE.IcosahedronGeometry(3, 0),
      new THREE.OctahedronGeometry(2.5, 0),
      new THREE.TorusGeometry(3, 0.8, 16, 32)
    ];

    for (let i = 0; i < 5; i++) {
      const geom = shapes[i % shapes.length];
      const mat = new THREE.MeshPhongMaterial({
        color: i % 2 === 0 ? 0x10b981 : 0x14b8a6,
        wireframe: true,
        transparent: true,
        opacity: 0.12,
        emissive: i % 2 === 0 ? 0x059669 : 0x0d9488,
        emissiveIntensity: 0.15
      });

      const mesh = new THREE.Mesh(geom, mat);
      mesh.position.set(
        (Math.random() - 0.5) * 80,
        (Math.random() - 0.5) * 40,
        (Math.random() - 0.5) * 60
      );
      mesh.rotSpeedX = (Math.random() - 0.5) * 0.005;
      mesh.rotSpeedY = (Math.random() - 0.5) * 0.005;

      this.bgObjects.push(mesh);
      this.bgScene.add(mesh);
    }

    // ==================== SHERLOCK HOLMES 3D DEERSTALKER HAT ====================
    const hatGroup = new THREE.Group();
    hatGroup.position.set(22, 6, -18);

    // Crown Base
    const crownGeom = new THREE.ConeGeometry(5, 4, 32, 1, true);
    const crownMat = new THREE.MeshPhongMaterial({
      color: 0x10b981,
      wireframe: true,
      transparent: true,
      opacity: 0.35,
      emissive: 0x059669,
      emissiveIntensity: 0.3
    });
    const crown = new THREE.Mesh(crownGeom, crownMat);
    crown.position.y = 2;
    hatGroup.add(crown);

    // Front Visor / Brim
    const visorGeom = new THREE.CylinderGeometry(6, 6.5, 0.4, 32, 1, false, 0, Math.PI);
    const visorMat = new THREE.MeshPhongMaterial({
      color: 0x14b8a6,
      transparent: true,
      opacity: 0.4,
      wireframe: true
    });
    const frontVisor = new THREE.Mesh(visorGeom, visorMat);
    frontVisor.position.set(0, 0, 1.5);
    frontVisor.rotation.x = 0.2;
    hatGroup.add(frontVisor);

    // Back Visor
    const backVisor = frontVisor.clone();
    backVisor.position.set(0, 0, -1.5);
    backVisor.rotation.y = Math.PI;
    backVisor.rotation.x = 0.2;
    hatGroup.add(backVisor);

    // Side Ear Flaps
    const flapGeom = new THREE.BoxGeometry(0.3, 3, 3);
    const flapMat = new THREE.MeshPhongMaterial({ color: 0x06b6d4, wireframe: true, transparent: true, opacity: 0.3 });
    const leftFlap = new THREE.Mesh(flapGeom, flapMat);
    leftFlap.position.set(-4.8, 1, 0);
    leftFlap.rotation.z = 0.25;
    hatGroup.add(leftFlap);

    const rightFlap = leftFlap.clone();
    rightFlap.position.set(4.8, 1, 0);
    rightFlap.rotation.z = -0.25;
    hatGroup.add(rightFlap);

    // Top Cap / Opening Lid
    const lidGeom = new THREE.SphereGeometry(2.5, 16, 16, 0, Math.PI * 2, 0, Math.PI / 2);
    const lidMat = new THREE.MeshPhongMaterial({ color: 0x34d399, wireframe: true, transparent: true, opacity: 0.65 });
    const lidMesh = new THREE.Mesh(lidGeom, lidMat);
    lidMesh.position.y = 3.8;
    hatGroup.add(lidMesh);
    this.sherlockLid = lidMesh;

    // Glowing Inner Evidence Core (unveiled when lid opens)
    const innerOrbGeom = new THREE.IcosahedronGeometry(1.5, 1);
    const innerOrbMat = new THREE.MeshBasicMaterial({ color: 0x10b981, wireframe: true, transparent: true, opacity: 0.85 });
    const innerOrb = new THREE.Mesh(innerOrbGeom, innerOrbMat);
    innerOrb.position.y = 2.5;
    hatGroup.add(innerOrb);
    this.sherlockCoreOrb = innerOrb;

    // Orbiting Magnifying Lens Ring
    const lensRingGeom = new THREE.TorusGeometry(7.5, 0.2, 16, 48);
    const lensRingMat = new THREE.MeshBasicMaterial({ color: 0x2dd4bf, wireframe: true, transparent: true, opacity: 0.45 });
    const lensRing = new THREE.Mesh(lensRingGeom, lensRingMat);
    lensRing.rotation.x = Math.PI / 3;
    hatGroup.add(lensRing);
    this.sherlockLensRing = lensRing;

    this.sherlockHatGroup = hatGroup;
    this.bgScene.add(hatGroup);
  }


  /* ==================== 2. INTERACTIVE 3D VAULT STAGE ==================== */
  initVaultStage() {
    this.vaultCanvas = document.getElementById("three-vault-canvas");
    if (!this.vaultCanvas || this.vaultScene) return;

    this.vaultScene = new THREE.Scene();
    this.vaultScene.fog = new THREE.FogExp2(0x080c14, 0.002);

    const container = this.vaultCanvas.parentElement;
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 500;

    this.vaultCamera = new THREE.PerspectiveCamera(50, width / height, 0.1, 1000);
    this.vaultCamera.position.set(0, 10, 32);

    this.vaultRenderer = new THREE.WebGLRenderer({
      canvas: this.vaultCanvas,
      alpha: true,
      antialias: true
    });
    this.vaultRenderer.setSize(width, height);
    this.vaultRenderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    this.raycaster = new THREE.Raycaster();
    this.mouse = new THREE.Vector2(-999, -999);

    // Vault Lighting (Soft Emerald Ambient & Directional Lights)
    const ambientLight = new THREE.AmbientLight(0x10b981, 0.35);
    this.vaultScene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0x10b981, 1.5);
    dirLight.position.set(10, 20, 15);
    this.vaultScene.add(dirLight);

    const pointLight = new THREE.PointLight(0x14b8a6, 2.5, 50);
    pointLight.position.set(0, 0, 0);
    this.vaultScene.add(pointLight);

    // Build Central 3D AES Cryptographic Core
    this.buildVaultCore();

    // Rebuild Nodes if evidence data is pre-populated
    this.rebuildEvidenceNodes(this.evidenceData);

    this.isVaultActive = true;
  }

  buildVaultCore() {
    const coreGroup = new THREE.Group();

    // 1. Inner AES Core Cube
    const cubeGeom = new THREE.BoxGeometry(4, 4, 4);
    const cubeMat = new THREE.MeshPhongMaterial({
      color: 0x047857,
      emissive: 0x064e3b,
      emissiveIntensity: 0.5,
      shininess: 90,
      wireframe: false,
      transparent: true,
      opacity: 0.85
    });
    const coreCube = new THREE.Mesh(cubeGeom, cubeMat);
    coreGroup.add(coreCube);

    // Inner Wireframe Accent
    const wireGeom = new THREE.BoxGeometry(4.2, 4.2, 4.2);
    const wireMat = new THREE.MeshBasicMaterial({
      color: 0x10b981,
      wireframe: true,
      transparent: true,
      opacity: 0.65
    });
    const wireCube = new THREE.Mesh(wireGeom, wireMat);
    coreGroup.add(wireCube);

    // Outer Orbit Rings
    const ringMat1 = new THREE.MeshBasicMaterial({ color: 0x10b981, wireframe: true, transparent: true, opacity: 0.5 });
    const ringGeom1 = new THREE.TorusGeometry(6.5, 0.08, 16, 64);
    const ring1 = new THREE.Mesh(ringGeom1, ringMat1);
    coreGroup.add(ring1);
    this.vaultRings.push(ring1);

    const ringMat2 = new THREE.MeshBasicMaterial({ color: 0x14b8a6, wireframe: true, transparent: true, opacity: 0.45 });
    const ringGeom2 = new THREE.TorusGeometry(8.5, 0.08, 16, 64);
    const ring2 = new THREE.Mesh(ringGeom2, ringMat2);
    ring2.rotation.x = Math.PI / 3;
    coreGroup.add(ring2);
    this.vaultRings.push(ring2);

    const ringMat3 = new THREE.MeshBasicMaterial({ color: 0x06b6d4, wireframe: true, transparent: true, opacity: 0.45 });
    const ringGeom3 = new THREE.TorusGeometry(10.5, 0.08, 16, 64);
    const ring3 = new THREE.Mesh(ringGeom3, ringMat3);
    ring3.rotation.y = Math.PI / 4;
    coreGroup.add(ring3);
    this.vaultRings.push(ring3);

    this.vaultCore = coreGroup;
    this.vaultScene.add(coreGroup);
  }

  /* Update or populate 3D Evidence Nodes in Vault */
  rebuildEvidenceNodes(data) {
    if (!this.vaultScene) return;

    this.evidenceData = data || [];
    const items = this.evidenceData;

    // Clear existing nodes and laser lines
    this.vaultNodes.forEach(node => this.vaultScene.remove(node));
    this.vaultLaserLines.forEach(line => this.vaultScene.remove(line));
    this.vaultNodes = [];
    this.vaultLaserLines = [];

    const count = items.length;
    const radius = 14;

    items.forEach((item, index) => {
      const angle = (index / count) * Math.PI * 2;
      const x = Math.cos(angle) * radius;
      const z = Math.sin(angle) * radius;
      const y = (Math.sin(index * 1.5) * 3);

      // Node Geometry based on category
      let geom;
      const catLower = (item.category ? item.category.toLowerCase() : "");
      switch (catLower) {
        case "memory":
          // Cyber Hexagonal Memory Prism
          geom = new THREE.CylinderGeometry(1.6, 1.6, 2.2, 6);
          break;
        case "pcap":
          // Radar Network Octahedron
          geom = new THREE.OctahedronGeometry(1.8, 0);
          break;
        case "logs":
        case "registry":
          // Encrypted Registry Security Capsule
          geom = new THREE.DodecahedronGeometry(1.6, 0);
          break;
        case "malware":
          // Bio-Threat Spiked Polyhedron
          geom = new THREE.IcosahedronGeometry(1.8, 0);
          break;
        default:
          // Storage Data Module
          geom = new THREE.BoxGeometry(2, 2, 2);
          break;
      }

      // Digital Forensics Color Palette - Cybersecurity Dark Theme
      let color = 0x10b981; // Soft Emerald default
      if (item.integrity === "TAMPERED") color = 0xef4444; // Critical Red Alert for Tampered
      else if (item.is_preserved) color = 0x14b8a6; // Verified Cryptographic Muted Teal
      else if (item.category === "Malware") color = 0xef4444; // Critical Red Alert for Malware Specimen

      const mat = new THREE.MeshPhongMaterial({
        color: color,
        emissive: color,
        emissiveIntensity: 0.35,
        shininess: 90,
        wireframe: false,
        transparent: true,
        opacity: 0.90
      });

      const mesh = new THREE.Mesh(geom, mat);
      mesh.position.set(x, y, z);
      mesh.userData = { ...item, originalScale: 1.0, orbitAngle: angle, orbitRadius: radius, orbitY: y };

      // Wireframe overlay for node
      const wireMat = new THREE.MeshBasicMaterial({ color: 0x10b981, wireframe: true, transparent: true, opacity: 0.25 });
      const wireMesh = new THREE.Mesh(geom, wireMat);
      wireMesh.scale.set(1.08, 1.08, 1.08);
      mesh.add(wireMesh);

      // Add 3D Holographic Soft Lock Ring if Preserved
      if (item.is_preserved) {
        const lockRingMat = new THREE.MeshBasicMaterial({ color: 0x10b981, wireframe: true, transparent: true, opacity: 0.65 });
        const lockRingGeom = new THREE.TorusGeometry(2.4, 0.06, 12, 32);
        const lockRing = new THREE.Mesh(lockRingGeom, lockRingMat);
        lockRing.rotation.x = Math.PI / 2;
        mesh.add(lockRing);
      }

      // Add Threat Spikes if Malware Specimen or Tampered
      if (catLower === "malware" || item.integrity === "TAMPERED") {
        const spikeMat = new THREE.MeshBasicMaterial({ color: 0xef4444 });
        for (let s = 0; s < 6; s++) {
          const spikeGeom = new THREE.ConeGeometry(0.3, 1.4, 4);
          const spike = new THREE.Mesh(spikeGeom, spikeMat);
          spike.position.set(
            (Math.random() - 0.5) * 2.2,
            (Math.random() - 0.5) * 2.2,
            (Math.random() - 0.5) * 2.2
          );
          mesh.add(spike);
        }
      }

      this.vaultScene.add(mesh);
      this.vaultNodes.push(mesh);

      // Laser connector line from central vault core (0,0,0) to node
      const lineMat = new THREE.LineBasicMaterial({
        color: item.integrity === "TAMPERED" ? 0xef4444 : 0x10b981,
        transparent: true,
        opacity: 0.45
      });
      const points = [new THREE.Vector3(0, 0, 0), mesh.position.clone()];
      const lineGeom = new THREE.BufferGeometry().setFromPoints(points);
      const line = new THREE.Line(lineGeom, lineMat);

      this.vaultScene.add(line);
      this.vaultLaserLines.push(line);
    });

    // Update HUD counters
    const countEl = document.getElementById("vault-3d-node-count");
    if (countEl) countEl.textContent = count;

    const overlay = document.getElementById("vault-empty-overlay");
    if (overlay) {
      overlay.style.display = count === 0 ? "flex" : "none";
    }
  }

  /* ==================== 4. 3D INTERACTIVE CUSTODY CHAIN STAGE ==================== */
  initCustodyStage(logsData) {
    const canvas = document.getElementById("three-custody-canvas");
    if (!canvas || !window.THREE) return;

    if (!this.custodyScene) {
      this.custodyScene = new THREE.Scene();
      const container = canvas.parentElement;
      const w = container.clientWidth || 800;
      const h = container.clientHeight || 320;

      this.custodyCamera = new THREE.PerspectiveCamera(45, w / h, 0.1, 1000);
      this.custodyCamera.position.set(0, 8, 28);

      this.custodyRenderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
      this.custodyRenderer.setSize(w, h);
      this.custodyRenderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

      const light = new THREE.DirectionalLight(0x10b981, 1.5);
      light.position.set(10, 20, 10);
      this.custodyScene.add(light);

      const amb = new THREE.AmbientLight(0x10b981, 0.35);
      this.custodyScene.add(amb);
    }

    // Build 3D Block Chain Pipeline
    if (this.custodyBlocks) this.custodyBlocks.forEach(b => this.custodyScene.remove(b));
    this.custodyBlocks = [];

    const logs = logsData || [];

    const startX = -((logs.length - 1) * 6) / 2;
    logs.forEach((log, idx) => {
      const x = startX + idx * 6;
      const geom = new THREE.BoxGeometry(3, 3, 3);
      const mat = new THREE.MeshPhongMaterial({
        color: idx % 2 === 0 ? 0x10b981 : 0x14b8a6,
        emissive: idx % 2 === 0 ? 0x047857 : 0x0f766e,
        emissiveIntensity: 0.4,
        wireframe: false,
        transparent: true,
        opacity: 0.9
      });

      const block = new THREE.Mesh(geom, mat);
      block.position.set(x, 0, 0);
      block.userData = log;

      const wire = new THREE.Mesh(geom, new THREE.MeshBasicMaterial({ color: 0x10b981, wireframe: true, opacity: 0.25, transparent: true }));
      wire.scale.set(1.08, 1.08, 1.08);
      block.add(wire);

      this.custodyScene.add(block);
      this.custodyBlocks.push(block);

      // Connect 3D Holographic Chain Line to previous block
      if (idx > 0) {
        const lineMat = new THREE.LineBasicMaterial({ color: 0x10b981, transparent: true, opacity: 0.7 });
        const pts = [new THREE.Vector3(x - 6, 0, 0), new THREE.Vector3(x, 0, 0)];
        const lineGeom = new THREE.BufferGeometry().setFromPoints(pts);
        const chainLine = new THREE.Line(lineGeom, lineMat);
        this.custodyScene.add(chainLine);
      }
    });

    this.isCustodyActive = true;
  }

  /* ==================== 5. 3D MULTI-FACTOR AUDIT SCANNER STAGE ==================== */
  initAuditStage(reportData) {
    const canvas = document.getElementById("three-audit-canvas");
    if (!canvas || !window.THREE) return;

    if (!this.auditScene) {
      this.auditScene = new THREE.Scene();
      const container = canvas.parentElement;
      const w = container.clientWidth || 800;
      const h = container.clientHeight || 300;

      this.auditCamera = new THREE.PerspectiveCamera(45, w / h, 0.1, 1000);
      this.auditCamera.position.set(0, 12, 24);

      this.auditRenderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
      this.auditRenderer.setSize(w, h);
      this.auditRenderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

      const amb = new THREE.AmbientLight(0x10b981, 0.5);
      this.auditScene.add(amb);

      // Sweeping Laser Scanner Line
      const scanGeom = new THREE.PlaneGeometry(30, 0.3);
      const scanMat = new THREE.MeshBasicMaterial({ color: 0x10b981, side: THREE.DoubleSide, transparent: true, opacity: 0.65 });
      this.auditScanPlane = new THREE.Mesh(scanGeom, scanMat);
      this.auditScanPlane.rotation.x = Math.PI / 2;
      this.auditScene.add(this.auditScanPlane);
    }

    if (this.auditNodes) this.auditNodes.forEach(n => this.auditScene.remove(n));
    this.auditNodes = [];

    const results = reportData && reportData.results ? reportData.results : [];

    results.forEach((res, idx) => {
      const geom = res.is_valid ? new THREE.IcosahedronGeometry(1.6, 0) : new THREE.ConeGeometry(1.6, 2.8, 4);
      const color = res.is_valid ? 0x10b981 : 0xef4444;
      const mat = new THREE.MeshPhongMaterial({ color: color, emissive: color, emissiveIntensity: 0.5, wireframe: true });
      const mesh = new THREE.Mesh(geom, mat);
      const angle = (idx / results.length) * Math.PI * 2;
      mesh.position.set(Math.cos(angle) * 8, 0, Math.sin(angle) * 8);
      this.auditScene.add(mesh);
      this.auditNodes.push(mesh);
    });

    this.isAuditActive = true;
  };

  /* ==================== 3. ANIMATION LOOP & RENDER ==================== */
  animate() {
    requestAnimationFrame(() => this.animate());

    // 1. Animate Ambient Background
    if (this.bgScene && this.bgRenderer) {
      if (this.bgParticles) {
        this.bgParticles.rotation.y += 0.0005;
        this.bgParticles.rotation.x += 0.0002;
      }

      this.bgObjects.forEach(obj => {
        obj.rotation.x += obj.rotSpeedX;
        obj.rotation.y += obj.rotSpeedY;
      });

      // Animate Sherlock Holmes 3D Deerstalker Hat (Floating, Rotating & Opening/Closing Lid)
      if (this.sherlockHatGroup) {
        const t = Date.now() * 0.0015;
        this.sherlockHatGroup.rotation.y = Math.sin(t * 0.5) * 0.4;
        this.sherlockHatGroup.position.y = 6 + Math.sin(t) * 0.8;

        if (this.sherlockLid) {
          // Opening and closing animation of the hat crown lid!
          const lidOpen = (Math.sin(t * 0.8) + 1) * 0.5; // 0 to 1 smooth wave
          this.sherlockLid.position.y = 3.8 + lidOpen * 1.8;
          this.sherlockLid.rotation.x = -lidOpen * 0.6;
        }

        if (this.sherlockCoreOrb) {
          this.sherlockCoreOrb.rotation.y += 0.02;
          this.sherlockCoreOrb.rotation.z += 0.01;
        }

        if (this.sherlockLensRing) {
          this.sherlockLensRing.rotation.z += 0.015;
        }
      }

      // Static, stable background camera (zero mouse parallax / zero camera tilt)
      this.bgCamera.position.set(0, 15, 60);
      this.bgCamera.lookAt(0, 0, 0);

      this.bgRenderer.render(this.bgScene, this.bgCamera);
    }


    // 2. Animate Vault 3D Stage
    if (this.isVaultActive && this.vaultScene && this.vaultRenderer) {
      if (this.vaultCore) {
        this.vaultCore.rotation.y += 0.005;
        this.vaultCore.rotation.x += 0.002;
      }

      this.vaultRings.forEach((ring, idx) => {
        ring.rotation.z += 0.008 * (idx % 2 === 0 ? 1 : -1);
      });

      // Orbit 3D Evidence Nodes smoothly
      const time = Date.now() * 0.0006;
      this.vaultNodes.forEach((node, idx) => {
        if (node !== this.hoveredNode && node !== this.selectedNode) {
          const currentAngle = node.userData.orbitAngle + time * 0.3;
          node.position.x = Math.cos(currentAngle) * node.userData.orbitRadius;
          node.position.z = Math.sin(currentAngle) * node.userData.orbitRadius;
          node.position.y = node.userData.orbitY + Math.sin(time * 2 + idx) * 0.5;
          node.rotation.x += 0.01;
          node.rotation.y += 0.01;

          // Update connecting laser line points
          const line = this.vaultLaserLines[idx];
          if (line) {
            const positions = line.geometry.attributes.position.array;
            positions[3] = node.position.x;
            positions[4] = node.position.y;
            positions[5] = node.position.z;
            line.geometry.attributes.position.needsUpdate = true;
          }
        }
      });

      // Auto Orbit cinematic toggle
      if (this.isAutoOrbit && this.vaultCamera) {
        const time = Date.now() * 0.0003;
        this.vaultCamera.position.x = Math.sin(time) * 32;
        this.vaultCamera.position.z = Math.cos(time) * 32;
        this.vaultCamera.lookAt(0, 0, 0);
      }

      this.vaultRenderer.render(this.vaultScene, this.vaultCamera);
    }

    // 3. Animate 3D Radium Decryptor Loading Stage
    if (this.loadingScene && this.loadingRenderer) {
      if (this.loadingCube) {
        this.loadingCube.rotation.x += 0.035;
        this.loadingCube.rotation.y += 0.045;
      }
      if (this.loadingInner) {
        this.loadingInner.rotation.x -= 0.05;
        this.loadingInner.rotation.z += 0.03;
      }
      if (this.loadingRing) {
        this.loadingRing.rotation.z += 0.04;
      }
      this.loadingRenderer.render(this.loadingScene, this.loadingCamera);
    }

    // 4. Animate 3D Custody Chain Pipeline Stage
    if (this.isCustodyActive && this.custodyScene && this.custodyRenderer) {
      if (this.custodyBlocks) {
        this.custodyBlocks.forEach((block, i) => {
          block.rotation.y += 0.015 * (i % 2 === 0 ? 1 : -1);
          block.rotation.x += 0.008;
        });
      }
      this.custodyRenderer.render(this.custodyScene, this.custodyCamera);
    }

    // 5. Animate 3D Multi-Factor Audit Scanner Stage
    if (this.isAuditActive && this.auditScene && this.auditRenderer) {
      if (this.auditNodes) {
        this.auditNodes.forEach(node => {
          node.rotation.y += 0.02;
        });
      }
      if (this.auditScanPlane) {
        this.auditScanPlane.position.z = Math.sin(Date.now() * 0.002) * 10;
      }
      this.auditRenderer.render(this.auditScene, this.auditCamera);
    }

    /* ==================== COMMENTED OUT PER USER REQUEST ====================
    // 6. Animate 3D Auth Cyber Computer Workstation (Breakdown, Light Burst & Reverse Reassembly)
    if (this.authScene && this.authRenderer) {
      // Smooth interpolation for breakdown explosion & light burst
      this.explosionProgress += (this.targetExplosion - this.explosionProgress) * 0.14;
      this.crackProgress += (this.targetCrack - this.crackProgress) * 0.12;
      this.burstIntensity += (this.targetBurst - this.burstIntensity) * 0.15;

      if (this.authBurstLight) {
        this.authBurstLight.intensity = this.burstIntensity;
      }

      if (this.crackMat) {
        this.crackMat.opacity = this.crackProgress;
      }

      // Animate 3D Computer Workstation Main Parts Breakdown & Reverse Reassembly
      if (this.monitorMesh) {
        this.monitorMesh.position.set(0, 0, 0).addScaledVector(new THREE.Vector3(-3.5, 2.2, 5.5), this.explosionProgress);
        this.monitorMesh.rotation.y = Math.sin(Date.now() * 0.001) * 0.05 + this.explosionProgress * 0.6;
        this.monitorMesh.rotation.z = -this.explosionProgress * 0.4;
      }

      if (this.screenMesh) {
        this.screenMesh.position.set(0, 0, 0.51).addScaledVector(new THREE.Vector3(-3.5, 2.2, 6.0), this.explosionProgress);
        this.screenMesh.rotation.y = Math.sin(Date.now() * 0.001) * 0.05 + this.explosionProgress * 0.6;
      }

      if (this.screenBgMesh) {
        this.screenBgMesh.position.set(0, 0, 0.505).addScaledVector(new THREE.Vector3(-3.5, 2.2, 6.0), this.explosionProgress);
      }

      if (this.towerMesh) {
        this.towerMesh.position.set(3.2, -0.2, -0.5).addScaledVector(new THREE.Vector3(6.5, -2.0, 4.5), this.explosionProgress);
        this.towerMesh.rotation.x = this.explosionProgress * 0.7;
        this.towerMesh.rotation.z = this.explosionProgress * 0.3;
      }

      if (this.kbMesh) {
        this.kbMesh.position.set(0, -2.3, 1.2).addScaledVector(new THREE.Vector3(0.5, -5.5, 7.5), this.explosionProgress);
        this.kbMesh.rotation.x = -this.explosionProgress * 0.8;
      }

      if (this.standMesh) {
        this.standMesh.position.set(0, -2.0, 0).addScaledVector(new THREE.Vector3(-0.5, -4.5, -2.5), this.explosionProgress);
      }

      // Animate 3D PC Debris Fragments along velocity vectors
      if (this.computerFragments) {
        this.computerFragments.forEach(frag => {
          frag.position.copy(frag.userData.origPos).addScaledVector(frag.userData.velocity, this.explosionProgress);
          frag.rotation.x += frag.userData.rotSpeed.x * (1 + this.explosionProgress * 3);
          frag.rotation.y += frag.userData.rotSpeed.y * (1 + this.explosionProgress * 3);
        });
      }

      this.authRenderer.render(this.authScene, this.authCamera);
    }
    ======================================================================== */
  }


  handleRaycaster() {
    if (!this.raycaster || !this.vaultCamera || this.vaultNodes.length === 0) return;

    this.raycaster.setFromCamera(this.mouse, this.vaultCamera);
    const intersects = this.raycaster.intersectObjects(this.vaultNodes);

    if (intersects.length > 0) {
      const hitNode = intersects[0].object;

      if (this.hoveredNode !== hitNode) {
        if (this.hoveredNode) {
          // Reset previous hovered node
          this.hoveredNode.scale.set(1, 1, 1);
        }

        this.hoveredNode = hitNode;
        this.hoveredNode.scale.set(1.4, 1.4, 1.4);

        // Update HUD hover tooltip
        this.updateVaultHUD(hitNode.userData);
      }
      this.vaultCanvas.style.cursor = "pointer";
    } else {
      if (this.hoveredNode) {
        this.hoveredNode.scale.set(1, 1, 1);
        this.hoveredNode = null;
      }
      this.vaultCanvas.style.cursor = "default";
    }
  }

  updateVaultHUD(data) {
    const hudContainer = document.getElementById("vault-3d-inspector");
    if (!hudContainer) return;

    hudContainer.innerHTML = `
      <div style="font-size: 0.75rem; color: var(--accent-cyan); font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">3D Node Inspector</div>
      <div style="font-size: 1.1rem; font-weight: 700; color: #fff; margin: 0.25rem 0;">${data.filename || "Evidence Artifact"}</div>
      <div style="display: flex; gap: 0.5rem; margin-bottom: 0.75rem;">
        <span class="badge badge-indigo">${data.category || "General"}</span>
        <span class="badge ${data.integrity === 'TAMPERED' ? 'badge-amber' : 'badge-emerald'}">${data.integrity || 'VALID'}</span>
        ${data.is_preserved ? '<span class="badge badge-cyan">Locked Read-Only</span>' : ''}
      </div>
      <div class="mono-text" style="font-size: 0.75rem; color: var(--text-secondary); background: rgba(0,0,0,0.4); padding: 0.5rem; border-radius: 6px; word-break: break-all;">
        <span style="color: var(--accent-indigo);">SHA256:</span> ${data.sha256 || 'Pending preservation...'}
      </div>
    `;
    hudContainer.style.display = "block";
  }

  setupEventListeners() {
    window.addEventListener("mousemove", (e) => {
      this.mouseX = (e.clientX / window.innerWidth) * 2 - 1;
      this.mouseY = (e.clientY / window.innerHeight) * 2 - 1;

      // Also map for vault raycaster canvas
      if (this.vaultCanvas) {
        const rect = this.vaultCanvas.getBoundingClientRect();
        this.mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
        this.mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
      }
    });

    window.addEventListener("resize", () => {
      if (this.bgCamera && this.bgRenderer) {
        this.bgCamera.aspect = window.innerWidth / window.innerHeight;
        this.bgCamera.updateProjectionMatrix();
        this.bgRenderer.setSize(window.innerWidth, window.innerHeight);
      }

      if (this.vaultCanvas && this.vaultCamera && this.vaultRenderer) {
        const container = this.vaultCanvas.parentElement;
        const w = container.clientWidth;
        const h = container.clientHeight;
        this.vaultCamera.aspect = w / h;
        this.vaultCamera.updateProjectionMatrix();
        this.vaultRenderer.setSize(w, h);
      }
    });

    // Vault Canvas Click Listener
    document.addEventListener("click", (e) => {
      if (e.target === this.vaultCanvas && this.hoveredNode) {
        this.selectedNode = this.hoveredNode;
        this.updateVaultHUD(this.selectedNode.userData);
      }
    });
  }

  initLoadingRadiumStage() {
    const canvas = document.getElementById("loading-radium-canvas");
    if (!canvas || this.loadingScene || !window.THREE) return;

    this.loadingScene = new THREE.Scene();
    this.loadingCamera = new THREE.PerspectiveCamera(50, 1, 0.1, 100);
    this.loadingCamera.position.z = 7;

    this.loadingRenderer = new THREE.WebGLRenderer({
      canvas: canvas,
      alpha: true,
      antialias: true
    });
    this.loadingRenderer.setSize(140, 140);
    this.loadingRenderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // Soft Emerald Wireframe Decryptor Cube
    const geom = new THREE.BoxGeometry(2.4, 2.4, 2.4);
    const mat = new THREE.MeshPhongMaterial({
      color: 0x10b981,
      emissive: 0x059669,
      emissiveIntensity: 0.6,
      wireframe: true
    });
    this.loadingCube = new THREE.Mesh(geom, mat);
    this.loadingScene.add(this.loadingCube);

    // Inner Glowing Octahedron Core
    const innerGeom = new THREE.OctahedronGeometry(1.2, 0);
    const innerMat = new THREE.MeshBasicMaterial({ color: 0x14b8a6, wireframe: true });
    this.loadingInner = new THREE.Mesh(innerGeom, innerMat);
    this.loadingScene.add(this.loadingInner);

    // Outer Orbit Ring
    const ringGeom = new THREE.TorusGeometry(3.2, 0.06, 12, 48);
    const ringMat = new THREE.MeshBasicMaterial({ color: 0x10b981, wireframe: true, transparent: true, opacity: 0.75 });
    this.loadingRing = new THREE.Mesh(ringGeom, ringMat);
    this.loadingScene.add(this.loadingRing);

    const light = new THREE.PointLight(0x10b981, 2.5, 20);
    light.position.set(5, 5, 5);
    this.loadingScene.add(light);
  }

  /* ==================== 6. 3D AUTH CYBER COMPUTER WORKSTATION (COMMENTED OUT PER USER REQUEST) ====================
  initAuthStage() {
    const canvas = document.getElementById("auth-3d-canvas");
    if (!canvas || !window.THREE) return;

    const container = canvas.parentElement;
    const w = container.clientWidth || 340;
    const h = container.clientHeight || 210;

    if (!this.authScene) {
      this.authScene = new THREE.Scene();

      this.authCamera = new THREE.PerspectiveCamera(45, w / h, 0.1, 100);
      this.authCamera.position.set(0, 0.2, 8.5);

      this.authRenderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
      this.authRenderer.setSize(w, h);
      this.authRenderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

      // Soft Emerald Cybersecurity Ambient & Directional Lights
      const ambLight = new THREE.AmbientLight(0x10b981, 0.8);
      this.authScene.add(ambLight);

      const dirLight = new THREE.DirectionalLight(0x14b8a6, 2.0);
      dirLight.position.set(5, 10, 8);
      this.authScene.add(dirLight);

      this.authBurstLight = new THREE.PointLight(0x10b981, 2.0, 50);
      this.authBurstLight.position.set(0, 0.5, 3);
      this.authScene.add(this.authBurstLight);
    } else if (this.authRenderer) {
      this.authRenderer.setSize(w, h);
      this.authCamera.aspect = w / h;
      this.authCamera.updateProjectionMatrix();
    }

    // Clear previous auth objects
    if (this.computerGroup) this.authScene.remove(this.computerGroup);
    this.computerGroup = new THREE.Group();
    this.computerFragments = [];

    // 1. Monitor Body & Bezel (Dark Charcoal with Emerald Accents)
    const monGeom = new THREE.BoxGeometry(4.2, 3.2, 1.0);
    const monMat = new THREE.MeshPhongMaterial({ color: 0x0f172a, emissive: 0x064e3b, emissiveIntensity: 0.4, shininess: 90 });
    this.monitorMesh = new THREE.Mesh(monGeom, monMat);
    this.computerGroup.add(this.monitorMesh);

    // Monitor Glowing Edge Wireframe (Soft Emerald)
    const monWireMat = new THREE.MeshBasicMaterial({ color: 0x10b981, wireframe: true, transparent: true, opacity: 0.4 });
    const monWireMesh = new THREE.Mesh(monGeom, monWireMat);
    this.computerGroup.add(monWireMesh);

    // 2. CRT Terminal Matrix Grid Screen (Soft Emerald Green)
    const screenGeom = new THREE.PlaneGeometry(3.8, 2.7, 16, 12);
    this.screenMat = new THREE.MeshBasicMaterial({ color: 0x10b981, wireframe: true, transparent: true, opacity: 0.85 });
    this.screenMesh = new THREE.Mesh(screenGeom, this.screenMat);
    this.screenMesh.position.z = 0.51;
    this.computerGroup.add(this.screenMesh);

    const screenBgGeom = new THREE.PlaneGeometry(3.8, 2.7);
    this.screenBgMat = new THREE.MeshBasicMaterial({ color: 0x080c14, transparent: true, opacity: 0.9 });
    const screenBgMesh = new THREE.Mesh(screenBgGeom, this.screenBgMat);
    screenBgMesh.position.z = 0.505;
    this.computerGroup.add(screenBgMesh);

    // 3. Monitor Stand
    const standGeom = new THREE.BoxGeometry(1.2, 0.8, 1.2);
    const standMat = new THREE.MeshPhongMaterial({ color: 0x0f172a, emissive: 0x10b981, emissiveIntensity: 0.3, wireframe: true });
    const standMesh = new THREE.Mesh(standGeom, standMat);
    standMesh.position.set(0, -2.0, 0);
    this.computerGroup.add(standMesh);

    // 4. Tower / CPU (Muted Teal Wireframe)
    const towerGeom = new THREE.BoxGeometry(1.5, 4.2, 3.2);
    const towerMat = new THREE.MeshPhongMaterial({ color: 0x0f172a, emissive: 0x14b8a6, emissiveIntensity: 0.4, wireframe: true });
    this.towerMesh = new THREE.Mesh(towerGeom, towerMat);
    this.towerMesh.position.set(3.2, -0.2, -0.5);
    this.computerGroup.add(this.towerMesh);

    // 5. Keyboard Block
    const kbGeom = new THREE.BoxGeometry(4.0, 0.25, 1.5);
    const kbMat = new THREE.MeshBasicMaterial({ color: 0x10b981, wireframe: true });
    const kbMesh = new THREE.Mesh(kbGeom, kbMat);
    kbMesh.position.set(0, -2.3, 1.2);
    this.computerGroup.add(kbMesh);

    // 6. Cyber Laser Crack Lines (Visible during scan / failure / success)
    const crackPoints = [
      new THREE.Vector3(-1.8, 1.2, 0.52), new THREE.Vector3(-0.5, 0.2, 0.52),
      new THREE.Vector3(-0.5, 0.2, 0.52), new THREE.Vector3(0.8, 0.8, 0.52),
      new THREE.Vector3(-0.5, 0.2, 0.52), new THREE.Vector3(-0.2, -1.0, 0.52),
      new THREE.Vector3(-0.2, -1.0, 0.52), new THREE.Vector3(1.5, -0.8, 0.52),
      new THREE.Vector3(3.2, 1.5, 1.1), new THREE.Vector3(3.2, -1.5, 1.1)
    ];
    const crackGeom = new THREE.BufferGeometry().setFromPoints(crackPoints);
    this.crackMat = new THREE.LineBasicMaterial({ color: 0x10b981, transparent: true, opacity: 0, linewidth: 2 });
    this.crackLines = new THREE.LineSegments(crackGeom, this.crackMat);
    this.computerGroup.add(this.crackLines);

    // 7. Shattered Debris Fragments (For Breakdown Explosion)
    for (let f = 0; f < 28; f++) {
      const fGeom = Math.random() > 0.5 ? new THREE.TetrahedronGeometry(0.4) : new THREE.BoxGeometry(0.5, 0.5, 0.2);
      const fMat = new THREE.MeshPhongMaterial({
        color: Math.random() > 0.5 ? 0x10b981 : 0x14b8a6,
        emissive: 0x10b981,
        emissiveIntensity: 0.6,
        wireframe: true
      });
      const frag = new THREE.Mesh(fGeom, fMat);
      frag.position.set((Math.random() - 0.5) * 3, (Math.random() - 0.5) * 2, (Math.random() - 0.5) * 1);
      frag.userData = {
        origPos: frag.position.clone(),
        velocity: new THREE.Vector3((Math.random() - 0.5) * 14, (Math.random() - 0.5) * 12, (Math.random() + 0.2) * 14),
        rotSpeed: new THREE.Vector3(Math.random() * 0.3, Math.random() * 0.3, Math.random() * 0.3)
      };
      this.computerFragments.push(frag);
      this.computerGroup.add(frag);
    }

    this.authScene.add(this.computerGroup);

    // Reset Animation Variables
    this.explosionProgress = 0;
    this.targetExplosion = 0;
    this.crackProgress = 0;
    this.targetCrack = 0;
    this.burstIntensity = 2;
    this.targetBurst = 2;
    this.isAuthStageReady = true;
  }

  playAppOpeningBootAnimation(onBootComplete) {
    if (onBootComplete) onBootComplete();
  }

  triggerAuthScan() {}

  triggerAuthSuccessAnimation(onComplete) {
    if (onComplete) onComplete();
  }

  triggerAuthFailureAnimation(errorMessage) {}
  ================================================================================== */

  playAppOpeningBootAnimation(onBootComplete) {
    if (onBootComplete) onBootComplete();
  }

  triggerAuthScan() {}

  triggerAuthSuccessAnimation(onComplete) {
    if (onComplete) onComplete();
  }

  triggerAuthFailureAnimation(errorMessage) {}


  // Viewport 3D Controls
  toggleExplodedView() {
    this.isExploded = !this.isExploded;
    this.vaultNodes.forEach((node, idx) => {
      const radius = this.isExploded ? 22 + (idx % 3) * 6 : node.userData.orbitRadius || 14;
      node.position.x = Math.cos(node.userData.orbitAngle) * radius;
      node.position.z = Math.sin(node.userData.orbitAngle) * radius;
    });
  }

  toggleAutoOrbit() {
    this.isAutoOrbit = !this.isAutoOrbit;
  }

  // Camera Presets
  resetVaultCamera() {
    if (this.vaultCamera) {
      this.vaultCamera.position.set(0, 10, 32);
      this.vaultCamera.lookAt(0, 0, 0);
    }
  }

  focusVaultCore() {
    if (this.vaultCamera) {
      this.vaultCamera.position.set(0, 4, 14);
      this.vaultCamera.lookAt(0, 0, 0);
    }
  }

  topViewVault() {
    if (this.vaultCamera) {
      this.vaultCamera.position.set(0, 35, 0.1);
      this.vaultCamera.lookAt(0, 0, 0);
    }
  }
}

// Global instance
window.hmacfr3D = new HMACFR_3DEngine();
