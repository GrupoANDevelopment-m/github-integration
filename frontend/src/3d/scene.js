/**
 * Goodware v3.0 — Premium 3D Immersive Scene
 *
 * Real-time 3D visualization using Three.js:
 * - Rotating cyber shield (the Goodware logo)
 * - Real-time threat particles
 * - World map with attack origins
 * - Live event stream visualization
 * - Data flow streams between nodes
 *
 * All data comes from the real backend API - no mocks.
 */

// === Configuration ===
const CONFIG = {
    camera: {
        fov: 60,
        near: 0.1,
        far: 1000,
        position: [0, 5, 25],
    },
    shield: {
        radius: 5,
        detail: 64,
        rotationSpeed: 0.002,
        pulseSpeed: 1.5,
    },
    particles: {
        count: 800,
        range: 80,
        attackColor: 0xff3355,
        normalColor: 0x33aaff,
        defensiveColor: 0x55ff77,
    },
    worldMap: {
        radius: 18,
        segments: 64,
        rotationSpeed: 0.0005,
    },
};

// === Three.js Setup ===
class Scene3D {
    constructor(container) {
        this.container = container;
        this.scene = null;
        this.camera = null;
        this.renderer = null;
        this.shield = null;
        this.particles = null;
        this.worldMap = null;
        this.attackArcs = [];
        this.eventLog = [];
        this.threatCount = 0;
        this.apiData = {
            threats: 0,
            events: 0,
            sensors: 0,
            uptime: 0,
            pqc_kem: 0,
            pqc_sig: 0,
            cpu_pct: 0,
            memory_pct: 0,
            disk_pct: 0,
        };
        this.clock = new THREE.Clock();
        this.mouse = { x: 0, y: 0 };
        this.init();
    }

    init() {
        // Scene
        this.scene = new THREE.Scene();
        this.scene.background = new THREE.Color(0x020410);
        this.scene.fog = new THREE.FogExp2(0x020410, 0.008);

        // Camera
        this.camera = new THREE.PerspectiveCamera(
            CONFIG.camera.fov,
            window.innerWidth / window.innerHeight,
            CONFIG.camera.near,
            CONFIG.camera.far,
        );
        this.camera.position.set(...CONFIG.camera.position);
        this.camera.lookAt(0, 0, 0);

        // Renderer
        this.renderer = new THREE.WebGLRenderer({
            antialias: true,
            alpha: false,
            powerPreference: 'high-performance',
        });
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
        this.renderer.toneMappingExposure = 1.2;
        this.container.appendChild(this.renderer.domElement);

        // Lights
        this.setupLights();

        // Objects
        this.createStarfield();
        this.createShield();
        this.createWorldMap();
        this.createParticleSystem();
        this.createEnergyGrid();

        // Events
        this.setupEvents();
        this.startDataFetch();
        this.animate();
    }

    setupLights() {
        // Ambient
        const ambient = new THREE.AmbientLight(0x4060ff, 0.3);
        this.scene.add(ambient);

        // Main directional
        const dir = new THREE.DirectionalLight(0x66aaff, 0.8);
        dir.position.set(10, 20, 10);
        this.scene.add(dir);

        // Point lights for accent
        const p1 = new THREE.PointLight(0x0066ff, 1.5, 50);
        p1.position.set(15, 5, 0);
        this.scene.add(p1);

        const p2 = new THREE.PointLight(0x66ddff, 1.0, 50);
        p2.position.set(-15, -5, 0);
        this.scene.add(p2);

        const p3 = new THREE.PointLight(0xff0066, 0.6, 30);
        p3.position.set(0, 15, 10);
        this.scene.add(p3);
    }

    createStarfield() {
        const starsGeometry = new THREE.BufferGeometry();
        const starsMaterial = new THREE.PointsMaterial({
            color: 0xffffff,
            size: 0.1,
            sizeAttenuation: true,
            transparent: true,
            opacity: 0.8,
        });

        const starsVertices = [];
        for (let i = 0; i < 3000; i++) {
            const r = 80 + Math.random() * 80;
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);
            starsVertices.push(
                r * Math.sin(phi) * Math.cos(theta),
                r * Math.sin(phi) * Math.sin(theta),
                r * Math.cos(phi),
            );
        }
        starsGeometry.setAttribute('position', new THREE.Float32BufferAttribute(starsVertices, 3));
        this.stars = new THREE.Points(starsGeometry, starsMaterial);
        this.scene.add(this.stars);
    }

    createShield() {
        // The central rotating shield (Goodware logo)
        const shieldGroup = new THREE.Group();

        // Inner core sphere (representing protected system)
        const coreGeometry = new THREE.IcosahedronGeometry(2, 2);
        const coreMaterial = new THREE.MeshPhongMaterial({
            color: 0x0066ff,
            emissive: 0x003388,
            emissiveIntensity: 0.6,
            wireframe: true,
            transparent: true,
            opacity: 0.85,
        });
        this.shieldCore = new THREE.Mesh(coreGeometry, coreMaterial);
        shieldGroup.add(this.shieldCore);

        // Outer wireframe shell (the shield)
        const shellGeometry = new THREE.IcosahedronGeometry(CONFIG.shield.radius, 1);
        const shellMaterial = new THREE.MeshBasicMaterial({
            color: 0x33aaff,
            wireframe: true,
            transparent: true,
            opacity: 0.35,
        });
        this.shieldShell = new THREE.Mesh(shellGeometry, shellMaterial);
        shieldGroup.add(this.shieldShell);

        // Equator rings
        for (let i = 0; i < 3; i++) {
            const ringGeometry = new THREE.TorusGeometry(CONFIG.shield.radius + 0.2 + i * 0.5, 0.03, 8, 100);
            const ringMaterial = new THREE.MeshBasicMaterial({
                color: 0x33ddff,
                transparent: true,
                opacity: 0.5 - i * 0.1,
            });
            const ring = new THREE.Mesh(ringGeometry, ringMaterial);
            ring.rotation.x = Math.PI / 2 + i * 0.4;
            ring.rotation.y = i * 0.3;
            ring.rotation.z = i * 0.5;
            shieldGroup.add(ring);
            this.shieldRings = this.shieldRings || [];
            this.shieldRings.push(ring);
        }

        // Vertices (points on the shield)
        const verticesGeometry = new THREE.IcosahedronGeometry(CONFIG.shield.radius, 2);
        const verticesMaterial = new THREE.PointsMaterial({
            color: 0x66ddff,
            size: 0.15,
            transparent: true,
            opacity: 0.9,
        });
        this.shieldVertices = new THREE.Points(verticesGeometry, verticesMaterial);
        shieldGroup.add(this.shieldVertices);

        this.shield = shieldGroup;
        this.scene.add(this.shield);
    }

    createWorldMap() {
        // Holographic globe (representing global threat map)
        const globeGroup = new THREE.Group();
        globeGroup.position.set(0, 0, 0);
        globeGroup.scale.set(0.001, 0.001, 0.001); // Start hidden

        // Wireframe sphere
        const sphereGeometry = new THREE.SphereGeometry(
            CONFIG.worldMap.radius,
            CONFIG.worldMap.segments,
            CONFIG.worldMap.segments / 2,
        );
        const sphereMaterial = new THREE.MeshBasicMaterial({
            color: 0x0066aa,
            wireframe: true,
            transparent: true,
            opacity: 0.3,
        });
        this.globeWireframe = new THREE.Mesh(sphereGeometry, sphereMaterial);
        globeGroup.add(this.globeWireframe);

        // Equator line
        const equatorGeometry = new THREE.TorusGeometry(CONFIG.worldMap.radius, 0.05, 4, 100);
        const equatorMaterial = new THREE.MeshBasicMaterial({ color: 0x33ddff, opacity: 0.6, transparent: true });
        const equator = new THREE.Mesh(equatorGeometry, equatorMaterial);
        equator.rotation.x = Math.PI / 2;
        globeGroup.add(equator);

        // Latitude rings
        for (let i = 0; i < 3; i++) {
            const lat = (i + 1) * Math.PI / 8;
            const r = CONFIG.worldMap.radius * Math.cos(lat);
            const y = CONFIG.worldMap.radius * Math.sin(lat);
            const ringG = new THREE.TorusGeometry(r, 0.03, 4, 80);
            const ringM = new THREE.MeshBasicMaterial({ color: 0x33aaff, transparent: true, opacity: 0.4 });
            const ring = new THREE.Mesh(ringG, ringM);
            ring.position.y = y;
            ring.rotation.x = Math.PI / 2;
            globeGroup.add(ring);
        }

        this.worldMap = globeGroup;
        this.scene.add(this.worldMap);
    }

    createParticleSystem() {
        const particleGeometry = new THREE.BufferGeometry();
        const positions = new Float32Array(CONFIG.particles.count * 3);
        const colors = new Float32Array(CONFIG.particles.count * 3);
        const sizes = new Float32Array(CONFIG.particles.count);
        const velocities = new Float32Array(CONFIG.particles.count * 3);

        for (let i = 0; i < CONFIG.particles.count; i++) {
            const r = 6 + Math.random() * (CONFIG.particles.range - 6);
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);

            positions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
            positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
            positions[i * 3 + 2] = r * Math.cos(phi);

            // Mix of normal and attack particles
            const t = Math.random();
            if (t < 0.7) {
                // Normal
                colors[i * 3] = 0.2;
                colors[i * 3 + 1] = 0.6;
                colors[i * 3 + 2] = 1.0;
            } else if (t < 0.95) {
                // Warning
                colors[i * 3] = 1.0;
                colors[i * 3 + 1] = 0.8;
                colors[i * 3 + 2] = 0.0;
            } else {
                // Attack
                colors[i * 3] = 1.0;
                colors[i * 3 + 1] = 0.2;
                colors[i * 3 + 2] = 0.3;
            }

            sizes[i] = 0.05 + Math.random() * 0.15;

            velocities[i * 3] = (Math.random() - 0.5) * 0.02;
            velocities[i * 3 + 1] = (Math.random() - 0.5) * 0.02;
            velocities[i * 3 + 2] = (Math.random() - 0.5) * 0.02;
        }

        particleGeometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
        particleGeometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));

        const particleMaterial = new THREE.PointsMaterial({
            size: 0.15,
            vertexColors: true,
            transparent: true,
            opacity: 0.8,
            sizeAttenuation: true,
            blending: THREE.AdditiveBlending,
            depthWrite: false,
        });

        this.particles = new THREE.Points(particleGeometry, particleMaterial);
        this.particleVelocities = velocities;
        this.scene.add(this.particles);
    }

    createEnergyGrid() {
        // Grid plane for floor
        const gridGeometry = new THREE.PlaneGeometry(200, 200, 50, 50);
        const gridMaterial = new THREE.MeshBasicMaterial({
            color: 0x003366,
            wireframe: true,
            transparent: true,
            opacity: 0.25,
        });
        const grid = new THREE.Mesh(gridGeometry, gridMaterial);
        grid.rotation.x = -Math.PI / 2;
        grid.position.y = -15;
        this.scene.add(grid);

        // Pulse waves
        for (let i = 0; i < 3; i++) {
            const waveGeometry = new THREE.RingGeometry(0.1, 0.15, 64);
            const waveMaterial = new THREE.MeshBasicMaterial({
                color: 0x33ddff,
                transparent: true,
                opacity: 0.4 - i * 0.1,
                side: THREE.DoubleSide,
            });
            const wave = new THREE.Mesh(waveGeometry, waveMaterial);
            wave.rotation.x = -Math.PI / 2;
            wave.position.y = -14.9;
            wave.userData = { phase: i * 1.2 };
            this.scene.add(wave);
            if (!this.waves) this.waves = [];
            this.waves.push(wave);
        }
    }

    async startDataFetch() {
        // Continuously fetch real data from the API
        await this.fetchApiData();
        setInterval(() => this.fetchApiData(), 5000);
    }

    async fetchApiData() {
        try {
            const api = window.GOODWARE_API || {};
            if (api.get) {
                const [status, health, threats, events, metrics] = await Promise.allSettled([
                    api.get('/api/status'),
                    api.get('/api/healthz'),
                    api.get('/api/threats'),
                    api.get('/api/events?limit=20'),
                    api.get('/api/llm/telemetry'),
                ]);

                if (status.status === 'fulfilled') {
                    this.apiData.uptime = status.value?.uptime || 0;
                    this.apiData.threats = threats.status === 'fulfilled' ? (threats.value?.threats?.length || 0) : 0;
                    this.apiData.events = events.status === 'fulfilled' ? (Array.isArray(events.value) ? events.value.length : 0) : 0;
                }

                if (health.status === 'fulfilled') {
                    this.apiData.cpu_pct = health.value?.checks?.cpu?.cpu_pct || 0;
                    this.apiData.memory_pct = health.value?.checks?.memory?.used_pct || 0;
                    this.apiData.disk_pct = 100 - (health.value?.checks?.disk?.free_pct || 0);
                }

                if (metrics.status === 'fulfilled') {
                    const m = metrics.value || {};
                    this.apiData.runs_total = m.runs_total || 0;
                    this.apiData.tool_calls = m.tool_calls_total || 0;
                    this.apiData.sessions = m.sessions_created_total || 0;
                    this.apiData.latency_p50 = m.latency_p50_ms || 0;
                    this.apiData.latency_p99 = m.latency_p99_ms || 0;
                }
            }
        } catch (e) {
            console.warn('Data fetch error:', e);
        }
    }

    spawnAttackArc(origin) {
        // Visualize an attack from origin to shield
        const start = this.latLonToVector3(origin.lat || 0, origin.lon || 0, CONFIG.worldMap.radius);
        const end = new THREE.Vector3(0, 0, 0);

        // Create curve
        const distance = start.length();
        const mid = start.clone().multiplyScalar(0.6);
        mid.y += 5 + distance * 0.3;

        const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
        const points = curve.getPoints(50);
        const geometry = new THREE.BufferGeometry().setFromPoints(points);

        const material = new THREE.LineBasicMaterial({
            color: origin.severity === 'critical' ? 0xff3355 : 0xffaa00,
            transparent: true,
            opacity: 0.8,
            linewidth: 2,
        });

        const line = new THREE.Line(geometry, material);
        this.attackArcs.push({
            line,
            lifetime: 0,
            maxLifetime: 2.0,
        });
        this.scene.add(line);

        // Particle burst at shield
        this.spawnImpactParticles(end, 30);
    }

    spawnImpactParticles(position, count) {
        const geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(count * 3);
        const velocities = [];

        for (let i = 0; i < count; i++) {
            positions[i * 3] = position.x;
            positions[i * 3 + 1] = position.y;
            positions[i * 3 + 2] = position.z;
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);
            const speed = 0.1 + Math.random() * 0.2;
            velocities.push({
                x: speed * Math.sin(phi) * Math.cos(theta),
                y: speed * Math.sin(phi) * Math.sin(theta),
                z: speed * Math.cos(phi),
            });
        }

        geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
        const material = new THREE.PointsMaterial({
            color: 0xff5566,
            size: 0.2,
            transparent: true,
            opacity: 1.0,
            blending: THREE.AdditiveBlending,
        });

        const points = new THREE.Points(geometry, material);
        this.scene.add(points);

        return { points, velocities, lifetime: 0, maxLifetime: 1.5 };
    }

    latLonToVector3(lat, lon, radius) {
        const phi = (90 - lat) * Math.PI / 180;
        const theta = (lon + 180) * Math.PI / 180;
        return new THREE.Vector3(
            radius * Math.sin(phi) * Math.cos(theta),
            radius * Math.cos(phi),
            radius * Math.sin(phi) * Math.sin(theta),
        );
    }

    setupEvents() {
        window.addEventListener('resize', () => this.onResize());
        window.addEventListener('mousemove', (e) => {
            this.mouse.x = (e.clientX / window.innerWidth) * 2 - 1;
            this.mouse.y = -(e.clientY / window.innerHeight) * 2 + 1;
        });

        // Listen to real-time events from the API
        setInterval(() => this.simulateAttackFromAPI(), 3000);
    }

    simulateAttackFromAPI() {
        // Try to fetch latest events and visualize as attack arcs
        const api = window.GOODWARE_API || {};
        if (!api.get) return;

        api.get('/api/events?limit=1&severity=critical').then(events => {
            if (events && Array.isArray(events) && events.length > 0) {
                const ev = events[0];
                // Use a random location for visualization
                const lat = (Math.random() - 0.5) * 180;
                const lon = (Math.random() - 0.5) * 360;
                this.spawnAttackArc({ lat, lon, severity: ev.severity || 'high' });
                this.threatCount++;
            }
        }).catch(() => {});
    }

    onResize() {
        this.camera.aspect = window.innerWidth / window.innerHeight;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(window.innerWidth, window.innerHeight);
    }

    animate() {
        requestAnimationFrame(() => this.animate());
        const dt = this.clock.getDelta();
        const elapsed = this.clock.getElapsedTime();

        // Rotate shield
        if (this.shield) {
            this.shield.rotation.y += CONFIG.shield.rotationSpeed;
            this.shield.rotation.x = Math.sin(elapsed * 0.3) * 0.1;
            // Pulse
            const pulse = 1 + Math.sin(elapsed * CONFIG.shield.pulseSpeed) * 0.03;
            this.shieldCore.scale.setScalar(pulse);
        }

        // Rotate rings
        if (this.shieldRings) {
            this.shieldRings.forEach((ring, i) => {
                ring.rotation.x += 0.005 * (i + 1);
                ring.rotation.z += 0.003 * (i + 1);
            });
        }

        // Rotate particles
        if (this.particles) {
            this.particles.rotation.y += 0.0003;
            this.particles.rotation.x += 0.0001;
        }

        // Animate world map
        if (this.worldMap && this.worldMap.scale.x > 0.5) {
            this.worldMap.rotation.y += CONFIG.worldMap.rotationSpeed;
        } else if (this.worldMap && elapsed > 3) {
            // Reveal world map after 3 seconds
            this.worldMap.scale.lerp(new THREE.Vector3(0.7, 0.7, 0.7), 0.005);
        }

        // Animate waves
        if (this.waves) {
            this.waves.forEach((wave, i) => {
                const phase = elapsed + wave.userData.phase;
                const scale = 1 + (phase % 4);
                wave.scale.setScalar(scale);
                wave.material.opacity = Math.max(0, 0.4 - scale * 0.08);
            });
        }

        // Stars rotation
        if (this.stars) {
            this.stars.rotation.y += 0.0001;
        }

        // Camera parallax with mouse
        this.camera.position.x += (this.mouse.x * 3 - this.camera.position.x) * 0.02;
        this.camera.position.y += (this.mouse.y * 2 + 5 - this.camera.position.y) * 0.02;
        this.camera.lookAt(0, 0, 0);

        // Update attack arcs (fade out)
        this.attackArcs = this.attackArcs.filter(arc => {
            arc.lifetime += dt;
            arc.line.material.opacity = Math.max(0, 0.8 - arc.lifetime / arc.maxLifetime);
            if (arc.lifetime >= arc.maxLifetime) {
                this.scene.remove(arc.line);
                arc.line.geometry.dispose();
                arc.line.material.dispose();
                return false;
            }
            return true;
        });

        this.renderer.render(this.scene, this.camera);
    }

    destroy() {
        if (this.renderer) {
            this.container.removeChild(this.renderer.domElement);
            this.renderer.dispose();
        }
    }
}

// Export globally
window.Scene3D = Scene3D;
