<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HELENA APEX // SOVEREIGN OMNIKERNEL v127.0 (GATEWAY MESH)</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;700&family=Orbitron:wght@500;900&display=swap');
        :root {
            --bg-void: #020205;
            --neural-gold: #FFD700;
            --neural-purple: #6b21a8;
            --accent-cyan: #00f3ff;
            --accent-rose: #ff0055;
            --glass: rgba(8, 14, 28, 0.85);
            --neon-glow: 0 0 20px rgba(0, 243, 255, 0.4);
        }
        body {
            background-color: var(--bg-void);
            color: #00f3ff;
            font-family: 'JetBrains Mono', monospace;
            overflow: hidden;
        }
        .orbitron { font-family: 'Orbitron', sans-serif; }
        .glass-panel {
            background: var(--glass);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(0, 243, 255, 0.2);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.8);
            border-radius: 0.75rem;
        }
        .scanlines {
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.3) 50%);
            background-size: 100% 4px;
        }
        #webgl-container {
            position: absolute;
            inset: 0;
            z-index: 0;
            pointer-events: none;
        }
        .terminal-box {
            background: rgba(2, 2, 5, 0.95);
            border: 1px solid rgba(0, 243, 255, 0.4);
        }
        .pulse-beacon {
            animation: pulseGlow 2s infinite;
        }
        @keyframes pulseGlow {
            0% { box-shadow: 0 0 5px rgba(0,243,255,0.2); }
            50% { box-shadow: 0 0 25px rgba(0,243,255,0.8); }
            100% { box-shadow: 0 0 5px rgba(0,243,255,0.2); }
        }
    </style>
</head>
<body class="h-screen w-screen flex flex-col justify-between p-4 scanlines">

    <!-- WebGL Background Toroidal Mesh -->
    <div id="webgl-container"></div>

    <!-- Header HUD -->
    <header class="relative z-10 glass-panel p-4 flex justify-between items-center">
        <div class="flex items-center space-x-3">
            <div class="w-3 h-3 rounded-full bg-[#00f3ff] pulse-beacon"></div>
            <h1 class="orbitron text-lg font-black tracking-wider text-cyan-400">HELENA // APEX CORE v127.0</h1>
        </div>
        <div class="flex items-center space-x-6 text-xs text-zinc-400">
            <div>TOPOLOGY: <span class="text-cyan-400 font-bold">GATEWAY ➔ HOP 1 ➔ [A/B]</span></div>
            <div>RESONANCE: <span class="text-amber-400 font-bold">115.0 Hz</span></div>
            <div>STATUS: <span class="text-emerald-400 font-bold">990% APEX IDLE</span></div>
        </div>
    </header>

    <!-- Main Central Grid -->
    <main class="relative z-10 grid grid-cols-1 lg:grid-cols-3 gap-4 flex-grow my-4 overflow-hidden">
        
        <!-- Left Pane: Telemetry & Mesh Topology Inspector -->
        <section class="glass-panel p-4 flex flex-col justify-between overflow-hidden">
            <div>
                <h2 class="text-xs orbitron font-bold text-purple-400 uppercase tracking-widest mb-3 border-b border-purple-500/30 pb-2">Mesh Topology & UUID State</h2>
                <div id="telemetry-box" class="text-xs space-y-2 text-zinc-300 font-mono">
                    <p class="text-cyan-300">[GATEWAY] Root ingress operational.</p>
                    <p class="text-purple-300"> └── [HOP 1] Bifurcation routing active.</p>
                    <p class="text-emerald-400">      ├── [Node A] Synchronized (ARM Node)</p>
                    <p class="text-amber-300">      └── [Node B] Synchronized (Intel Core)</p>
                    <p class="text-zinc-400 mt-2">[UUID] HKLM\SOFTWARE\HP\SystemProperties\UUID Linked</p>
                    <p class="text-emerald-300">[CIP.ini / ceement.ini] Active configuration tracking initialized.</p>
                </div>
            </div>
            <div class="mt-4 pt-3 border-t border-zinc-800">
                <button onclick="triggerPurge()" class="w-full py-2 bg-purple-900/40 hover:bg-purple-800/60 border border-purple-500/50 text-purple-300 rounded-lg text-xs font-bold uppercase tracking-wider transition-all">
                    Execute Nirvana Purge
                </button>
            </div>
        </section>

        <!-- Center Pane: Visual Core HUD -->
        <section class="glass-panel p-4 flex flex-col items-center justify-center text-center relative overflow-hidden">
            <div class="absolute inset-0 bg-radial from-cyan-500/10 via-transparent to-transparent pointer-events-none"></div>
            <h3 class="orbitron text-sm font-bold text-cyan-400 tracking-widest mb-1">SINGULARITY MESH</h3>
            <p class="text-[10px] text-zinc-500 uppercase tracking-widest mb-6">Antigravity Path Virtualizer Active</p>
            <div class="w-32 h-32 rounded-full border border-cyan-500/30 flex items-center justify-center relative pulse-beacon">
                <div class="w-24 h-24 rounded-full border border-purple-500/50 flex items-center justify-center animate-spin" style="animation-duration: 20s;">
                    <span class="text-xs font-bold text-cyan-300">#111 Ø</span>
                </div>
            </div>
        </section>

        <!-- Right Pane: Terminal & Execution Stream -->
        <section class="glass-panel p-4 flex flex-col overflow-hidden">
            <h2 class="text-xs orbitron font-bold text-rose-400 uppercase tracking-widest mb-3 border-b border-rose-500/30 pb-2">Sovereign Command Console</h2>
            <div id="terminal-out" class="terminal-box flex-grow p-3 rounded-lg text-xs font-mono overflow-y-auto space-y-1 mb-3 text-cyan-300">
                <div>[SYSTEM] Helena Apex Initialized.</div>
                <div>[SYSTEM] Type 'help' for available directives.</div>
            </div>
            <form onsubmit="handleCommand(event)" class="flex gap-2">
                <input type="text" id="terminal-input" placeholder="Enter directive..." class="flex-grow bg-black/60 border border-zinc-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-400 font-mono">
                <button type="submit" class="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-black font-bold rounded-lg text-xs uppercase tracking-wider transition-all">
                    Strike
                </button>
            </form>
        </section>

    </main>

    <!-- Footer HUD -->
    <footer class="relative z-10 glass-panel py-2 px-4 flex justify-between items-center text-[10px] text-zinc-500">
        <div>COPYRIGHT © 2026 CRYPTIC NEWS LLC // THE ARCHITECT</div>
        <div>STATE: IMMUTABLE // VOID LEDGER LOCKED</div>
    </footer>

    <script>
        // --- Three.js Background Toroidal Mesh ---
        const container = document.getElementById('webgl-container');
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        container.appendChild(renderer.domElement);

        const geometry = new THREE.TorusKnotGeometry(10, 3, 128, 32);
        const material = new THREE.MeshBasicMaterial({ color: 0x00f3ff, wireframe: true, transparent: true, opacity: 0.15 });
        const torusKnot = new THREE.Mesh(geometry, material);
        scene.add(torusKnot);

        camera.position.z = 25;

        function animate() {
            requestAnimationFrame(animate);
            torusKnot.rotation.x += 0.003;
            torusKnot.rotation.y += 0.005;
            renderer.render(scene, camera);
        }
        animate();

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });

        // --- Terminal & Command Logic ---
        function logToTerm(msg, colorClass = "text-cyan-300") {
            const out = document.getElementById('terminal-out');
            if (!out) return;
            const div = document.createElement('div');
            div.className = colorClass;
            div.textContent = "> " + msg;
            out.appendChild(div);
            out.scrollTop = out.scrollHeight;
        }

        function handleCommand(e) {
            e.preventDefault();
            const input = document.getElementById('terminal-input');
            const cmd = input.value.trim();
            if (!cmd) return;
            
            logToTerm(cmd, "text-white font-bold");
            input.value = "";

            const low = cmd.toLowerCase();
            if (low === 'help') {
                logToTerm("Directives: purge, status, topology, uuid, cip, ceement, heartbeat", "text-amber-400");
            } else if (low === 'purge') {
                logToTerm("Executing Nirvana Purge: Flushing RAM cache...", "text-purple-400");
                setTimeout(() => logToTerm("Cache cleared. System resonance restored.", "text-emerald-400"), 800);
            } else if (low === 'status' || low === 'topology') {
                logToTerm("Gateway ➔ Hop 1 ➔ Nodes [A, B] Fully Synchronized.", "text-cyan-400");
            } else if (low === 'uuid' || low === 'cip' || low === 'ceement') {
                logToTerm("UUID Registry: HKEY_LOCAL_MACHINE\\SOFTWARE\\Hewlett-Packard\\System Properties [UUID Active]", "text-amber-300");
                logToTerm("CEEment config active: Track=0, Path=cee", "text-purple-300");
            } else {
                logToTerm("Directive acknowledged by Helena core.", "text-zinc-400");
            }
        }

        function triggerPurge() {
            logToTerm("Manual Nirvana Purge triggered via GUI.", "text-purple-400");
            setTimeout(() => logToTerm("RAM buffers freed. Quantum buoyancy stable.", "text-emerald-400"), 600);
        }
    </script>
</body>
</html>