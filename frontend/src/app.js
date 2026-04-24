/**
 * FEDERATED THREAT INTELLIGENCE - RETRO CONSOLE
 * API Integrated Frontend
 */

document.addEventListener('DOMContentLoaded', () => {
    const state = {
        currentSample: null, // This will hold the sample_id (folder name)
        currentModule: 'welcome',
        isProcessing: false,
        history: [],
        apiBase: window.location.origin.includes(':3000') 
            ? window.location.origin.replace(':3000', ':8000') 
            : window.location.origin + ':8000'
    };

    // DOM Elements
    const directoryTree = document.getElementById('directory-tree');
    const terminalContent = document.getElementById('terminal-content');
    const clearTerminalBtn = document.getElementById('clear-terminal');
    const moduleContainer = document.getElementById('module-container');
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const fileInfo = document.getElementById('file-info');
    const loadingOverlay = document.getElementById('loading-overlay');
    const statusText = document.getElementById('status-text');
    const clockElement = document.getElementById('clock');

    // --- INITIALIZATION ---

    function init() {
        updateClock();
        setInterval(updateClock, 1000);
        logToTerminal('SYSTEM READY. CONNECTED TO FTI-BACKEND (GEMINI-POWERED).');
        setupEventListeners();
    }

    function setupEventListeners() {
        // Directory Navigation
        directoryTree.addEventListener('click', (e) => {
            const item = e.target.closest('.tree-item');
            if (!item) return;

            // Handle folder toggling
            if (item.classList.contains('folder')) {
                const toggle = item.querySelector('.toggle');
                const subTree = item.querySelector('ul');
                if (subTree) {
                    const isHidden = subTree.classList.toggle('hidden');
                    toggle.textContent = isHidden ? '[+]' : '[-]';
                }
                return;
            }

            // Handle module selection
            const moduleName = item.getAttribute('data-module');
            if (moduleName) {
                console.log('Module clicked:', moduleName);
                if (moduleName === 'upload') {
                    fetchSamples(); // Fetch samples when clicking /Samples
                }
                switchModule(moduleName);
                
                // Highlight active item
                document.querySelectorAll('.tree-item').forEach(el => el.classList.remove('active'));
                item.classList.add('active');
            }
        });

        // Terminal Clear
        if (clearTerminalBtn) {
            clearTerminalBtn.addEventListener('click', () => {
                terminalContent.innerHTML = '';
                logToTerminal('TERMINAL BUFFER CLEARED.');
            });
        }

        // File Upload Handling Disabled
        /*
        dropZone.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                logToTerminal('UPLOAD DISABLED. PLEASE SELECT FROM /SAMPLES.', 'error');
            }
        });
        */
    }

    // --- CORE FUNCTIONS ---

    function updateClock() {
        const now = new Date();
        clockElement.textContent = now.toTimeString().split(' ')[0];
    }

    function logToTerminal(message, type = 'default') {
        const line = document.createElement('div');
        line.className = `line ${type}`;
        
        if (type === 'success' || type === 'error') {
            line.textContent = '> ';
            terminalContent.appendChild(line);
            let i = 0;
            const text = message.toUpperCase();
            const interval = setInterval(() => {
                line.textContent += text[i];
                i++;
                if (i >= text.length) {
                    clearInterval(interval);
                    terminalContent.scrollTop = terminalContent.scrollHeight;
                }
            }, 10);
        } else {
            line.textContent = `> ${message.toUpperCase()}`;
            terminalContent.appendChild(line);
            terminalContent.scrollTop = terminalContent.scrollHeight;
        }
    }

    function switchModule(moduleName) {
        logToTerminal(`NAVIGATING TO /${moduleName.toUpperCase()}...`);
        
        document.querySelectorAll('.module').forEach(m => m.classList.add('hidden'));
        
        const moduleMap = {
            'upload': 'upload-module',
            'hash': 'analysis-module',
            'strings': 'analysis-module',
            'pe': 'analysis-module',
            'entropy': 'analysis-module',
            'behavior': 'analysis-module',
            'network': 'analysis-module',
            'reports': 'analysis-module',
            'logs': 'welcome-module'
        };

        const moduleId = moduleMap[moduleName] || 'welcome-module';
        const moduleEl = document.getElementById(moduleId);
        if (moduleEl) {
            console.log('Activating module:', moduleId);
            moduleEl.classList.remove('hidden');
            moduleEl.classList.add('active');
            
            if (moduleId === 'analysis-module') {
                setupAnalysisUI(moduleName);
            }
            if (moduleName === 'logs') {
                downloadReport();
            }
        } else {
            console.warn('Module element not found:', moduleId);
        }

        state.currentModule = moduleName;
    }

    // --- API INTEGRATION ---

    async function fetchSamples() {
        setProcessing(true);
        logToTerminal('FETCHING MALWARE SAMPLES FROM DATA VAULT...');
        console.log('Fetching samples from:', `${state.apiBase}/samples`);
        
        try {
            const response = await fetch(`${state.apiBase}/samples`);
            if (response.ok) {
                const samples = await response.json();
                displaySampleIcons(samples);
                logToTerminal(`VAULT SYNCHRONIZED. ${samples.length} SAMPLES FOUND.`, 'success');
            } else {
                throw new Error(`SERVER ERROR: ${response.status}`);
            }
        } catch (err) {
            console.error('Fetch error:', err);
            logToTerminal('VAULT ERROR: ' + err.message, 'error');
            // Try fallback to localhost if direct access failed
            if (!state.apiBase.includes('localhost')) {
                state.apiBase = 'http://localhost:8000';
                setTimeout(fetchSamples, 100);
            }
        } finally {
            setProcessing(false);
        }
    }

    function displaySampleIcons(samples) {
        const dropZone = document.getElementById('drop-zone');
        dropZone.innerHTML = ''; // Clear drop zone
        dropZone.className = "grid grid-cols-4 gap-4 p-4";

        if (samples.length === 0) {
            dropZone.innerHTML = '<p class="col-span-4 opacity-60">NO SAMPLES FOUND IN DATA/FEATURES</p>';
            return;
        }

        samples.forEach(sampleId => {
            const icon = document.createElement('div');
            icon.className = 'sample-icon';
            const displayName = sampleId.includes('__') ? sampleId.split('__')[0] : sampleId;
            icon.innerHTML = `
                <div class="text-3xl mb-1" style="pointer-events:none">☣️</div>
                <div class="sample-name text-white" style="pointer-events:none">${displayName}</div>
            `;
            icon.onclick = () => selectSample(sampleId);
            dropZone.appendChild(icon);
        });
    }

    async function selectSample(sampleId) {
        state.currentSample = sampleId;
        logToTerminal(`SAMPLE SELECTED: ${sampleId}`, 'info');
        
        setProcessing(true);
        try {
            const response = await fetch(`${state.apiBase}/samples/${sampleId}/summary`);
            if (response.ok) {
                const data = await response.json();
                const metadata = data.metadata || {};
                
                // Update Metadata UI
                document.getElementById('info-name').textContent = metadata.binary_name || 'UNKNOWN';
                document.getElementById('info-size').textContent = metadata.size_bytes ? formatBytes(metadata.size_bytes) : 'N/A';
                document.getElementById('info-type').textContent = metadata.architecture || 'BINARY';
                document.getElementById('info-date').textContent = metadata.analysis_timestamp_utc || 'N/A';
                fileInfo.classList.remove('hidden');

                logToTerminal('THREAT SUMMARY LOADED.', 'success');
                if (data.threat) {
                    logToTerminal(`VERDICT: ${data.threat.verdict}`, 'info');
                    logToTerminal(`RISK SCORE: ${data.threat.risk_score}`, 'info');
                }

                // IMPORTANT: Refresh the current module UI if it's an analysis module
                const moduleMap = {
                    'hash': 'analysis-module',
                    'strings': 'analysis-module',
                    'pe': 'analysis-module',
                    'entropy': 'analysis-module',
                    'behavior': 'analysis-module',
                    'network': 'analysis-module',
                    'reports': 'analysis-module'
                };
                if (moduleMap[state.currentModule] === 'analysis-module') {
                    setupAnalysisUI(state.currentModule);
                }
            }
        } catch (err) {
            logToTerminal('SUMMARY ERROR: ' + err.message, 'error');
        } finally {
            setProcessing(false);
        }
    }

    function setupAnalysisUI(moduleName) {
        const title = document.getElementById('analysis-title');
        const desc = document.getElementById('analysis-desc');
        const controls = document.getElementById('analysis-controls');
        
        if (moduleName === 'strings') {
            title.textContent = `/FUNCTIONS-ANALYSIS`;
        } else {
            title.textContent = `/${moduleName.toUpperCase()}-ANALYSIS`;
        }
        controls.innerHTML = '';

        const btn = document.createElement('button');
        btn.className = 'retro-btn';
        if (moduleName === 'strings') {
            btn.textContent = `RUN FUNCTIONS SCAN`;
        } else {
            btn.textContent = `RUN ${moduleName.toUpperCase()} SCAN`;
        }
        btn.disabled = !state.currentSample;
        
        if (!state.currentSample) {
            desc.textContent = 'WARNING: NO SAMPLE SELECTED. BROWSE /SAMPLES FIRST.';
            desc.classList.add('text-[#ff4444]');
        } else {
            desc.textContent = `READY TO ANALYZE: ${state.currentSample.split('__')[0]}`;
            desc.classList.remove('text-[#ff4444]');
        }

        btn.onclick = () => runAnalysis(moduleName);
        controls.appendChild(btn);
    }

    async function runAnalysis(type) {
        if (!state.currentSample) return;
        
        setProcessing(true);
        logToTerminal(`INITIATING ${type.toUpperCase()} ANALYSIS...`);
        
        let endpoint = '';
        switch(type) {
            case 'hash': endpoint = '/analysis/static/hash'; break;
            case 'strings': endpoint = '/analysis/static/functions'; break;
            case 'entropy': endpoint = '/analysis/static/entropy'; break;
            case 'pe': endpoint = '/analysis/static/pe'; break;
            case 'behavior': endpoint = '/analysis/dynamic'; break;
            case 'network': endpoint = '/analysis/dynamic?network_only=true'; break;
            case 'reports': endpoint = '/report'; break;
            default: endpoint = '/analysis/static/hash';
        }

        const method = (type === 'reports') ? 'POST' : 'GET';

        try {
            const response = await fetch(`${state.apiBase}/samples/${state.currentSample}${endpoint}`, { method });
            if (response.ok) {
                const data = await response.json();
                displayResults(type, data);
            } else {
                throw new Error('ANALYSIS FAILED');
            }
        } catch (err) {
            logToTerminal(`${type.toUpperCase()} ERROR: ${err.message}`, 'error');
        } finally {
            setProcessing(false);
        }
    }

    function displayResults(type, data) {
        logToTerminal(`--- ${type.toUpperCase()} RESULTS ---`, 'info');
        if (Array.isArray(data)) {
            data.forEach(line => logToTerminal(line, 'success'));
        } else if (typeof data === 'object' && data !== null) {
            if (data.report) {
                // Formatting for long Gemini reports
                logToTerminal('AI REPORT GENERATED:', 'info');
                const lines = data.report.split('\n');
                lines.forEach(l => { if(l.trim()) logToTerminal(l, 'success') });
            } else {
                const flattenObject = (obj, prefix = '') => {
                    Object.entries(obj).forEach(([key, val]) => {
                        const fullKey = prefix ? `${prefix}.${key}` : key;
                        if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
                            flattenObject(val, fullKey);
                        } else if (Array.isArray(val)) {
                             logToTerminal(`${fullKey.toUpperCase()}: [ARRAY WITH ${val.length} ITEMS]`, 'info');
                             val.forEach((item, idx) => {
                                 if (typeof item === 'string') logToTerminal(`  - ${item}`, 'success');
                                 else if (typeof item === 'object') {
                                     // Special handling for function objects
                                     const name = item.function || item.name || `ITEM ${idx}`;
                                     logToTerminal(`  > ${name}`, 'success');
                                 }
                             });
                        } else {
                            logToTerminal(`${fullKey.toUpperCase()}: ${val}`, 'success');
                        }
                    });
                };
                flattenObject(data);
            }
        } else {
            logToTerminal(String(data), 'success');
        }
    }

    async function downloadReport() {
        if (!state.currentSample) {
            logToTerminal('ERROR: NO SAMPLE SELECTED. CANNOT DOWNLOAD LOGS.', 'error');
            return;
        }
        logToTerminal('PREPARING REPORT FOR DOWNLOAD...');
        window.location.href = `${state.apiBase}/samples/${state.currentSample}/download-report`;
    }

    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    function setProcessing(bool) {
        state.isProcessing = bool;
        if (loadingOverlay) loadingOverlay.classList.toggle('hidden', !bool);
        statusText.textContent = bool ? 'PROCESSING' : 'IDLE';
        statusText.className = bool ? 'text-yellow-400' : 'text-[#00aaff]';
    }

    init();
});
