// BharatPOS - Core Logic Script

// Initialize Application State
let appState = {
    currentUser: null,
    business: {
        name: 'Ramesh Bakery',
        upiId: 'ramesh@okaxis',
        phone: '+91 98765 43210',
        address: 'Indiranagar, Bengaluru',
        gstin: ''
    },
    customer: {
        name: '',
        phone: '',
        invoiceNo: 'BR-1001',
        date: new Date().toISOString().split('T')[0] // Default to today
    },
    items: [
        { id: 'default-1', name: 'Chocolate Truffle Cake - 1kg', price: 650.00, purchasePrice: 450.00, qty: 1, unit: 'pcs' },
        { id: 'default-2', name: 'Pineapple Pastry', price: 80.00, purchasePrice: 50.00, qty: 2, unit: 'pcs' },
        { id: 'default-3', name: 'Garlic Bread (Loaf)', price: 90.00, purchasePrice: 60.00, qty: 1, unit: 'pcs' }
    ],
    gstRate: 0,
    discountAmt: 0,
    discountType: 'flat',
    roundOffActive: 'yes',
    editingItemId: null,
    inventory: [],
    editingInventoryProductId: null,
    history: [],
    language: 'en',
    analyticsFilter: {
        preset: 'last7',
        startDate: '',
        endDate: ''
    }
};

// Global QRious Instance
let qrInstance = null;

// ==========================================
// Cryptographic Storage Helper Functions
// ==========================================
let activeEncryptionKey = null;

// Convert Hex string to Uint8Array bytes
function hexToBytes(hex) {
    if (!hex) return new Uint8Array(0);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

// Derive AES-GCM 256-bit key from password + salt via PBKDF2
async function deriveKey(password, saltHex) {
    if (!window.crypto || !window.crypto.subtle) {
        console.warn('Web Crypto API is not available (non-secure context). Using fallback key derivation.');
        return { isFallback: true, password, saltHex };
    }
    
    const saltBytes = hexToBytes(saltHex);
    const passwordBuffer = new TextEncoder().encode(password);
    
    // Import raw password as key material
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
    );
    
    // Derive AES-GCM 256-bit key
    return await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: saltBytes,
            iterations: 1000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true, // exportable to allow sessionStorage backup
        ['encrypt', 'decrypt']
    );
}

// Export CryptoKey to Base64 string for sessionStorage persistence
async function exportKeyToBase64(key) {
    if (key && key.isFallback) {
        return btoa(JSON.stringify(key));
    }
    const exported = await window.crypto.subtle.exportKey('raw', key);
    // Convert array buffer to binary string
    const binary = String.fromCharCode.apply(null, new Uint8Array(exported));
    return btoa(binary);
}

// Import CryptoKey from Base64 string
async function importKeyFromBase64(base64Key) {
    try {
        const decoded = atob(base64Key);
        if (decoded.includes('"isFallback"')) {
            return JSON.parse(decoded);
        }
    } catch (e) {
        // Not a JSON fallback, continue standard
    }

    if (!window.crypto || !window.crypto.subtle) {
        return { isFallback: true, dummy: true };
    }

    const binary = atob(base64Key);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return await window.crypto.subtle.importKey(
        'raw',
        bytes,
        { name: 'AES-GCM' },
        true,
        ['encrypt', 'decrypt']
    );
}

// Encrypt plain text using AES-GCM key
async function encryptData(plainText, key) {
    if (key && key.isFallback) {
        // Simple XOR encryption fallback with key password for local file:// mode
        const pwd = key.password || 'fallback';
        let result = '';
        for (let i = 0; i < plainText.length; i++) {
            result += String.fromCharCode(plainText.charCodeAt(i) ^ pwd.charCodeAt(i % pwd.length));
        }
        return 'FALLBACK:' + btoa(unescape(encodeURIComponent(result)));
    }

    const encoded = new TextEncoder().encode(plainText);
    // Generate random 12-byte Initialization Vector (IV)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const cipherBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encoded
    );
    
    // Combine IV + CipherText into single binary payload
    const combined = new Uint8Array(iv.length + cipherBuffer.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(cipherBuffer), iv.length);
    
    // Convert to Base64 string
    const binary = String.fromCharCode.apply(null, combined);
    return btoa(binary);
}

// Decrypt cipher text using AES-GCM key
async function decryptData(cipherBase64, key) {
    if (cipherBase64 && cipherBase64.startsWith('FALLBACK:')) {
        const actualCipher = cipherBase64.substring(9);
        const decodedBinary = decodeURIComponent(escape(atob(actualCipher)));
        const pwd = (key && key.password) || 'fallback';
        let result = '';
        for (let i = 0; i < decodedBinary.length; i++) {
            result += String.fromCharCode(decodedBinary.charCodeAt(i) ^ pwd.charCodeAt(i % pwd.length));
        }
        return result;
    }

    const binary = atob(cipherBase64);
    const combined = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        combined[i] = binary.charCodeAt(i);
    }
    
    const iv = combined.slice(0, 12);
    const cipherText = combined.slice(12);
    
    const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        cipherText
    );
    return new TextDecoder().decode(decrypted);
}

// Show login form overlay and clear workspace state
function showLoginFormDirectly() {
    document.getElementById('authOverlay').style.display = 'flex';
    document.body.classList.add('auth-active');
    document.getElementById('userHeaderBadge').style.display = 'none';
    document.getElementById('logoutBtn').style.display = 'none';

    // Load clean state
    appState.currentUser = null;
    appState.business = { name: '', upiId: '', phone: '', address: '' };
    appState.customer = { name: '', phone: '', invoiceNo: 'BR-1001', date: new Date().toISOString().split('T')[0] };
    appState.items = [
        { id: 'default-1', name: 'Chocolate Truffle Cake - 1kg', price: 650.00, purchasePrice: 450.00, qty: 1, unit: 'pcs' },
        { id: 'default-2', name: 'Pineapple Pastry', price: 80.00, purchasePrice: 50.00, qty: 2, unit: 'pcs' },
        { id: 'default-3', name: 'Garlic Bread (Loaf)', price: 90.00, purchasePrice: 60.00, qty: 1, unit: 'pcs' }
    ];
    appState.discountAmt = 0;
    appState.discountType = 'flat';
    appState.totals = { subtotal: 0, gstAmount: 0, discount: 0, grandTotal: 0 };
    appState.history = [];
    appState.inventory = [];

    initFormDefaults();
    autoSetNextInvoiceNumber();
    renderInventory();
    calculateInvoice();

    // Check if there are any registered accounts on this site.
    // If not, default to the 'register' tab to guide the user.
    try {
        const accountsData = localStorage.getItem('bharatpos_accounts');
        const accounts = accountsData ? JSON.parse(accountsData) : [];
        if (accounts.length === 0) {
            switchAuthTab('register');
        } else {
            switchAuthTab('login');
        }
    } catch (e) {
        console.error('Error reading accounts on DOMContentLoaded:', e);
        switchAuthTab('register');
    }
}

// Migrate legacy "vyaparflow_" namespace keys in localStorage to "bharatpos_" namespace
function migrateLocalStorageNamespace() {
    try {
        const localKeys = Object.keys(localStorage);
        localKeys.forEach(key => {
            if (key && key.startsWith('vyaparflow_')) {
                const newKey = key.replace('vyaparflow_', 'bharatpos_');
                if (!localStorage.getItem(newKey)) {
                    localStorage.setItem(newKey, localStorage.getItem(key));
                }
            }
        });
        const sessionKeys = Object.keys(sessionStorage);
        sessionKeys.forEach(key => {
            if (key && key.startsWith('vyaparflow_')) {
                const newKey = key.replace('vyaparflow_', 'bharatpos_');
                if (!sessionStorage.getItem(newKey)) {
                    sessionStorage.setItem(newKey, sessionStorage.getItem(key));
                }
            }
        });
    } catch (e) {
        console.error('Namespace migration error:', e);
    }
}

// DOM Elements Initialization
document.addEventListener('DOMContentLoaded', () => {
    // Run storage namespace migration
    migrateLocalStorageNamespace();

    // Setup Event Listeners
    setupEventListeners();

    // Load global language setting
    appState.language = localStorage.getItem('bharatpos_global_language') || 'en';
    const langSel = document.getElementById('languageSelector');
    if (langSel) {
        langSel.value = appState.language;
    }
    applyTranslations();

    // Initialize Admin Alerts/Broadcasts Monitoring
    initBroadcastMonitoring();

    // Check if user session exists and key is in sessionStorage
    const savedUser = localStorage.getItem('bharatpos_current_user');
    const sessionKey = sessionStorage.getItem('bharatpos_session_key');
    
    if (savedUser && sessionKey) {
        // Restore session key and complete login
        importKeyFromBase64(sessionKey).then(key => {
            activeEncryptionKey = key;
            completeLogin(savedUser);
        }).catch(err => {
            console.error('Session key restoration failed:', err);
            // Session key is corrupted or expired, clear user state
            localStorage.removeItem('bharatpos_current_user');
            sessionStorage.removeItem('bharatpos_session_key');
            activeEncryptionKey = null;
            showLoginFormDirectly();
        });
    } else {
        // Missing active key/user, show login overlay directly
        localStorage.removeItem('bharatpos_current_user');
        sessionStorage.removeItem('bharatpos_session_key');
        activeEncryptionKey = null;
        showLoginFormDirectly();
    }
    
    // Register PWA Service Worker (only on live production domains to prevent local development caching)
    if ('serviceWorker' in navigator && !window.location.hostname.includes('localhost') && !window.location.hostname.includes('127.0.0.1')) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('./sw.js')
                .then(reg => {
                    console.log('[PWA] Service Worker registered successfully on scope:', reg.scope);
                    
                    // Check for updates on load
                    if (reg.waiting) {
                        showUpdateToast(reg);
                    }

                    // Listen for updates in progress
                    reg.addEventListener('updatefound', () => {
                        const newWorker = reg.installing;
                        if (newWorker) {
                            newWorker.addEventListener('statechange', () => {
                                if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                                    showUpdateToast(reg);
                                }
                            });
                        }
                    });
                })
                .catch(err => console.warn('[PWA] Service Worker registration failed:', err));

            // Prevent multiple reloads
            let refreshing = false;
            navigator.serviceWorker.addEventListener('controllerchange', () => {
                if (!refreshing) {
                    refreshing = true;
                    window.location.reload();
                }
            });
        });
    }

// Show a premium toast notification when a PWA update is available
function showUpdateToast(registration) {
    if (document.getElementById('pwaUpdateToast')) return;

    const toast = document.createElement('div');
    toast.id = 'pwaUpdateToast';
    toast.className = 'pwa-update-toast';
    toast.innerHTML = `
        <div class="toast-body">
            <div class="toast-icon">
                <i data-lucide="sparkles"></i>
            </div>
            <div class="toast-text">
                <strong>New Version Available</strong>
                <span>Update to get the latest features.</span>
            </div>
            <button id="btnApplyUpdate" class="btn btn-emerald btn-sm">Refresh</button>
        </div>
    `;
    document.body.appendChild(toast);

    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    document.getElementById('btnApplyUpdate').addEventListener('click', () => {
        if (registration.waiting) {
            registration.waiting.postMessage({ action: 'skipWaiting' });
        } else {
            window.location.reload();
        }
    });
}
    
    // Initialize Lucide Icons
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }


});

// Setup form defaults from state
function initFormDefaults() {
    // Business Inputs
    document.getElementById('bizName').value = appState.business.name;
    document.getElementById('bizUpi').value = appState.business.upiId;
    document.getElementById('bizPhone').value = appState.business.phone;
    document.getElementById('bizAddress').value = appState.business.address;
    document.getElementById('bizGstin').value = appState.business.gstin || '';

    // Customer & Invoice Inputs
    document.getElementById('custName').value = appState.customer.name;
    document.getElementById('custPhone').value = appState.customer.phone;
    document.getElementById('invNumber').value = appState.customer.invoiceNo;
    document.getElementById('invDate').value = appState.customer.date;

    // Financial Controls
    document.getElementById('gstRate').value = appState.gstRate;
    document.getElementById('discountAmt').value = appState.discountAmt || '';
    if (document.getElementById('discountType')) {
        document.getElementById('discountType').value = appState.discountType || 'flat';
    }
    if (document.getElementById('paymentMode')) {
        document.getElementById('paymentMode').value = appState.paymentMode || 'upi';
    }
    if (document.getElementById('roundOffActive')) {
        document.getElementById('roundOffActive').value = appState.roundOffActive || 'yes';
    }
}

// Attach Event Listeners
function setupEventListeners() {
    ['bizName', 'bizUpi', 'bizPhone', 'bizAddress', 'bizGstin'].forEach(id => {
        document.getElementById(id).addEventListener('input', (e) => {
            const field = id.replace('biz', '').toLowerCase();
            let key = field;
            if (field === 'name') key = 'name';
            else if (field === 'upi') key = 'upiId';
            else if (field === 'phone') key = 'phone';
            else if (field === 'address') key = 'address';
            else if (field === 'gstin') key = 'gstin';
            
            appState.business[key] = e.target.value;
            saveBusinessProfile();
            updatePreview();
        });
    });

    // Customer & Invoice Inputs
    ['custName', 'custPhone', 'invNumber', 'invDate'].forEach(id => {
        document.getElementById(id).addEventListener('input', (e) => {
            const field = id.replace('cust', '').replace('inv', '').toLowerCase();
            let key = field;
            if (id === 'custName') key = 'name';
            else if (id === 'custPhone') {
                key = 'phone';
                e.target.value = e.target.value.replace(/\D/g, '');
                
                // CRM Phone Autocomplete Name Look Up
                const val = e.target.value;
                if (val.length === 10) {
                    const matched = appState.history.find(inv => inv.customerPhone === val);
                    if (matched) {
                        appState.customer.name = matched.customerName;
                        document.getElementById('custName').value = matched.customerName;
                    }
                }
            } else if (id === 'invNumber') key = 'invoiceNo';
            else if (id === 'invDate') key = 'date';
            
            if (id.startsWith('cust')) {
                appState.customer[key] = e.target.value;
            } else {
                appState.customer[key] = e.target.value;
            }
            updatePreview();
        });
    });

    // Add Item Click
    document.getElementById('addItemBtn').addEventListener('click', addLineItem);
    
    // Add Item Keyboard Enter
    ['newItemName', 'newItemPrice', 'newItemQty'].forEach(id => {
        document.getElementById(id).addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                addLineItem();
            }
        });
    });

    // Financial Inputs
    document.getElementById('gstRate').addEventListener('change', (e) => {
        appState.gstRate = parseFloat(e.target.value) || 0;
        calculateInvoice();
    });
    document.getElementById('discountAmt').addEventListener('input', (e) => {
        const val = parseFloat(e.target.value);
        appState.discountAmt = isNaN(val) ? 0 : val;
        calculateInvoice();
    });
    if (document.getElementById('discountType')) {
        document.getElementById('discountType').addEventListener('change', (e) => {
            calculateInvoice();
        });
    }
    if (document.getElementById('paymentMode')) {
        document.getElementById('paymentMode').addEventListener('change', (e) => {
            appState.paymentMode = e.target.value;
            updatePreview();
        });
    }
    if (document.getElementById('roundOffActive')) {
        document.getElementById('roundOffActive').addEventListener('change', (e) => {
            appState.roundOffActive = e.target.value;
            calculateInvoice();
        });
    }

    // Button Actions
    document.getElementById('whatsappShareBtn').addEventListener('click', shareViaWhatsApp);
    document.getElementById('copyUpiBtn').addEventListener('click', copyUpiPaymentLink);
    document.getElementById('printBtn').addEventListener('click', () => {
        const invNo = appState.customer.invoiceNo || 'N/A';
        generateInvoicePdf(invNo);
    });
    document.getElementById('saveInvoiceBtn').addEventListener('click', saveInvoiceToHistory);
    document.getElementById('newInvoiceBtn').addEventListener('click', startNewInvoice);
    document.getElementById('cancelEditBtn').addEventListener('click', cancelEditItem);
    document.getElementById('exportExcelBtn').addEventListener('click', exportLedgerToExcel);
    
    document.getElementById('addProdBtn').addEventListener('click', addProductToInventory);
    document.getElementById('cancelProdEditBtn').addEventListener('click', cancelEditProduct);
    
    if (document.getElementById('btnApplyRefill')) {
        document.getElementById('btnApplyRefill').addEventListener('click', () => {
            const refillInput = document.getElementById('prodRefillBoxes');
            const pcsPerBoxInput = document.getElementById('prodPcsPerBox');
            const stockInput = document.getElementById('prodStock');
            
            const boxes = parseFloat(refillInput.value) || 0;
            const pcsPerBox = parseFloat(pcsPerBoxInput.value) || 1;
            
            if (boxes > 0) {
                const currentStock = parseFloat(stockInput.value) || 0;
                const refilledPcs = boxes * pcsPerBox;
                stockInput.value = (currentStock + refilledPcs).toFixed(2).replace(/\.00$/, '');
                refillInput.value = '';
                alert(`Added ${refilledPcs} pcs (${boxes} boxes of ${pcsPerBox} pcs) to Stock. Total: ${stockInput.value} pcs.`);
            } else {
                alert('Please enter a valid number of boxes to refill.');
                refillInput.focus();
            }
        });
    }
    
    document.getElementById('newItemName').addEventListener('input', (e) => {
        const val = e.target.value.trim();
        const matched = appState.inventory.find(item => item.name.toLowerCase() === val.toLowerCase());
        if (matched) {
            document.getElementById('newItemPrice').value = matched.price;
            const unitSelect = document.getElementById('newItemUnit');
            if (unitSelect && matched.unit) {
                unitSelect.value = matched.unit;
            }
            document.getElementById('newItemQty').focus();
        }
    });

    ['prodName', 'prodPrice', 'prodSku'].forEach(id => {
        document.getElementById(id).addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                addProductToInventory();
            }
        });
    });

    // Admin Excel Actions
    document.getElementById('downloadTemplateBtn').addEventListener('click', downloadExcelTemplate);
    if (document.getElementById('exportStockExcelBtn')) {
        document.getElementById('exportStockExcelBtn').addEventListener('click', exportStockReportToExcel);
    }
    
    const dropZone = document.getElementById('excelDropZone');
    const fileInput = document.getElementById('excelFileInput');

    dropZone.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', handleExcelUpload);

    // Drag and Drop handlers
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    ['dragleave', 'drop'].forEach(evtName => {
        dropZone.addEventListener(evtName, (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
        });
    });

    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            fileInput.files = files;
            // Create a fake event object
            handleExcelUpload({ target: fileInput });
        }
    });

    // Theme Toggle
    document.getElementById('themeToggle').addEventListener('click', toggleTheme);

    // Search Inputs Event Listeners
    const searchLineItems = document.getElementById('searchLineItemsInput');
    if (searchLineItems) {
        searchLineItems.addEventListener('input', filterLineItems);
    }
    const searchInventory = document.getElementById('searchInventoryInput');
    if (searchInventory) {
        searchInventory.addEventListener('input', filterInventory);
    }
    const searchHistory = document.getElementById('searchHistoryInput');
    if (searchHistory) {
        searchHistory.addEventListener('input', filterHistory);
    }
    const ledgerStartDate = document.getElementById('ledgerStartDate');
    const ledgerEndDate = document.getElementById('ledgerEndDate');
    if (ledgerStartDate) {
        ledgerStartDate.addEventListener('change', filterHistory);
    }
    if (ledgerEndDate) {
        ledgerEndDate.addEventListener('change', filterHistory);
    }
    
    // Logout Button
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);

    // Hamburger Menu and Overlay Toggle
    const menuToggle = document.getElementById('menuToggle');
    const appSidebar = document.getElementById('appSidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    
    if (menuToggle && appSidebar && sidebarOverlay) {
        menuToggle.addEventListener('click', () => {
            if (window.innerWidth >= 1024) {
                // On desktop, toggle sidebar collapse
                const appMain = document.querySelector('.app-main');
                if (appMain) {
                    appMain.classList.toggle('sidebar-collapsed');
                }
            } else {
                // On mobile, toggle sidebar drawer
                appSidebar.classList.toggle('sidebar-open');
                sidebarOverlay.classList.toggle('active');
            }
        });
        
        sidebarOverlay.addEventListener('click', () => {
            appSidebar.classList.remove('sidebar-open');
            sidebarOverlay.classList.remove('active');
        });
    }

    // Receipt format toggle formatting handler
    const receiptFormatSelect = document.getElementById('receiptFormat');
    if (receiptFormatSelect) {
        receiptFormatSelect.addEventListener('change', (e) => {
            const receipt = document.getElementById('printableReceipt');
            if (receipt) {
                if (e.target.value === 'thermal') {
                    receipt.classList.add('receipt-format-thermal');
                } else {
                    receipt.classList.remove('receipt-format-thermal');
                }
            }
        });
    }

    // Reset inactivity timer on any interaction events
    ['mousemove', 'mousedown', 'keypress', 'touchstart', 'scroll'].forEach(evt => {
        document.addEventListener(evt, resetInactivityTimer);
    });

    // Language selector change listener
    const langSelector = document.getElementById('languageSelector');
    if (langSelector) {
        langSelector.addEventListener('change', (e) => {
            const lang = e.target.value;
            appState.language = lang;
            localStorage.setItem('bharatpos_global_language', lang);
            if (appState.currentUser) {
                localStorage.setItem(`bharatpos_${appState.currentUser.toLowerCase()}_language`, lang);
            }
            applyTranslations();
        });
    }

    // Analytics Date Presets & Custom inputs
    const presetSelect = document.getElementById('analyticsDatePreset');
    if (presetSelect) {
        presetSelect.addEventListener('change', (e) => {
            const val = e.target.value;
            appState.analyticsFilter.preset = val;
            
            const customDates = document.getElementById('analyticsCustomDates');
            if (customDates) {
                customDates.style.display = val === 'custom' ? 'flex' : 'none';
            }
            
            renderAnalytics();
        });
    }
    
    ['analyticsStartDate', 'analyticsEndDate'].forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            input.addEventListener('change', () => {
                if (appState.analyticsFilter.preset === 'custom') {
                    appState.analyticsFilter.startDate = document.getElementById('analyticsStartDate').value;
                    appState.analyticsFilter.endDate = document.getElementById('analyticsEndDate').value;
                    renderAnalytics();
                }
            });
        }
    });

    // Drill-down search input
    const drilldownSearchInput = document.getElementById('drilldownSearch');
    if (drilldownSearchInput) {
        drilldownSearchInput.addEventListener('input', (e) => {
            renderDrilldownTable(activeDrilldownInvoices, activeDrilldownType, null, e.target.value);
        });
    }

    // Init chart click events
    initAnalyticsEvents();
}

// Collapsible Panels Toggle
function toggleCard(cardId) {
    const card = document.getElementById(cardId);
    card.classList.toggle('collapsed');
}

// Sidebar navigation view switcher
function switchWorkspaceView(viewId) {
    // Hide all views
    const views = document.querySelectorAll('.workspace-view');
    views.forEach(view => {
        view.classList.remove('active-view');
    });

    // Show selected view
    const targetView = document.getElementById(viewId);
    if (targetView) {
        targetView.classList.add('active-view');
    }

    // Render Canvas Sales Analytics when opening Analytics view
    if (viewId === 'viewAnalytics') {
        setTimeout(renderAnalytics, 50);
    }

    // Reset active nav item highlights
    const navItems = document.querySelectorAll('.nav-item, .nav-subitem');
    navItems.forEach(item => {
        item.classList.remove('active');
    });

    // Find and highlight matching nav item in sidebar
    let targetNavItemId = '';
    if (viewId === 'viewBilling') targetNavItemId = 'navBilling';
    else if (viewId === 'viewAnalytics') targetNavItemId = 'navAnalytics';
    else if (viewId === 'viewProfile') targetNavItemId = 'navProfile';
    else if (viewId === 'viewInventory') targetNavItemId = 'navInventory';
    else if (viewId === 'viewAdmin') targetNavItemId = 'navAdmin';


    const targetNavItem = document.getElementById(targetNavItemId);
    if (targetNavItem) {
        targetNavItem.classList.add('active');
        
        // If it's a subitem, ensure the parent group is open/active
        const parentGroup = targetNavItem.closest('.nav-group');
        if (parentGroup) {
            parentGroup.classList.add('active');
        }
    }

    // On mobile, close sidebar drawer
    const sidebar = document.getElementById('appSidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (sidebar && overlay) {
        sidebar.classList.remove('sidebar-open');
        overlay.classList.remove('active');
    }
}

// Toggle Collapsible Sub-menus in Sidebar
function toggleSubmenu(menuId) {
    const group = document.getElementById(menuId);
    if (group) {
        group.classList.toggle('active');
    }
}

// Add / Save Item Logic
function addLineItem() {
    const nameInput = document.getElementById('newItemName');
    const priceInput = document.getElementById('newItemPrice');
    const qtyInput = document.getElementById('newItemQty');
    const unitInput = document.getElementById('newItemUnit');

    const name = nameInput.value.trim();
    const price = parseFloat(priceInput.value);
    const qty = parseFloat(qtyInput.value);
    const unit = unitInput ? unitInput.value : 'pcs';

    if (!name) {
        alert('Please enter an item description.');
        nameInput.focus();
        return;
    }
    if (isNaN(price) || price <= 0) {
        alert('Please enter a valid price greater than 0.');
        priceInput.focus();
        return;
    }
    if (isNaN(qty) || qty <= 0) {
        alert('Please enter a valid quantity greater than 0.');
        qtyInput.focus();
        return;
    }

    // Live Stock Validation Warning Check
    const matchedProduct = appState.inventory.find(p => p.name.toLowerCase() === name.toLowerCase());
    if (matchedProduct) {
        if (qty > matchedProduct.stock) {
            if (!confirm(t('low_stock_warning', matchedProduct.stock, matchedProduct.unit || 'pcs', name, qty))) {
                qtyInput.focus();
                return;
            }
        }
    }

    let purchasePrice = 0;
    if (matchedProduct) {
        purchasePrice = matchedProduct.purchasePrice || 0;
    }

    if (appState.editingItemId) {
        // Editing existing item
        const itemIndex = appState.items.findIndex(item => item.id === appState.editingItemId);
        if (itemIndex > -1) {
            appState.items[itemIndex].name = name;
            appState.items[itemIndex].price = price;
            appState.items[itemIndex].purchasePrice = purchasePrice;
            appState.items[itemIndex].qty = qty;
            appState.items[itemIndex].unit = unit;
        }
        
        // Reset Edit State
        appState.editingItemId = null;
        
        // Reset Button UI
        const addBtn = document.getElementById('addItemBtn');
        addBtn.innerHTML = '<i data-lucide="plus"></i> Add';
        addBtn.className = 'btn btn-secondary';
        document.getElementById('cancelEditBtn').style.display = 'none';
        
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    } else {
        // Adding new item
        const item = {
            id: Date.now().toString(),
            name: name,
            price: price,
            purchasePrice: purchasePrice,
            qty: qty,
            unit: unit
        };
        appState.items.push(item);
    }

    // Reset Inputs
    nameInput.value = '';
    priceInput.value = '';
    qtyInput.value = '1';
    if (unitInput) unitInput.value = 'pcs';
    nameInput.focus();

    // Recalculate
    calculateInvoice();
}

// Edit Item Logic
function editLineItem(itemId) {
    const item = appState.items.find(item => item.id === itemId);
    if (!item) return;

    // Load details into inputs
    document.getElementById('newItemName').value = item.name;
    document.getElementById('newItemPrice').value = item.price;
    document.getElementById('newItemQty').value = item.qty;
    if (document.getElementById('newItemUnit')) {
        document.getElementById('newItemUnit').value = item.unit || 'pcs';
    }

    // Set Editing ID
    appState.editingItemId = itemId;

    // Update Add Button to Save
    const addBtn = document.getElementById('addItemBtn');
    addBtn.innerHTML = '<i data-lucide="save"></i> Save';
    addBtn.className = 'btn btn-emerald'; // visually signal active editing
    document.getElementById('cancelEditBtn').style.display = 'inline-block';

    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    document.getElementById('newItemName').focus();
    
    // Trigger render to show highlight
    calculateInvoice();
}

// Cancel Edit Logic
function cancelEditItem() {
    // Clear input fields
    document.getElementById('newItemName').value = '';
    document.getElementById('newItemPrice').value = '';
    document.getElementById('newItemQty').value = '1';
    if (document.getElementById('newItemUnit')) {
        document.getElementById('newItemUnit').value = 'pcs';
    }

    // Clear Edit State
    appState.editingItemId = null;

    // Reset Button UI
    const addBtn = document.getElementById('addItemBtn');
    addBtn.innerHTML = '<i data-lucide="plus"></i> Add';
    addBtn.className = 'btn btn-secondary';
    document.getElementById('cancelEditBtn').style.display = 'none';

    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    calculateInvoice();
}

// Remove Item Logic
function removeLineItem(itemId) {
    if (appState.editingItemId === itemId) {
        cancelEditItem();
    }
    appState.items = appState.items.filter(item => item.id !== itemId);
    calculateInvoice();
}

// Adjust Line Item Quantity inline
function adjustLineItemQty(itemId, change) {
    const item = appState.items.find(i => i.id === itemId);
    if (item) {
        const newQty = item.qty + change;
        if (newQty <= 0) {
            removeLineItem(itemId);
        } else {
            item.qty = parseFloat(newQty.toFixed(3));
            calculateInvoice();
        }
    }
}

// Calculations and UI Updates
function calculateInvoice() {
    let subtotal = 0;
    
    // Clear and build Items Table (Inputs side)
    const itemsBody = document.getElementById('itemsBody');
    itemsBody.innerHTML = '';

    if (appState.items.length === 0) {
        itemsBody.innerHTML = `
            <tr class="empty-state-row">
                <td colspan="5" class="text-center text-muted">${t('no_items_added')}</td>
            </tr>
        `;
    } else {
        appState.items.forEach(item => {
            const itemTotal = item.price * item.qty;
            subtotal += itemTotal;

            const row = document.createElement('tr');
            if (appState.editingItemId === item.id) {
                row.className = 'editing-row-highlight';
            }
            row.innerHTML = `
                <td><strong>${escapeHtml(item.name)}</strong></td>
                <td class="text-right">₹${item.price.toFixed(2)}</td>
                <td class="text-center">
                    <div class="inline-qty-control">
                        <button type="button" class="btn-qty-adjust decrease" onclick="adjustLineItemQty('${item.id}', -1)" aria-label="Decrease quantity">
                            <i data-lucide="minus"></i>
                        </button>
                        <span class="qty-display">${item.qty} ${item.unit || 'pcs'}</span>
                        <button type="button" class="btn-qty-adjust increase" onclick="adjustLineItemQty('${item.id}', 1)" aria-label="Increase quantity">
                            <i data-lucide="plus"></i>
                        </button>
                    </div>
                </td>
                <td class="text-right">₹${itemTotal.toFixed(2)}</td>
                <td class="text-center">
                    <div class="action-cell">
                        <button class="btn-table-action" onclick="editLineItem('${item.id}')" aria-label="Edit item">
                            <i data-lucide="edit-3"></i>
                        </button>
                        <button class="btn-table-action delete" onclick="removeLineItem('${item.id}')" aria-label="Delete item">
                            <i data-lucide="trash-2"></i>
                        </button>
                    </div>
                </td>
            `;
            itemsBody.appendChild(row);
        });
        
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    }

    // Calculations
    const gstAmount = (subtotal * appState.gstRate) / 100;
    const discountType = document.getElementById('discountType') ? document.getElementById('discountType').value : 'flat';
    appState.discountType = discountType;

    // Apply strict validation / clamping to the input element and value
    const discountAmtInput = document.getElementById('discountAmt');
    if (discountAmtInput) {
        if (appState.discountAmt < 0) {
            appState.discountAmt = 0;
            discountAmtInput.value = '';
        }
        if (discountType === 'percent') {
            discountAmtInput.max = '100';
            if (appState.discountAmt > 100) {
                appState.discountAmt = 100;
                discountAmtInput.value = '100';
            }
        } else {
            discountAmtInput.removeAttribute('max');
        }
    }

    let discount = appState.discountAmt;
    if (discountType === 'percent') {
        discount = (subtotal * appState.discountAmt) / 100;
    }
    const grandTotalVal = Math.max(0, subtotal + gstAmount - discount);
    
    // Check if Round Off is enabled
    const roundOffActiveSelect = document.getElementById('roundOffActive');
    const roundOffActive = roundOffActiveSelect ? roundOffActiveSelect.value === 'yes' : (appState.roundOffActive !== 'no');
    
    let grandTotal = grandTotalVal;
    let roundOff = 0;
    
    if (roundOffActive) {
        grandTotal = Math.round(grandTotalVal);
        roundOff = grandTotal - grandTotalVal;
    }

    // Keep references in State
    appState.totals = {
        subtotal,
        gstAmount,
        discount, // Absolute calculated discount
        discountInput: appState.discountAmt,
        discountType,
        roundOff,
        grandTotal
    };

    // Update Live UI Preview
    updatePreview();

    // Re-apply search filter for line items
    filterLineItems();
}

// Update the Digital Invoice Receipt Preview Pane
function updatePreview() {
    // Business Details
    document.getElementById('previewBizName').innerText = appState.business.name || 'Your Business Name';
    document.getElementById('previewBizAddress').innerText = appState.business.address || '';
    document.getElementById('previewBizPhone').innerText = appState.business.phone || '';

    const previewBizGstin = document.getElementById('previewBizGstin');
    if (previewBizGstin) {
        if (appState.business.gstin) {
            previewBizGstin.innerText = `GSTIN/VAT: ${appState.business.gstin}`;
            previewBizGstin.style.display = 'block';
        } else {
            previewBizGstin.style.display = 'none';
        }
    }

    // Customer / Invoice Details
    document.getElementById('previewInvNo').innerText = `#${appState.customer.invoiceNo || 'INV-000'}`;
    
    // Date formatting (e.g. 12 Jun 2026)
    if (appState.customer.date) {
        const options = { year: 'numeric', month: 'short', day: 'numeric' };
        const formattedDate = new Date(appState.customer.date).toLocaleDateString('en-IN', options);
        document.getElementById('previewInvDate').innerText = formattedDate;
    } else {
        document.getElementById('previewInvDate').innerText = '---';
    }

    document.getElementById('previewCustName').innerText = appState.customer.name || 'Customer Name';
    document.getElementById('previewCustPhone').innerText = appState.customer.phone ? `+91 ${appState.customer.phone}` : '';

    // Receipt Line Items
    const receiptBody = document.getElementById('receiptItemsBody');
    receiptBody.innerHTML = '';

    if (appState.items.length === 0) {
        receiptBody.innerHTML = `
            <tr>
                <td colspan="4" class="text-center text-muted" style="padding: 2rem 0;">No items added yet.</td>
            </tr>
        `;
    } else {
        appState.items.forEach(item => {
            const itemTotal = item.price * item.qty;
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${escapeHtml(item.name)}</td>
                <td class="text-right">₹${item.price.toFixed(2)}</td>
                <td class="text-center">${item.qty} ${item.unit || 'pcs'}</td>
                <td class="text-right">₹${itemTotal.toFixed(2)}</td>
            `;
            receiptBody.appendChild(row);
        });
    }

    // Totals Panel
    const totals = appState.totals || { subtotal: 0, gstAmount: 0, discount: 0, grandTotal: 0 };
    document.getElementById('previewSubtotal').innerText = `₹${totals.subtotal.toFixed(2)}`;
    
    // GST Label split CGST & SGST compliant (conditional on admin config)
    const cgstRow = document.getElementById('previewCgstRow');
    const sgstRow = document.getElementById('previewSgstRow');
    
    const storedConfig = localStorage.getItem('bharatpos_admin_config');
    const config = storedConfig ? JSON.parse(storedConfig) : {};
    const gstSplitActive = config.gstSplit !== false;
    
    if (appState.gstRate > 0) {
        if (gstSplitActive) {
            const splitRate = (appState.gstRate / 2).toFixed(1).replace(/\.0$/, '');
            const splitAmount = totals.gstAmount / 2;
            
            if (cgstRow) {
                cgstRow.style.display = 'flex';
                cgstRow.querySelector('span:first-child').innerText = `CGST (${splitRate}%)`;
                document.getElementById('previewCgst').innerText = `₹${splitAmount.toFixed(2)}`;
            }
            if (sgstRow) {
                sgstRow.style.display = 'flex';
                sgstRow.querySelector('span:first-child').innerText = `SGST (${splitRate}%)`;
                document.getElementById('previewSgst').innerText = `₹${splitAmount.toFixed(2)}`;
            }
        } else {
            // Combined single GST line
            if (cgstRow) {
                cgstRow.style.display = 'flex';
                cgstRow.querySelector('span:first-child').innerText = `GST (${appState.gstRate}%)`;
                document.getElementById('previewCgst').innerText = `₹${totals.gstAmount.toFixed(2)}`;
            }
            if (sgstRow) {
                sgstRow.style.display = 'none';
            }
        }
    } else {
        if (cgstRow) cgstRow.style.display = 'none';
        if (sgstRow) sgstRow.style.display = 'none';
    }

    // Discount
    const discountRow = document.getElementById('previewDiscountRow');
    if (totals.discount > 0) {
        discountRow.style.display = 'flex';
        document.getElementById('previewDiscount').innerText = `-₹${totals.discount.toFixed(2)}`;
        
        // Dynamically update the Discount label to reflect percentage or flat type
        const discountLabelSpan = discountRow.querySelector('span:first-child');
        if (discountLabelSpan) {
            const isGu = appState.language === 'gu';
            const type = totals.discountType || 'flat';
            const inputVal = totals.discountInput !== undefined ? totals.discountInput : appState.discountAmt;
            if (type === 'percent') {
                discountLabelSpan.innerText = isGu ? `ડિસ્કાઉન્ટ (${inputVal}%)` : `Discount (${inputVal}%)`;
            } else {
                discountLabelSpan.innerText = isGu ? 'ડિસ્કાઉન્ટ' : 'Discount';
            }
        }
    } else {
        discountRow.style.display = 'none';
    }

    // Round Off
    const roundOffRow = document.getElementById('previewRoundOffRow');
    if (roundOffRow) {
        if (totals.roundOff && Math.abs(totals.roundOff) >= 0.01) {
            roundOffRow.style.display = 'flex';
            const sign = totals.roundOff > 0 ? '+' : '-';
            document.getElementById('previewRoundOff').innerText = `${sign}₹${Math.abs(totals.roundOff).toFixed(2)}`;
        } else {
            roundOffRow.style.display = 'none';
        }
    }

    document.getElementById('previewGrandTotal').innerText = `₹${totals.grandTotal.toFixed(2)}`;
    document.getElementById('previewUpiId').innerText = appState.business.upiId || 'not-set@upi';

    // Generate UPI URL & QR Code
    updateUpiPaymentDetails();
}

// Generate UPI Payment Link & QR
function updateUpiPaymentDetails() {
    const upiId = appState.business.upiId ? appState.business.upiId.trim() : '';
    const bizName = appState.business.name ? appState.business.name.trim() : 'Merchant';
    const amount = appState.totals ? appState.totals.grandTotal : 0;
    const invNo = appState.customer.invoiceNo ? appState.customer.invoiceNo.trim() : 'INV';

    if (!upiId) {
        // Render dummy QR code if UPI VPA is missing
        renderQrCode('Please enter a valid UPI ID in Business Profile.');
        return;
    }

    // Construct standard UPI deep link
    // Specs: upi://pay?pa=recipient@upi&pn=RecipientName&am=Amount&tn=TransactionNote&cu=INR
    const upiUrl = `upi://pay?pa=${encodeURIComponent(upiId)}&pn=${encodeURIComponent(bizName)}&am=${amount.toFixed(2)}&tn=${encodeURIComponent(invNo)}&cu=INR`;
    
    // Save generated deep link back in appState
    appState.upiUrl = upiUrl;

    // Render QR
    renderQrCode(upiUrl);
}

// QR Code Canvas Renderer using QRious
function renderQrCode(dataString) {
    const canvas = document.getElementById('qrCanvas');
    const qrImg = document.getElementById('qrImg');
    if (!canvas) return;

    if (window.QRious) {
        try {
            if (!qrInstance) {
                qrInstance = new QRious({
                    element: canvas,
                    value: dataString,
                    size: 180,
                    background: '#ffffff',
                    foreground: '#0f172a',
                    level: 'M'
                });
            } else {
                qrInstance.set({
                    value: dataString
                });
            }
            
            // Update image source for reliable cloning/PDF generation
            if (qrImg) {
                qrImg.src = canvas.toDataURL('image/png');
            }
        } catch (e) {
            console.error('Error generating QR code:', e);
        }
    }
}

// Copy UPI Payment String
function copyUpiPaymentLink() {
    if (!appState.upiUrl) {
        alert('Please complete the Business Profile (UPI ID) first.');
        return;
    }
    
    navigator.clipboard.writeText(appState.upiUrl)
        .then(() => {
            alert('UPI payment link copied to clipboard!');
        })
        .catch(err => {
            console.error('Failed to copy text: ', err);
            // Fallback
            const textarea = document.createElement('textarea');
            textarea.value = appState.upiUrl;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            alert('UPI payment link copied to clipboard!');
        });
}

// Create and Dispatch WhatsApp Message Link
function shareViaWhatsApp() {
    const custPhone = appState.customer.phone ? appState.customer.phone.trim() : '';
    const custName = appState.customer.name ? appState.customer.name.trim() : 'Customer';
    const bizName = appState.business.name ? appState.business.name.trim() : 'Our business';
    const totals = appState.totals || { grandTotal: 0 };
    const invNo = appState.customer.invoiceNo || 'N/A';

    if (!custPhone || custPhone.length !== 10) {
        alert(t('invalid_phone'));
        document.getElementById('custPhone').focus();
        return;
    }

    if (!appState.business.upiId) {
        alert(t('set_upi'));
        document.getElementById('businessCard').classList.remove('collapsed');
        document.getElementById('bizUpi').focus();
        return;
    }

    if (appState.items.length === 0) {
        alert(t('add_one_item'));
        document.getElementById('newItemName').focus();
        return;
    }

    // Build structured emojis message
    const isGu = appState.language === 'gu';
    let message = isGu ? `🧾 *${bizName.toUpperCase()} તરફથી ઇન્વોઇસ*\n` : `🧾 *INVOICE FROM ${bizName.toUpperCase()}*\n`;
    message += `------------------------------------\n`;
    message += isGu ? `*ઇન્વોઇસ નં:* #${invNo}\n` : `*Invoice No:* #${invNo}\n`;
    message += isGu ? `*તારીખ:* ${appState.customer.date}\n` : `*Date:* ${appState.customer.date}\n`;
    message += isGu ? `*ગ્રાહક:* ${custName}\n\n` : `*Billed To:* ${custName}\n\n`;

    message += isGu ? `*વસ્તુઓ:*\n` : `*Items:*\n`;
    appState.items.forEach((item, index) => {
        message += `${index + 1}. ${item.name} (x${item.qty} ${item.unit || 'pcs'}) - ₹${(item.price * item.qty).toFixed(2)}\n`;
    });
    
    message += `\n`;
    if (appState.gstRate > 0) {
        message += isGu ? `*પેટા સરવાળો:* ₹${totals.subtotal.toFixed(2)}\n` : `*Subtotal:* ₹${totals.subtotal.toFixed(2)}\n`;
        message += `*GST (${appState.gstRate}%):* ₹${totals.gstAmount.toFixed(2)}\n`;
    }
    if (totals.discount > 0) {
        const type = totals.discountType || 'flat';
        const inputVal = totals.discountInput !== undefined ? totals.discountInput : appState.discountAmt;
        if (type === 'percent') {
            message += isGu ? `*ડિસ્કાઉન્ટ (${inputVal}%):* -₹${totals.discount.toFixed(2)}\n` : `*Discount (${inputVal}%):* -₹${totals.discount.toFixed(2)}\n`;
        } else {
            message += isGu ? `*ડિસ્કાઉન્ટ:* -₹${totals.discount.toFixed(2)}\n` : `*Discount:* -₹${totals.discount.toFixed(2)}\n`;
        }
    }
    if (totals.roundOff && Math.abs(totals.roundOff) >= 0.01) {
        const sign = totals.roundOff > 0 ? '+' : '-';
        message += isGu ? `*રાઉન્ડ ઓફ:* ${sign}₹${Math.abs(totals.roundOff).toFixed(2)}\n` : `*Round Off:* ${sign}₹${Math.abs(totals.roundOff).toFixed(2)}\n`;
    }
    message += isGu ? `*કુલ રકમ: ₹${totals.grandTotal.toFixed(2)}*\n` : `*Grand Total: ₹${totals.grandTotal.toFixed(2)}*\n`;
    message += `------------------------------------\n\n`;
    
    message += isGu ? `⚡ *UPI દ્વારા ત્વરિત ચૂકવણી કરો:* \n` : `⚡ *Pay instantly via UPI:* \n`;
    message += isGu ? `સીધા ચૂકવવા માટે આ લિંક પર ક્લિક કરો: ${appState.upiUrl}\n\n` : `Click this link to pay directly: ${appState.upiUrl}\n\n`;
    message += isGu ? `(કૃપા કરીને ઉપર ડાઉનલોડ કરેલ પીડીએફ ફાઇલ મોકલો)\n\n` : `(Please find the PDF invoice document attached above)\n\n`;
    message += isGu ? `અમારી સાથે ખરીદી કરવા બદલ આભાર! 🙏` : `Thank you for your business! 🙏`;

    // Construct WhatsApp Send Link
    const waUrl = `https://wa.me/91${custPhone}?text=${encodeURIComponent(message)}`;
    
    // Open WhatsApp in new window immediately to prevent popup blocker blocking it
    window.open(waUrl, '_blank');

    // Trigger PDF download
    generateInvoicePdf(invNo);

    // Notify user to attach the PDF
    setTimeout(() => {
        alert(t('whatsapp_opening', invNo));
    }, 500);
}

// Generate and Download beautiful A4 PDF invoice (White background, high contrast)
function generateInvoicePdf(invoiceNo) {
    const originalElement = document.getElementById('printableReceipt');
    if (!originalElement || typeof html2pdf === 'undefined') {
        alert('PDF library not loaded yet. Please check your internet connection.');
        return;
    }

    // 1. Clone the receipt element to avoid parent grid/sticky styles causing blank canvas outputs.
    // Since qrImg is an image element with a data URL src, it clones perfectly with its content.
    const clonedElement = originalElement.cloneNode(true);
    clonedElement.classList.add('pdf-export-mode');
    
    // Position it using 'fixed' at the top-left of the viewport so that the browser layouts and paints it
    // immediately, regardless of current page scroll position. Keep z-index at -9999 so it remains hidden.
    clonedElement.style.position = 'fixed';
    clonedElement.style.left = '0';
    clonedElement.style.top = '0';
    clonedElement.style.zIndex = '-9999';
    clonedElement.style.width = '790px'; // explicitly define width for proper rendering scale
    clonedElement.style.visibility = 'visible'; // must be visible to be captured by html2canvas
    clonedElement.style.display = 'block';
    
    document.body.appendChild(clonedElement);

    // Setup pdf configurations
    const opt = {
        margin:       [0.4, 0.4, 0.4, 0.4],
        filename:     `Invoice_${invoiceNo}.pdf`,
        image:        { type: 'jpeg', quality: 0.98 },
        html2canvas:  { 
            scale: 2, 
            useCORS: true, 
            logging: false,
            letterRendering: true,
            scrollX: 0, // Critical: Prevent blank pages due to scrolling offset
            scrollY: 0  // Critical: Prevent blank pages due to scrolling offset
        },
        jsPDF:        { unit: 'in', format: 'a4', orientation: 'portrait' }
    };

    // 3. Wait 150ms before triggering the PDF builder to give the browser time to lay out and paint the new element.
    setTimeout(() => {
        html2pdf().set(opt).from(clonedElement).save().then(() => {
            // Cleanup cloned element from body
            document.body.removeChild(clonedElement);
        }).catch(err => {
            console.error('PDF generation error:', err);
            if (clonedElement.parentNode) {
                document.body.removeChild(clonedElement);
            }
        });
    }, 150);
}

// Invoice Ledger & History Saving
function saveInvoiceToHistory() {
    if (!appState.business.upiId) {
        alert(t('complete_profile'));
        return;
    }
    if (appState.items.length === 0) {
        alert(t('add_items'));
        return;
    }
    if (!appState.customer.name) {
        alert(t('enter_cust_name'));
        document.getElementById('custName').focus();
        return;
    }

    const paymentModeSelect = document.getElementById('paymentMode');
    const paymentMode = paymentModeSelect ? paymentModeSelect.value : 'upi';

    const newInvoice = {
        id: Date.now().toString(),
        invoiceNo: appState.customer.invoiceNo,
        date: appState.customer.date,
        customerName: appState.customer.name,
        customerPhone: appState.customer.phone,
        items: [...appState.items],
        totals: { ...appState.totals },
        gstRate: appState.gstRate,
        paymentMode: paymentMode,
        roundOffActive: appState.roundOffActive || 'yes',
        status: paymentMode === 'cash' || paymentMode === 'card' ? 'Paid' : 'Pending'
    };

    // Check for duplicates, replace if matches ID, else push
    const existingIndex = appState.history.findIndex(inv => inv.invoiceNo === newInvoice.invoiceNo);
    if (existingIndex > -1) {
        const oldInvoice = appState.history[existingIndex];
        if (confirm(t('confirm_overwrite_invoice', newInvoice.invoiceNo))) {
            // Restore stock of old invoice items first to prevent duplicate deduction
            if (oldInvoice && oldInvoice.status !== 'Refunded' && oldInvoice.items) {
                oldInvoice.items.forEach(oldItem => {
                    const product = appState.inventory.find(p => p.name.toLowerCase() === oldItem.name.toLowerCase());
                    if (product) {
                        product.stock += oldItem.qty;
                    }
                });
            }
            appState.history[existingIndex] = newInvoice;
        } else {
            return;
        }
    } else {
        appState.history.unshift(newInvoice);
    }

    // Increment Invoice Number automatically
    autoSetNextInvoiceNumber();

    // Deduct stock for each item in the invoice
    appState.items.forEach(item => {
        const product = appState.inventory.find(p => p.name.toLowerCase() === item.name.toLowerCase());
        if (product) {
            product.stock = Math.max(0, product.stock - item.qty);
        }
    });
    saveInventory();
    renderInventory();

    // Save
    saveHistory();
    renderHistory();
    alert(t('invoice_saved'));
}

// Automatically set the next invoice number based on history
function autoSetNextInvoiceNumber() {
    let nextInvoiceNo = 'BR-1001'; // Default fallback
    
    if (appState.history && appState.history.length > 0) {
        // Grab the most recent invoice number from history (history[0] is the latest saved)
        const latestInvoiceNo = appState.history[0].invoiceNo;
        
        // Match trailing numbers to increment
        const match = latestInvoiceNo.match(/^(.*?)(\d+)$/);
        if (match) {
            const prefix = match[1];
            const numStr = match[2];
            const nextNum = parseInt(numStr) + 1;
            const nextNumStr = nextNum.toString().padStart(numStr.length, '0');
            nextInvoiceNo = prefix + nextNumStr;
        } else {
            // If it doesn't end with numbers, just append -1 or -001
            nextInvoiceNo = latestInvoiceNo + '-001';
        }
    }
    
    // Set to state and update form input
    appState.customer.invoiceNo = nextInvoiceNo;
    const invInput = document.getElementById('invNumber');
    if (invInput) {
        invInput.value = nextInvoiceNo;
    }
}

// Clear the current invoice workspace to start a new bill (preserving sequential billing number)
function startNewInvoice() {
    if (appState.items.length > 0 || appState.customer.name || appState.customer.phone) {
        if (!confirm(t('confirm_new_invoice'))) {
            return;
        }
    }

    // Reset customer workspace details
    appState.customer.name = '';
    appState.customer.phone = '';
    appState.customer.date = new Date().toISOString().split('T')[0];
    appState.items = [];
    appState.discountAmt = 0;
    appState.discountType = 'flat';
    appState.paymentMode = 'upi';
    appState.gstRate = 0;
    appState.roundOffActive = 'yes';

    // Reset input fields
    document.getElementById('custName').value = '';
    document.getElementById('custPhone').value = '';
    document.getElementById('invDate').value = appState.customer.date;
    document.getElementById('gstRate').value = '0';
    document.getElementById('discountAmt').value = '';
    if (document.getElementById('discountType')) {
        document.getElementById('discountType').value = 'flat';
    }
    if (document.getElementById('paymentMode')) {
        document.getElementById('paymentMode').value = 'upi';
    }
    if (document.getElementById('roundOffActive')) {
        document.getElementById('roundOffActive').value = 'yes';
    }
    
    // Automatically set next invoice number sequentially from history
    autoSetNextInvoiceNumber();

    // Recalculate bill
    calculateInvoice();

    // Reset buttons/cancel states
    if (appState.editingItemId) {
        cancelEditItem();
    }

    alert('Billing workspace cleared. New invoice ready!');
}

// Render Saved History Table
function renderHistory() {
    const historyBody = document.getElementById('historyBody');
    historyBody.innerHTML = '';

    if (appState.history.length === 0) {
        historyBody.innerHTML = `
            <tr class="empty-state-row">
                <td colspan="9" class="text-center text-muted">${t('no_invoices')}</td>
            </tr>
        `;
        document.getElementById('totalRevenue').innerText = '₹0.00';
        document.getElementById('totalInvoiceCount').innerText = '0';
        return;
    }

    let revenue = 0;
    appState.history.forEach(inv => {
        if (inv.status === 'Paid') {
            revenue += inv.totals.grandTotal;
        }

        const row = document.createElement('tr');
        row.setAttribute('data-id', inv.id);
        const formattedDate = new Date(inv.date).toLocaleDateString('en-IN', { year: 'numeric', month: 'short', day: 'numeric' });
        
        // Build items sublist html (names only)
        const itemsListHtml = inv.items.map(item => `
            <div style="margin-bottom: 0.15rem; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
                • ${escapeHtml(item.name)}
            </div>
        `).join('');

        // Build qty sublist html
        const qtyListHtml = inv.items.map(item => `
            <div style="margin-bottom: 0.15rem;">
                ${item.qty} ${item.unit || 'pcs'}
            </div>
        `).join('');

        let discountSubtext = '';
        if (inv.totals && inv.totals.discount > 0) {
            const isPercent = inv.totals.discountType === 'percent';
            const val = inv.totals.discountInput !== undefined ? inv.totals.discountInput : inv.totals.discount;
            discountSubtext = isPercent 
                ? `<div class="text-danger" style="font-size: 0.7rem; margin-top: 0.1rem;" title="Percentage Discount">Disc (${val}%): -₹${inv.totals.discount.toFixed(2)}</div>`
                : `<div class="text-danger" style="font-size: 0.7rem; margin-top: 0.1rem;" title="Flat Discount">Disc: -₹${inv.totals.discount.toFixed(2)}</div>`;
        }

        row.innerHTML = `
            <td><strong>#${escapeHtml(inv.invoiceNo)}</strong></td>
            <td>${formattedDate}</td>
            <td>
                <div>${escapeHtml(inv.customerName)}</div>
                <div class="text-muted" style="font-size: 0.75rem;">+91 ${escapeHtml(inv.customerPhone || '')}</div>
            </td>
            <td>
                <div style="font-size: 0.8rem; line-height: 1.4; max-width: 220px; max-height: 80px; overflow-y: auto;">
                    ${itemsListHtml}
                </div>
            </td>
            <td class="text-center">
                <div style="font-size: 0.8rem; line-height: 1.4; max-height: 80px; overflow-y: auto; color: var(--text-secondary);">
                    ${qtyListHtml}
                </div>
            </td>
            <td>
                <strong>₹${inv.totals.grandTotal.toFixed(2)}</strong>
                ${discountSubtext}
            </td>
            <td>
                <span class="stat-badge">${inv.paymentMode ? inv.paymentMode.toUpperCase() : 'UPI'}</span>
            </td>
            <td>
                <span class="status-badge ${inv.status.toLowerCase()}" onclick="toggleInvoiceStatus('${inv.id}')" title="Click to cycle status (Paid -> Pending -> Refunded)">
                    ${inv.status}
                </span>
            </td>
            <td class="text-center">
                <div class="action-cell">
                    <button class="btn-table-action" onclick="loadInvoiceIntoApp('${inv.id}')" title="Re-open & Edit">
                        <i data-lucide="edit-3"></i>
                    </button>
                    <button class="btn-table-action" onclick="shareHistoryInvoice('${inv.id}')" title="Resend to WhatsApp">
                        <i data-lucide="send"></i>
                    </button>
                    <button class="btn-table-action delete" onclick="deleteInvoiceFromHistory('${inv.id}')" title="Delete record">
                        <i data-lucide="trash-2"></i>
                    </button>
                </div>
            </td>
        `;
        historyBody.appendChild(row);
    });

    // Update LEDGER summary card statistics
    document.getElementById('totalRevenue').innerText = `₹${revenue.toFixed(2)}`;
    document.getElementById('totalInvoiceCount').innerText = appState.history.length;

    // Load Lucide Icons for dynamic row elements
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    // Re-apply search filter for ledger history
    filterHistory();
    
    // Update CRM Phone list
    updateCustomerPhoneDatalist();
}

// Toggle Invoice Paid / Pending / Refunded
function toggleInvoiceStatus(invoiceId) {
    const inv = appState.history.find(i => i.id === invoiceId);
    if (inv) {
        const oldStatus = inv.status;
        let newStatus;
        if (oldStatus === 'Paid') {
            newStatus = 'Pending';
        } else if (oldStatus === 'Pending') {
            newStatus = 'Refunded';
        } else {
            newStatus = 'Paid';
        }

        // Apply inventory updates depending on the status change
        // Transition: * -> Refunded (entering Refunded)
        if (newStatus === 'Refunded' && oldStatus !== 'Refunded') {
            // Restore stock
            if (inv.items) {
                inv.items.forEach(item => {
                    const product = appState.inventory.find(p => p.name.toLowerCase() === item.name.toLowerCase());
                    if (product) {
                        product.stock += item.qty;
                    }
                });
            }
        }
        // Transition: Refunded -> * (leaving Refunded)
        else if (oldStatus === 'Refunded' && newStatus !== 'Refunded') {
            // Deduct stock again
            if (inv.items) {
                inv.items.forEach(item => {
                    const product = appState.inventory.find(p => p.name.toLowerCase() === item.name.toLowerCase());
                    if (product) {
                        product.stock = Math.max(0, product.stock - item.qty);
                    }
                });
            }
        }

        inv.status = newStatus;
        saveInventory();
        renderInventory();
        saveHistory();
        renderHistory();
        renderAnalytics();
    }
}

// Reload a past invoice back into the active workspace to edit it
function loadInvoiceIntoApp(invoiceId) {
    const inv = appState.history.find(i => i.id === invoiceId);
    if (inv) {
        if (confirm(t('confirm_discard_workspace', inv.invoiceNo))) {
            appState.customer.name = inv.customerName;
            appState.customer.phone = inv.customerPhone;
            appState.customer.invoiceNo = inv.invoiceNo;
            appState.customer.date = inv.date;
            appState.items = [...inv.items];
            appState.totals = { ...inv.totals };
            appState.roundOffActive = inv.roundOffActive || 'yes';
            
            // Restore GST rate and discount details (with legacy fallbacks)
            if (inv.gstRate !== undefined) {
                appState.gstRate = inv.gstRate;
            } else if (inv.totals && inv.totals.subtotal > 0 && inv.totals.gstAmount > 0) {
                appState.gstRate = Math.round((inv.totals.gstAmount / inv.totals.subtotal) * 100);
            } else {
                appState.gstRate = 0;
            }
            
            appState.discountAmt = (inv.totals && inv.totals.discountInput !== undefined) ? inv.totals.discountInput : (inv.totals ? (inv.totals.discount || 0) : 0);
            appState.discountType = (inv.totals && inv.totals.discountType) ? inv.totals.discountType : 'flat';
            
            // We just store simple items and totals. So re-run form inputs.
            initFormDefaults();
            calculateInvoice();
            
            // Scroll to form workspace
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    }
}

// Resend a history invoice directly via WhatsApp without loading it in workspace
function shareHistoryInvoice(invoiceId) {
    const inv = appState.history.find(i => i.id === invoiceId);
    if (inv) {
        // Temporarily swap state, call share, swap back
        const currentItems = [...appState.items];
        const currentCustomer = { ...appState.customer };
        const currentTotals = { ...appState.totals };
        const currentUpiUrl = appState.upiUrl;

        appState.items = inv.items;
        appState.customer = {
            name: inv.customerName,
            phone: inv.customerPhone,
            invoiceNo: inv.invoiceNo,
            date: inv.date
        };
        appState.totals = inv.totals;
        updateUpiPaymentDetails();

        // Trigger WhatsApp Dispatch
        shareViaWhatsApp();

        // Revert back
        appState.items = currentItems;
        appState.customer = currentCustomer;
        appState.totals = currentTotals;
        appState.upiUrl = currentUpiUrl;
        updatePreview();
    }
}

// Delete Invoice from history
function deleteInvoiceFromHistory(invoiceId) {
    if (confirm(t('confirm_delete_invoice'))) {
        const targetInv = appState.history.find(i => i.id === invoiceId);
        if (targetInv && targetInv.status !== 'Refunded' && targetInv.items) {
            targetInv.items.forEach(item => {
                const product = appState.inventory.find(p => p.name.toLowerCase() === item.name.toLowerCase());
                if (product) {
                    product.stock += item.qty;
                }
            });
            saveInventory();
            renderInventory();
        }
        appState.history = appState.history.filter(i => i.id !== invoiceId);
        saveHistory();
        renderHistory();
        
        // Sync invoice number in case the latest was deleted
        autoSetNextInvoiceNumber();
    }
}

// Export Invoice Ledger to Excel (using SheetJS)
function exportLedgerToExcel() {
    if (appState.history.length === 0) {
        alert('There is no invoice data in history to export.');
        return;
    }

    // Prepare data array
    const data = [];
    
    // Header Row
    data.push([
        "Invoice No",
        "Date",
        "Customer Name",
        "Customer Phone",
        "Item Name",
        "Qty",
        "Unit",
        "Item Rate (₹)",
        "Item Total (₹)",
        "Subtotal (₹)",
        "GST Rate (%)",
        "GST Amount (₹)",
        "Discount Type",
        "Discount Input",
        "Total Discount (₹)",
        "Round Off (₹)",
        "Grand Total (₹)",
        "Payment Mode",
        "Status"
    ]);

    // Populate Rows
    appState.history.forEach(inv => {
        const gstRate = inv.gstRate !== undefined ? inv.gstRate : (inv.totals ? Math.round((inv.totals.gstAmount / (inv.totals.subtotal || 1)) * 100) : 0);
        
        inv.items.forEach(item => {
            const itemTotal = item.price * item.qty;
            const totals = inv.totals || {};
            data.push([
                inv.invoiceNo,
                inv.date,
                inv.customerName,
                inv.customerPhone ? `+91 ${inv.customerPhone}` : '',
                item.name,
                item.qty,
                item.unit || 'pcs',
                item.price,
                itemTotal,
                totals.subtotal || 0,
                gstRate,
                totals.gstAmount || 0,
                totals.discountType || 'flat',
                totals.discountInput !== undefined ? totals.discountInput : (totals.discount || 0),
                totals.discount || 0,
                totals.roundOff || 0,
                totals.grandTotal || 0,
                inv.paymentMode ? inv.paymentMode.toUpperCase() : 'UPI',
                inv.status
            ]);
        });
    });

    try {
        // Create SheetJS Worksheet
        const ws = XLSX.utils.aoa_to_sheet(data);

        // Define column widths for Excel formatting
        const wscols = [
            { wch: 15 }, // Invoice No
            { wch: 15 }, // Date
            { wch: 22 }, // Customer Name
            { wch: 18 }, // Customer Phone
            { wch: 35 }, // Item Name
            { wch: 10 }, // Qty
            { wch: 8 },  // Unit
            { wch: 15 }, // Item Rate
            { wch: 15 }, // Item Total
            { wch: 15 }, // Subtotal
            { wch: 12 }, // GST Rate (%)
            { wch: 15 }, // GST Amount
            { wch: 15 }, // Discount Type
            { wch: 15 }, // Discount Input
            { wch: 18 }, // Total Discount
            { wch: 15 }, // Round Off
            { wch: 18 }, // Grand Total
            { wch: 15 }, // Payment Mode
            { wch: 12 }  // Status
        ];
        ws['!cols'] = wscols;

        // Create Workbook
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, "Sales Ledger");

        // Save file
        const todayStr = new Date().toISOString().split('T')[0];
        XLSX.writeFile(wb, `BharatPOS_Sales_Ledger_${todayStr}.xlsx`);
    } catch (error) {
        console.error('Failed to export Excel:', error);
        alert('Error generating Excel file. Please make sure the sheet library is loaded.');
    }
}

// Download structured Excel Import Template (using ExcelJS)
async function downloadExcelTemplate() {
    try {
        const workbook = new ExcelJS.Workbook();
        const wsInventory = workbook.addWorksheet("Product Inventory");
        
        // Setup columns
        wsInventory.columns = [
            { header: "Product Name*", key: "name", width: 35 },
            { header: "Selling Price (₹)*", key: "price", width: 18 },
            { header: "Purchase Price (₹)*", key: "purchasePrice", width: 20 },
            { header: "Stock Qty*", key: "stock", width: 15 },
            { header: "Unit*", key: "unit", width: 10 },
            { header: "Pcs per Box (Optional)", key: "pcsPerBox", width: 22 },
            { header: "Category/SKU (Optional)", key: "sku", width: 22 }
        ];

        // Seed with current inventory if exists, else defaults
        const currentInv = appState.inventory.length > 0 ? appState.inventory : [
            { name: "Chocolate Truffle Cake - 1kg", price: 650.00, purchasePrice: 450.00, stock: 10, unit: "pcs", pcsPerBox: 1, sku: "Bakery-Cake" },
            { name: "Pineapple Pastry", price: 80.00, purchasePrice: 50.00, stock: 25, unit: "pcs", pcsPerBox: 1, sku: "Bakery-Pastry" },
            { name: "Sourdough Bread", price: 120.00, purchasePrice: 80.00, stock: 15, unit: "kg", pcsPerBox: 1, sku: "Bakery-Bread" }
        ];

        currentInv.forEach(prod => {
            wsInventory.addRow({
                name: prod.name,
                price: prod.price,
                purchasePrice: prod.purchasePrice || 0,
                stock: prod.stock,
                unit: prod.unit || 'pcs',
                pcsPerBox: prod.pcsPerBox || 1,
                sku: prod.sku || 'General'
            });
        });

        // Add dropdown data validation for column E (Unit*) from row 2 to 500
        wsInventory.dataValidations.add('E2:E500', {
            type: 'list',
            allowBlank: true,
            formulae: ['"pcs,kg,box,g,ltr,ml,packet,dozen"'],
            showErrorMessage: true,
            errorTitle: 'Invalid Unit',
            error: 'Please select a unit from the dropdown list (pcs, kg, box, g, ltr, ml, packet, dozen).'
        });

        // Style the header row in modern Indigo theme
        const headerRow = wsInventory.getRow(1);
        headerRow.font = { name: 'Arial', family: 2, size: 10, bold: true, color: { argb: 'FFFFFFFF' } };
        headerRow.fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FF4F46E5' } // Cyber Indigo
        };
        headerRow.alignment = { vertical: 'middle', horizontal: 'center' };

        // Generate buffer
        const buffer = await workbook.xlsx.writeBuffer();
        
        // Create Blob
        const blob = new Blob([buffer], {
            type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        });

        // Trigger Download
        const url = window.URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = "BharatPOS_Import_Template.xlsx";
        document.body.appendChild(anchor);
        anchor.click();
        document.body.removeChild(anchor);
        window.URL.revokeObjectURL(url);

    } catch (error) {
        console.error('Failed to download template:', error);
        alert('Error generating template file. Please make sure the sheet library is loaded.');
    }
}

// Export Current Stock Report in Excel format using ExcelJS
async function exportStockReportToExcel() {
    if (appState.inventory.length === 0) {
        alert(t('no_products_to_export'));
        return;
    }

    try {
        const workbook = new ExcelJS.Workbook();
        const wsStock = workbook.addWorksheet("Current Stock Report");

        // Setup columns
        wsStock.columns = [
            { header: "Product Name", key: "name", width: 35 },
            { header: "Category/SKU", key: "sku", width: 22 },
            { header: "Unit", key: "unit", width: 12 },
            { header: "Selling Price (₹)", key: "price", width: 18, style: { numFmt: '"₹"#,##0.00' } },
            { header: "Purchase Cost (₹)", key: "purchasePrice", width: 20, style: { numFmt: '"₹"#,##0.00' } },
            { header: "Stock Quantity", key: "stock", width: 16, style: { numFmt: '#,##0.00' } },
            { header: "Reorder Level", key: "minStock", width: 16, style: { numFmt: '#,##0.00' } },
            { header: "Stock Status", key: "status", width: 16 },
            { header: "Total Value (Retail) (₹)", key: "totalValueSelling", width: 22, style: { numFmt: '"₹"#,##0.00' } },
            { header: "Total Value (Cost) (₹)", key: "totalValueCost", width: 22, style: { numFmt: '"₹"#,##0.00' } },
            { header: "Potential Profit (₹)", key: "potentialProfit", width: 20, style: { numFmt: '"₹"#,##0.00' } }
        ];

        let totalQty = 0;
        let totalValueRetail = 0;
        let totalValueCost = 0;

        appState.inventory.forEach(prod => {
            const reorderLevel = prod.minStock !== undefined ? prod.minStock : 3;
            let status = "In Stock";
            if (prod.stock <= 0) {
                status = "Out of Stock";
            } else if (prod.stock <= reorderLevel) {
                status = "Reorder Alert";
            } else if (prod.stock <= reorderLevel + 3) {
                status = "Low Stock";
            }

            const sellingPrice = prod.price || 0;
            const costPrice = prod.purchasePrice || 0;
            const stockQty = prod.stock || 0;

            const totalValSelling = stockQty * sellingPrice;
            const totalValCost = stockQty * costPrice;
            const profit = totalValSelling - totalValCost;

            totalQty += stockQty;
            totalValueRetail += totalValSelling;
            totalValueCost += totalValCost;

            wsStock.addRow({
                name: prod.name,
                sku: prod.sku || 'General',
                unit: prod.unit || 'pcs',
                price: sellingPrice,
                purchasePrice: costPrice,
                stock: stockQty,
                minStock: reorderLevel,
                status: status,
                totalValueSelling: totalValSelling,
                totalValueCost: totalValCost,
                potentialProfit: profit
            });
        });

        // Add spacing row
        wsStock.addRow({});

        // Add summary row
        const summaryRow = wsStock.addRow({
            name: "TOTALS",
            sku: "",
            unit: "",
            price: "",
            purchasePrice: "",
            stock: totalQty,
            minStock: "",
            status: "",
            totalValueSelling: totalValueRetail,
            totalValueCost: totalValueCost,
            potentialProfit: totalValueRetail - totalValueCost
        });
        
        // Format Totals Row
        summaryRow.font = { name: 'Arial', size: 10, bold: true };
        summaryRow.getCell('name').alignment = { horizontal: 'left' };
        
        // Style Header Row in Indigo theme
        const headerRow = wsStock.getRow(1);
        headerRow.font = { name: 'Arial', family: 2, size: 10, bold: true, color: { argb: 'FFFFFFFF' } };
        headerRow.fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FF4F46E5' } // Cyber Indigo
        };
        headerRow.alignment = { vertical: 'middle', horizontal: 'center' };

        // Generate buffer
        const buffer = await workbook.xlsx.writeBuffer();

        // Create Blob
        const blob = new Blob([buffer], {
            type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        });

        // Trigger Download
        const todayStr = new Date().toISOString().split('T')[0];
        const url = window.URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `BharatPOS_Stock_Report_${todayStr}.xlsx`;
        document.body.appendChild(anchor);
        anchor.click();
        document.body.removeChild(anchor);
        window.URL.revokeObjectURL(url);

    } catch (error) {
        console.error('Failed to export stock report:', error);
        alert('Error generating stock report file. Please make sure the sheet library is loaded.');
    }
}

// Handle Excel Upload Parse and Ingestion
function handleExcelUpload(e) {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(evt) {
        try {
            const data = new Uint8Array(evt.target.result);
            const workbook = XLSX.read(data, { type: 'array' });

            let profileUpdated = false;
            let inventoryImportedCount = 0;

            // 1. Parse "Business Profile" Sheet if exists
            const profileSheetName = workbook.SheetNames.find(name => name.toLowerCase().includes("profile"));
            if (profileSheetName) {
                const sheet = workbook.Sheets[profileSheetName];
                const rows = XLSX.utils.sheet_to_json(sheet, { header: 1 });
                
                // Rows structure: [ ['Configuration Option', 'Setting Value'], ['Business Name', 'Ramesh Bakery'], ... ]
                rows.forEach((row, idx) => {
                    if (idx === 0 || !row || row.length < 2) return; // skip header or empty rows
                    const key = row[0].toString().trim().toLowerCase();
                    const val = row[1].toString().trim();

                    if (key.includes("business name")) {
                        appState.business.name = val;
                    } else if (key.includes("upi id")) {
                        appState.business.upiId = val;
                    } else if (key.includes("phone")) {
                        appState.business.phone = val;
                    } else if (key.includes("address")) {
                        appState.business.address = val;
                    }
                });
                
                // Save and update form fields
                saveBusinessProfile();
                profileUpdated = true;
            }

            // 2. Parse "Product Inventory" Sheet if exists
            const inventorySheetName = workbook.SheetNames.find(name => name.toLowerCase().includes("inventory") || name.toLowerCase().includes("product"));
            if (inventorySheetName) {
                const sheet = workbook.Sheets[inventorySheetName];
                const rows = XLSX.utils.sheet_to_json(sheet);
                
                // Columns mapping: "Product Name*", "Selling Price (₹)*", "Purchase Price (₹)*", "Stock Qty*", "Unit*", "Category/SKU (Optional)"
                const newInventory = [];
                rows.forEach(row => {
                    let name = row["Product Name*"] || row["Product Name"] || row["Name"] || row["name"];
                    let priceVal = row["Selling Price (₹)*"] || row["Selling Price"] || row["Price/Rate (₹)*"] || row["Price/Rate"] || row["Price"] || row["price"] || row["Rate"] || row["rate"];
                    let purchasePriceVal = row["Purchase Price (₹)*"] || row["Purchase Price"] || row["PurchasePrice"] || row["purchasePrice"] || row["Cost"] || row["cost"];
                    let stockVal = row["Stock Qty*"] || row["Stock Qty"] || row["Stock"] || row["stock"] || row["Quantity"] || row["quantity"];
                    let unitVal = row["Unit*"] || row["Unit"] || row["unit"];
                    let pcsPerBoxVal = row["Pcs per Box (Optional)"] || row["Pcs per Box"] || row["pcsPerBox"] || row["PcsPerBox"];
                    let sku = row["Category/SKU (Optional)"] || row["Category/SKU"] || row["SKU"] || row["sku"] || row["Category"] || row["category"];

                    if (!name) return; // Name is required
                    const price = parseFloat(priceVal);
                    if (isNaN(price)) return; // Price is required

                    const purchasePrice = parseFloat(purchasePriceVal);
                    const finalPurchasePrice = isNaN(purchasePrice) ? 0 : purchasePrice;

                    const stock = parseFloat(stockVal);
                    const finalStock = isNaN(stock) ? 0 : stock;
                    const finalUnit = unitVal ? unitVal.toString().trim().toLowerCase() : 'pcs';
                    
                    let pcsPerBox = parseFloat(pcsPerBoxVal);
                    if (isNaN(pcsPerBox) || pcsPerBox < 1) pcsPerBox = 1;

                    newInventory.push({
                        id: (Date.now() + newInventory.length).toString(), // distinct IDs
                        name: name.toString().trim(),
                        price: price,
                        purchasePrice: finalPurchasePrice,
                        stock: finalStock,
                        unit: finalUnit,
                        pcsPerBox: pcsPerBox,
                        sku: sku ? sku.toString().trim() : 'General'
                    });
                });

                if (newInventory.length > 0) {
                    appState.inventory = newInventory;
                    saveInventory();
                    inventoryImportedCount = newInventory.length;
                }
            }

            // 3. Post-Ingestion UI Refresh
            if (profileUpdated || inventoryImportedCount > 0) {
                // Sync invoice number
                autoSetNextInvoiceNumber();
                
                // Populate forms from state
                initFormDefaults();
                
                // Re-render Preview Receipt details
                updatePreview();

                // Re-render Inventory Database list and autocomplete datalist
                renderInventory();

                // Build success message
                let msg = 'Import Complete!';
                if (profileUpdated) msg += '\n- Business profile updated.';
                if (inventoryImportedCount > 0) msg += `\n- Imported ${inventoryImportedCount} products into your database.`;
                alert(msg);
            } else {
                alert('No valid sheets ("Business Profile" or "Product Inventory") found in the Excel file.');
            }

        } catch (error) {
            console.error('Failed to parse Excel file:', error);
            alert('Failed to parse Excel file. Please make sure it matches the layout of the template.');
        }

        // Reset file input value to allow uploading the same file again
        e.target.value = '';
    };

    reader.readAsArrayBuffer(file);
}

// ==========================================
// Product Inventory Database Logic
// ==========================================

// Add or Save Product in Inventory
function addProductToInventory() {
    const nameInput = document.getElementById('prodName');
    const priceInput = document.getElementById('prodPrice');
    const purchasePriceInput = document.getElementById('prodPurchasePrice');
    const stockInput = document.getElementById('prodStock');
    const minStockInput = document.getElementById('prodMinStock');
    const unitInput = document.getElementById('prodUnit');
    const skuInput = document.getElementById('prodSku');

    const name = nameInput.value.trim();
    const price = parseFloat(priceInput.value);
    const purchasePrice = purchasePriceInput ? parseFloat(purchasePriceInput.value) : 0;
    const stock = parseFloat(stockInput.value);
    const minStock = parseFloat(minStockInput ? minStockInput.value : '3') || 0;
    const unit = unitInput ? unitInput.value : 'pcs';
    const sku = skuInput.value.trim();

    const pcsPerBoxInput = document.getElementById('prodPcsPerBox');
    const pcsPerBox = parseFloat(pcsPerBoxInput ? pcsPerBoxInput.value : '1') || 1;

    if (!name) {
        alert('Please enter a product name.');
        nameInput.focus();
        return;
    }
    if (isNaN(price) || price < 0) {
        alert('Please enter a valid product price.');
        priceInput.focus();
        return;
    }
    if (isNaN(purchasePrice) || purchasePrice < 0) {
        alert('Please enter a valid product purchase price.');
        if (purchasePriceInput) purchasePriceInput.focus();
        return;
    }
    if (isNaN(stock) || stock < 0) {
        alert('Please enter a valid stock quantity.');
        stockInput.focus();
        return;
    }

    if (appState.editingInventoryProductId) {
        // Edit Mode
        const prodIndex = appState.inventory.findIndex(p => p.id === appState.editingInventoryProductId);
        if (prodIndex > -1) {
            appState.inventory[prodIndex].name = name;
            appState.inventory[prodIndex].price = price;
            appState.inventory[prodIndex].purchasePrice = purchasePrice;
            appState.inventory[prodIndex].stock = stock;
            appState.inventory[prodIndex].minStock = minStock;
            appState.inventory[prodIndex].unit = unit;
            appState.inventory[prodIndex].pcsPerBox = pcsPerBox;
            appState.inventory[prodIndex].sku = sku || 'General';
        }
        
        // Reset State
        appState.editingInventoryProductId = null;
        
        // Reset Button
        const addBtn = document.getElementById('addProdBtn');
        addBtn.innerHTML = '<i data-lucide="plus"></i> Add Product';
        addBtn.className = 'btn btn-emerald';
        document.getElementById('cancelProdEditBtn').style.display = 'none';
        
    } else {
        // Add Mode
        const newProduct = {
            id: Date.now().toString(),
            name: name,
            price: price,
            purchasePrice: purchasePrice,
            stock: stock,
            minStock: minStock,
            unit: unit,
            pcsPerBox: pcsPerBox,
            sku: sku || 'General'
        };
        appState.inventory.push(newProduct);
    }

    // Reset fields
    nameInput.value = '';
    priceInput.value = '';
    if (purchasePriceInput) purchasePriceInput.value = '';
    stockInput.value = '0';
    if (pcsPerBoxInput) pcsPerBoxInput.value = '1';
    const refillInput = document.getElementById('prodRefillBoxes');
    if (refillInput) refillInput.value = '';
    if (minStockInput) minStockInput.value = '3';
    if (unitInput) unitInput.value = 'pcs';
    skuInput.value = '';

    // Save and re-render
    saveInventory();
    renderInventory();
    
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
}

// Edit Product in Inventory
function editProductInInventory(productId) {
    const product = appState.inventory.find(p => p.id === productId);
    if (!product) return;

    // Load fields
    document.getElementById('prodName').value = product.name;
    document.getElementById('prodPrice').value = product.price;
    if (document.getElementById('prodPurchasePrice')) {
        document.getElementById('prodPurchasePrice').value = product.purchasePrice !== undefined ? product.purchasePrice : 0;
    }
    document.getElementById('prodStock').value = product.stock || 0;
    if (document.getElementById('prodMinStock')) {
        document.getElementById('prodMinStock').value = product.minStock !== undefined ? product.minStock : 3;
    }
    if (document.getElementById('prodUnit')) {
        document.getElementById('prodUnit').value = product.unit || 'pcs';
    }
    if (document.getElementById('prodPcsPerBox')) {
        document.getElementById('prodPcsPerBox').value = product.pcsPerBox || 1;
    }
    if (document.getElementById('prodRefillBoxes')) {
        document.getElementById('prodRefillBoxes').value = '';
    }
    document.getElementById('prodSku').value = product.sku === 'General' ? '' : product.sku;

    // Set Editing state
    appState.editingInventoryProductId = productId;

    // Update buttons
    const addBtn = document.getElementById('addProdBtn');
    addBtn.innerHTML = '<i data-lucide="save"></i> Save Product';
    addBtn.className = 'btn btn-primary'; // distinct color for editing
    document.getElementById('cancelProdEditBtn').style.display = 'inline-block';

    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }

    document.getElementById('prodName').focus();
}

// Cancel Edit Product
function cancelEditProduct() {
    document.getElementById('prodName').value = '';
    document.getElementById('prodPrice').value = '';
    if (document.getElementById('prodPurchasePrice')) {
        document.getElementById('prodPurchasePrice').value = '';
    }
    document.getElementById('prodStock').value = '0';
    if (document.getElementById('prodMinStock')) {
        document.getElementById('prodMinStock').value = '3';
    }
    if (document.getElementById('prodUnit')) {
        document.getElementById('prodUnit').value = 'pcs';
    }
    if (document.getElementById('prodPcsPerBox')) {
        document.getElementById('prodPcsPerBox').value = '1';
    }
    if (document.getElementById('prodRefillBoxes')) {
        document.getElementById('prodRefillBoxes').value = '';
    }
    document.getElementById('prodSku').value = '';

    appState.editingInventoryProductId = null;

    const addBtn = document.getElementById('addProdBtn');
    addBtn.innerHTML = '<i data-lucide="plus"></i> Add Product';
    addBtn.className = 'btn btn-emerald';
    document.getElementById('cancelProdEditBtn').style.display = 'none';

    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
    
    renderInventory();
}

// Delete Product from Inventory
function deleteProductFromInventory(productId) {
    if (confirm(t('confirm_delete_product'))) {
        if (appState.editingInventoryProductId === productId) {
            cancelEditProduct();
        }
        appState.inventory = appState.inventory.filter(p => p.id !== productId);
        saveInventory();
        renderInventory();
    }
}

// Render Inventory Table and Autocomplete Datalist
function renderInventory() {
    const tableBody = document.getElementById('inventoryBody');
    const datalist = document.getElementById('inventoryDatalist');
    
    if (!tableBody || !datalist) return;

    // Clear UI elements
    tableBody.innerHTML = '';
    datalist.innerHTML = '';

    if (appState.inventory.length === 0) {
        tableBody.innerHTML = `
            <tr class="empty-state-row">
                <td colspan="5" class="text-center text-muted">${t('no_products')}</td>
            </tr>
        `;
    } else {
        // Populate Table
        appState.inventory.forEach(prod => {
            const row = document.createElement('tr');
            if (appState.editingInventoryProductId === prod.id) {
                row.className = 'editing-row-highlight';
            }
            
            // Determine Stock Badge class
            let stockClass = 'in-stock';
            
            // Calculate Box counts if pcsPerBox > 1
            let boxesLabel = '';
            if (prod.pcsPerBox && prod.pcsPerBox > 1) {
                const boxes = (prod.stock / prod.pcsPerBox).toFixed(1).replace(/\.0$/, '');
                boxesLabel = ` (~${boxes} boxes)`;
            }
            
            let stockLabel = `${prod.stock} ${prod.unit || 'pcs'}${boxesLabel}`;
            const reorderLevel = prod.minStock !== undefined ? prod.minStock : 3;
            
            if (prod.stock <= 0) {
                stockClass = 'out-of-stock';
                stockLabel = 'Out of Stock';
            } else if (prod.stock <= reorderLevel) {
                stockClass = 'reorder-alert';
                stockLabel = `Reorder: ${prod.stock} ${prod.unit || 'pcs'}${boxesLabel} (Min: ${reorderLevel})`;
            } else if (prod.stock <= reorderLevel + 3) {
                stockClass = 'low-stock';
                stockLabel = `Low: ${prod.stock} ${prod.unit || 'pcs'}${boxesLabel}`;
            }
            
            row.innerHTML = `
                <td><strong>${escapeHtml(prod.name)}</strong></td>
                <td class="text-right">₹${prod.price.toFixed(2)}<br><small class="text-muted" style="font-size: 0.7rem;">Cost: ₹${(prod.purchasePrice || 0).toFixed(2)}</small></td>
                <td class="text-center"><span class="stock-badge ${stockClass}">${stockLabel}</span></td>
                <td><span class="stat-badge">${escapeHtml(prod.sku)}</span></td>
                <td class="text-center">
                    <div class="action-cell">
                        <button class="btn-table-action" onclick="editProductInInventory('${prod.id}')" title="Edit Product">
                            <i data-lucide="edit-3"></i>
                        </button>
                        <button class="btn-table-action delete" onclick="deleteProductFromInventory('${prod.id}')" title="Delete Product">
                            <i data-lucide="trash-2"></i>
                        </button>
                    </div>
                </td>
            `;
            tableBody.appendChild(row);

            // Populate Datalist Autocomplete
            const option = document.createElement('option');
            option.value = prod.name;
            option.textContent = `₹${prod.price.toFixed(2)} (${prod.stock} ${prod.unit || 'pcs'} left)`;
            datalist.appendChild(option);
        });

        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    }

    // Re-apply search filter for inventory database
    filterInventory();
}

// Local Storage Handlers
async function saveBusinessProfile() {
    const key = appState.currentUser ? `bharatpos_${appState.currentUser.toLowerCase()}_business` : 'bharatpos_business';
    const jsonStr = JSON.stringify(appState.business);
    if (activeEncryptionKey) {
        try {
            const encrypted = await encryptData(jsonStr, activeEncryptionKey);
            localStorage.setItem(key, encrypted);
        } catch (e) {
            console.error('Error encrypting business profile:', e);
        }
    } else {
        localStorage.setItem(key, jsonStr);
    }
}

async function saveHistory() {
    const key = appState.currentUser ? `bharatpos_${appState.currentUser.toLowerCase()}_history` : 'bharatpos_history';
    const jsonStr = JSON.stringify(appState.history);
    if (activeEncryptionKey) {
        try {
            const encrypted = await encryptData(jsonStr, activeEncryptionKey);
            localStorage.setItem(key, encrypted);
        } catch (e) {
            console.error('Error encrypting history:', e);
        }
    } else {
        localStorage.setItem(key, jsonStr);
    }
}

async function saveInventory() {
    const key = appState.currentUser ? `bharatpos_${appState.currentUser.toLowerCase()}_inventory` : 'bharatpos_inventory';
    const jsonStr = JSON.stringify(appState.inventory);
    if (activeEncryptionKey) {
        try {
            const encrypted = await encryptData(jsonStr, activeEncryptionKey);
            localStorage.setItem(key, encrypted);
        } catch (e) {
            console.error('Error encrypting inventory:', e);
        }
    } else {
        localStorage.setItem(key, jsonStr);
    }
}

async function loadEncryptedOrPlain(key, fallbackValue) {
    const data = localStorage.getItem(key);
    if (!data) return fallbackValue;
    
    // Check if it's plain JSON (starts with { or [)
    if (data.startsWith('{') || data.startsWith('[')) {
        try {
            const parsed = JSON.parse(data);
            // Migrate to encrypted if key is available
            if (activeEncryptionKey) {
                const encrypted = await encryptData(data, activeEncryptionKey);
                localStorage.setItem(key, encrypted);
            }
            return parsed;
        } catch (e) {
            console.error(`Error parsing plain JSON for key ${key}:`, e);
            return fallbackValue;
        }
    }
    
    // Otherwise it is encrypted
    if (activeEncryptionKey) {
        try {
            const decrypted = await decryptData(data, activeEncryptionKey);
            return JSON.parse(decrypted);
        } catch (e) {
            console.error(`Error decrypting data for key ${key}:`, e);
            return fallbackValue;
        }
    } else {
        console.warn(`Data is encrypted but no active encryption key found for key: ${key}`);
        return fallbackValue;
    }
}

async function loadFromLocalStorage(username) {
    const activeUser = username || appState.currentUser;
    if (!activeUser) return;

    const bizKey = `bharatpos_${activeUser.toLowerCase()}_business`;
    const histKey = `bharatpos_${activeUser.toLowerCase()}_history`;
    const invKey = `bharatpos_${activeUser.toLowerCase()}_inventory`;

    appState.business = await loadEncryptedOrPlain(bizKey, {
        name: '',
        upiId: '',
        phone: '',
        address: '',
        gstin: ''
    });

    appState.history = await loadEncryptedOrPlain(histKey, []);

    // Seed default inventory values if empty
    appState.inventory = await loadEncryptedOrPlain(invKey, null);
    if (!appState.inventory || appState.inventory.length === 0) {
        const masterCatalogData = localStorage.getItem('bharatpos_master_catalog');
        if (masterCatalogData) {
            try {
                const masterCatalog = JSON.parse(masterCatalogData);
                appState.inventory = masterCatalog.map(p => ({
                    id: p.id || Date.now().toString() + Math.random().toString(36).substring(2, 5),
                    name: p.name,
                    price: p.price,
                    purchasePrice: p.purchasePrice || 0,
                    stock: 0, // start with 0 stock
                    sku: p.sku || '',
                    unit: p.unit || 'pcs',
                    pcsPerBox: p.pcsPerBox || 1,
                    reorderLevel: p.reorderLevel !== undefined ? p.reorderLevel : 5
                }));
            } catch (err) {
                console.error('Error parsing master catalog for seed:', err);
                appState.inventory = [];
            }
        }
        
        if (!appState.inventory || appState.inventory.length === 0) {
            appState.inventory = [
                { id: '1', name: 'Chocolate Truffle Cake - 1kg', price: 650.00, purchasePrice: 450.00, stock: 10, sku: 'Bakery-Cake', unit: 'pcs' },
                { id: '2', name: 'Pineapple Pastry', price: 80.00, purchasePrice: 50.00, stock: 25, sku: 'Bakery-Pastry', unit: 'pcs' },
                { id: '3', name: 'Sourdough Bread', price: 120.00, purchasePrice: 80.00, stock: 15, sku: 'Bakery-Bread', unit: 'kg' },
                { id: '4', name: 'Garlic Bread (Loaf)', price: 90.00, purchasePrice: 60.00, stock: 12, sku: 'Bakery-Bread', unit: 'pcs' },
                { id: '5', name: 'Red Velvet Cupcake', price: 75.00, purchasePrice: 45.00, stock: 20, sku: 'Bakery-Cupcake', unit: 'pcs' }
            ];
        }
        await saveInventory();
    }

    const langKey = `bharatpos_${activeUser.toLowerCase()}_language`;
    appState.language = localStorage.getItem(langKey) || localStorage.getItem('bharatpos_global_language') || 'en';
    const langSelector = document.getElementById('languageSelector');
    if (langSelector) {
        langSelector.value = appState.language;
    }
}

// Theme Switcher
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('bharatpos_theme', newTheme);
}

// Theme loading on bootstrap
(function() {
    const savedTheme = localStorage.getItem('bharatpos_theme');
    if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
    }
})();

// Helper to escape HTML tags in content outputs (protect against XSS injection)
function escapeHtml(text) {
    if (!text) return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

// Filter Line Items inside the active workspace
function filterLineItems() {
    const searchWrapper = document.getElementById('lineItemsSearchWrapper');
    const searchInput = document.getElementById('searchLineItemsInput');
    if (!searchWrapper || !searchInput) return;

    if (appState.items.length === 0) {
        searchWrapper.style.display = 'none';
        searchInput.value = '';
        return;
    } else {
        searchWrapper.style.display = 'block';
    }

    const query = searchInput.value.toLowerCase().trim();
    const rows = document.querySelectorAll('#itemsBody tr:not(.empty-state-row)');
    rows.forEach(row => {
        const firstCell = row.querySelector('td:first-child');
        if (!firstCell) return;
        const itemName = firstCell.innerText.toLowerCase();
        if (itemName.includes(query)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// Filter products inside the Master Inventory Database panel
function filterInventory() {
    const searchWrapper = document.getElementById('inventorySearchWrapper');
    const searchInput = document.getElementById('searchInventoryInput');
    if (!searchWrapper || !searchInput) return;

    if (appState.inventory.length === 0) {
        searchWrapper.style.display = 'none';
        searchInput.value = '';
        return;
    } else {
        searchWrapper.style.display = 'block';
    }

    const query = searchInput.value.toLowerCase().trim();
    const rows = document.querySelectorAll('#inventoryBody tr:not(.empty-state-row)');
    rows.forEach(row => {
        const nameCell = row.querySelector('td:first-child');
        const skuCell = row.querySelector('td:nth-child(3)');
        if (!nameCell) return;
        
        const prodName = nameCell.innerText.toLowerCase();
        const sku = skuCell ? skuCell.innerText.toLowerCase() : '';
        if (prodName.includes(query) || sku.includes(query)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// Filter past invoices inside the Sales Ledger
function filterHistory() {
    const searchWrapper = document.getElementById('historySearchWrapper');
    const searchInput = document.getElementById('searchHistoryInput');
    const dateFiltersWrapper = document.getElementById('ledgerDateFiltersWrapper');
    const startDateInput = document.getElementById('ledgerStartDate');
    const endDateInput = document.getElementById('ledgerEndDate');
    
    if (!searchWrapper || !searchInput) return;

    if (appState.history.length === 0) {
        searchWrapper.style.display = 'none';
        if (dateFiltersWrapper) dateFiltersWrapper.style.display = 'none';
        searchInput.value = '';
        if (startDateInput) startDateInput.value = '';
        if (endDateInput) endDateInput.value = '';
        document.getElementById('totalRevenue').innerText = '₹0.00';
        document.getElementById('totalInvoiceCount').innerText = '0';
        return;
    } else {
        searchWrapper.style.display = 'block';
        if (dateFiltersWrapper) dateFiltersWrapper.style.display = 'flex';
    }

    const query = searchInput.value.toLowerCase().trim();
    const startDateVal = startDateInput ? startDateInput.value : '';
    const endDateVal = endDateInput ? endDateInput.value : '';

    const rows = document.querySelectorAll('#historyBody tr:not(.empty-state-row)');
    let visibleCount = 0;
    let visibleRevenue = 0;

    rows.forEach(row => {
        const invCell = row.querySelector('td:first-child');
        const custCell = row.querySelector('td:nth-child(3)');
        const itemsCell = row.querySelector('td:nth-child(4)');
        if (!invCell) return;

        const invNo = invCell.innerText.toLowerCase();
        const customer = custCell ? custCell.innerText.toLowerCase() : '';
        const items = itemsCell ? itemsCell.innerText.toLowerCase() : '';
        
        // Find matching invoice object
        const invId = row.getAttribute('data-id');
        let inv = null;
        if (invId) {
            inv = appState.history.find(i => i.id === invId);
        } else {
            const cleanInvNo = invCell.innerText.trim().replace('#', '').toLowerCase();
            inv = appState.history.find(i => i.invoiceNo.toLowerCase() === cleanInvNo);
        }
        const invDate = inv ? inv.date : ''; // YYYY-MM-DD format

        // Check text match
        const textMatch = invNo.includes(query) || customer.includes(query) || items.includes(query);

        // Check date match
        let dateMatch = true;
        if (startDateVal && invDate && invDate < startDateVal) {
            dateMatch = false;
        }
        if (endDateVal && invDate && invDate > endDateVal) {
            dateMatch = false;
        }

        if (textMatch && dateMatch) {
            row.style.display = '';
            visibleCount++;
            if (inv && inv.status === 'Paid') {
                visibleRevenue += inv.totals.grandTotal;
            }
        } else {
            row.style.display = 'none';
        }
    });

    // Update LEDGER summary card statistics in real time based on active records
    document.getElementById('totalRevenue').innerText = `₹${visibleRevenue.toFixed(2)}`;
    document.getElementById('totalInvoiceCount').innerText = visibleCount;
}

// ==========================================
// Authentication & Multi-User Handler Logic
// ==========================================
let currentAuthTab = 'login';

function switchAuthTab(tab) {
    currentAuthTab = tab;
    const tabLogin = document.getElementById('tabLogin');
    const tabRegister = document.getElementById('tabRegister');
    const registerBizGroup = document.getElementById('registerBizGroup');
    const registerSecurityGroup = document.getElementById('registerSecurityGroup');
    const loginAddons = document.getElementById('loginAddons');
    const submitText = document.getElementById('authSubmitText');
    const submitBtn = document.getElementById('authSubmitBtn');
    
    if (!tabLogin || !tabRegister || !registerBizGroup || !submitText || !submitBtn) return;

    if (tab === 'login') {
        tabLogin.classList.add('active-tab');
        tabRegister.classList.remove('active-tab');
        registerBizGroup.style.display = 'none';
        if (registerSecurityGroup) registerSecurityGroup.style.display = 'none';
        if (loginAddons) loginAddons.style.display = 'flex';
        submitText.innerText = 'Login';
        submitBtn.className = 'btn btn-primary';
    } else {
        tabRegister.classList.add('active-tab');
        tabLogin.classList.remove('active-tab');
        registerBizGroup.style.display = 'block';
        if (registerSecurityGroup) registerSecurityGroup.style.display = 'block';
        if (loginAddons) loginAddons.style.display = 'none';
        submitText.innerText = 'Register';
        submitBtn.className = 'btn btn-emerald';
    }
}

async function handleAuthSubmit(e) {
    e.preventDefault();
    
    const usernameInput = document.getElementById('authUsername');
    const passwordInput = document.getElementById('authPassword');
    const bizNameInput = document.getElementById('authBizName');
    
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const bizName = bizNameInput.value.trim();
    
    if (!username || !password) {
        alert('Please fill out all required fields.');
        return;
    }
    
    const submitBtn = document.getElementById('authSubmitBtn');
    const submitText = document.getElementById('authSubmitText');
    if (submitBtn && submitText) {
        submitBtn.disabled = true;
        submitText.innerText = 'Processing...';
    }

    let accounts = [];
    const accountsData = localStorage.getItem('bharatpos_accounts');
    if (accountsData) {
        accounts = JSON.parse(accountsData);
    }
    
    const matchedAccount = accounts.find(acc => acc.username.toLowerCase() === username.toLowerCase());
    
    if (currentAuthTab === 'login') {
        if (!matchedAccount) {
            alert('Username not found. Please register first.');
            if (submitBtn && submitText) {
                submitBtn.disabled = false;
                submitText.innerText = 'Login';
            }
            return;
        }
        
        // Hash password with stored salt to verify
        const result = await hashPassword(username, password, matchedAccount.salt);
        if (result.hash === matchedAccount.hash) {
            try {
                const key = await deriveKey(password, matchedAccount.salt);
                activeEncryptionKey = key;
                const b64Key = await exportKeyToBase64(key);
                sessionStorage.setItem('bharatpos_session_key', b64Key);
                await completeLogin(username);
            } catch (err) {
                console.error('Login key derivation failed:', err);
                alert('An error occurred during cryptographic setup. Please try again.');
                if (submitBtn && submitText) {
                    submitBtn.disabled = false;
                    submitText.innerText = 'Login';
                }
            }
        } else {
            alert('Incorrect password. Please try again.');
            if (submitBtn && submitText) {
                submitBtn.disabled = false;
                submitText.innerText = 'Login';
            }
        }
    } else {
        // Register Tab
        if (matchedAccount) {
            alert('Username already exists. Please choose a different name.');
            if (submitBtn && submitText) {
                submitBtn.disabled = false;
                submitText.innerText = 'Register';
            }
            return;
        }
        
        const securityQuestion = document.getElementById('authSecurityQuestion').value;
        const securityAnswer = document.getElementById('authSecurityAnswer').value.trim().toLowerCase();

        if (!securityAnswer) {
            alert('Please provide a security answer for password recovery.');
            if (submitBtn && submitText) {
                submitBtn.disabled = false;
                submitText.innerText = 'Register';
            }
            return;
        }
        
        // Hash and salt password via Wasm Argon2id
        const result = await hashPassword(username, password);
        
        const newAccount = {
            username: username,
            salt: result.salt,
            hash: result.hash,
            securityQuestion: securityQuestion,
            securityAnswer: securityAnswer
        };
        
        accounts.push(newAccount);
        localStorage.setItem('bharatpos_accounts', JSON.stringify(accounts));
        
        // Seed new profile and default values with encryption
        try {
            const key = await deriveKey(password, result.salt);
            activeEncryptionKey = key;
            const b64Key = await exportKeyToBase64(key);
            sessionStorage.setItem('bharatpos_session_key', b64Key);
            
            appState.currentUser = username;
            appState.business = {
                name: bizName || username + ' Business',
                upiId: '',
                phone: '',
                address: ''
            };
            await saveBusinessProfile();
            
            // Seed default inventory values
            await loadFromLocalStorage(username);
            
            alert('Registration successful! Logging you in...');
            await completeLogin(username);
        } catch (err) {
            console.error('Registration key derivation failed:', err);
            alert('Cryptographic setup failed during registration. Please try again.');
            if (submitBtn && submitText) {
                submitBtn.disabled = false;
                submitText.innerText = 'Register';
            }
        }
    }
}

// ==========================================
// Forgot Password & Recovery Flow Handlers
// ==========================================
let recoveryUsername = '';
let isRecoveryFallback = false;

function showForgotPassword(e) {
    if (e) e.preventDefault();
    
    // Hide default auth views
    document.getElementById('authForm').style.display = 'none';
    document.getElementById('authTabs').style.display = 'none';
    document.getElementById('loginAddons').style.display = 'none';
    
    // Show recovery form
    const recoveryForm = document.getElementById('recoveryForm');
    recoveryForm.style.display = 'block';
    
    // Reset recovery steps
    document.getElementById('recoveryStep1').style.display = 'block';
    document.getElementById('recoveryStep2').style.display = 'none';
    
    document.getElementById('recoveryUsername').value = '';
    document.getElementById('recoveryAnswer').value = '';
    document.getElementById('recoveryNewPassword').value = '';
    recoveryUsername = '';
    isRecoveryFallback = false;
}

function hideForgotPassword() {
    // Show default auth views
    document.getElementById('authForm').style.display = 'block';
    document.getElementById('authTabs').style.display = 'flex';
    document.getElementById('loginAddons').style.display = 'flex';
    
    // Hide recovery form
    document.getElementById('recoveryForm').style.display = 'none';
}

function proceedToRecoveryQuestion() {
    const usernameInput = document.getElementById('recoveryUsername');
    const username = usernameInput.value.trim();
    if (!username) {
        alert('Please enter your username.');
        usernameInput.focus();
        return;
    }
    
    let accounts = [];
    const accountsData = localStorage.getItem('bharatpos_accounts');
    if (accountsData) {
        accounts = JSON.parse(accountsData);
    }
    
    const matchedAccount = accounts.find(acc => acc.username.toLowerCase() === username.toLowerCase());
    if (!matchedAccount) {
        alert('Username not found. Please verify spelling or register.');
        return;
    }
    
    recoveryUsername = matchedAccount.username; // preserve exact casing
    
    const questionTextEl = document.getElementById('recoveryQuestionText');
    
    if (matchedAccount.securityQuestion && matchedAccount.securityAnswer) {
        // Human readable mapping
        const questionsMap = {
            'phone': 'What is your registered business phone number?',
            'city': 'What city were you born in?',
            'school': 'What was the name of your first school?',
            'food': 'What is your favorite food / dish?',
            'pet': 'What was the name of your first pet?'
        };
        const questionText = questionsMap[matchedAccount.securityQuestion] || 'Enter security answer:';
        questionTextEl.innerText = questionText;
        isRecoveryFallback = false;
        
        // Show step 2
        document.getElementById('recoveryStep1').style.display = 'none';
        document.getElementById('recoveryStep2').style.display = 'block';
        document.getElementById('recoveryAnswer').focus();
    } else {
        // Fallback for existing accounts: check if business profile exists with phone number
        const bizData = localStorage.getItem(`bharatpos_${recoveryUsername.toLowerCase()}_business`);
        let hasPhoneFallback = false;
        if (bizData) {
            try {
                const bizObj = JSON.parse(bizData);
                if (bizObj && bizObj.phone) {
                    hasPhoneFallback = true;
                }
            } catch (e) {
                console.error(e);
            }
        }
        
        if (hasPhoneFallback) {
            questionTextEl.innerText = 'Fallback verification: What is your registered Business Phone Number?';
            isRecoveryFallback = true;
            
            // Show step 2
            document.getElementById('recoveryStep1').style.display = 'none';
            document.getElementById('recoveryStep2').style.display = 'block';
            document.getElementById('recoveryAnswer').focus();
        } else {
            alert('This account has no security question or business profile details configured for password recovery. Please register a new username.');
        }
    }
}

async function handleRecoverySubmit(e) {
    e.preventDefault();
    
    const answerInput = document.getElementById('recoveryAnswer');
    const newPasswordInput = document.getElementById('recoveryNewPassword');
    
    const answer = answerInput.value.trim().toLowerCase();
    const newPassword = newPasswordInput.value;
    
    if (!answer || !newPassword) {
        alert('Please fill out all recovery fields.');
        return;
    }
    
    let accounts = [];
    const accountsData = localStorage.getItem('bharatpos_accounts');
    if (accountsData) {
        accounts = JSON.parse(accountsData);
    }
    
    const accIndex = accounts.findIndex(acc => acc.username.toLowerCase() === recoveryUsername.toLowerCase());
    if (accIndex === -1) {
        alert('Account not found. Please try again.');
        return;
    }
    
    const matchedAccount = accounts[accIndex];
    let isAnswerCorrect = false;
    
    if (isRecoveryFallback) {
        // Fallback: match clean phone numbers
        const bizData = localStorage.getItem(`bharatpos_${recoveryUsername.toLowerCase()}_business`);
        if (bizData) {
            try {
                const bizObj = JSON.parse(bizData);
                const registeredPhone = bizObj.phone.replace(/\D/g, ''); // leave only digits
                const inputPhone = answer.replace(/\D/g, ''); // leave only digits
                if (registeredPhone && inputPhone && registeredPhone === inputPhone) {
                    isAnswerCorrect = true;
                }
            } catch (err) {
                console.error('Fallback verification error:', err);
            }
        }
    } else {
        // Standard check
        if (matchedAccount.securityAnswer && matchedAccount.securityAnswer.toLowerCase() === answer) {
            isAnswerCorrect = true;
        }
    }
    
    if (!isAnswerCorrect) {
        alert('Incorrect answer. Verification failed.');
        answerInput.focus();
        return;
    }
    
    // Hash new password
    try {
        const result = await hashPassword(recoveryUsername, newPassword);
        accounts[accIndex].salt = result.salt;
        accounts[accIndex].hash = result.hash;
        
        // Write back
        localStorage.setItem('bharatpos_accounts', JSON.stringify(accounts));
        alert('Password reset successful! You can now log in with your new password.');
        hideForgotPassword();
    } catch (err) {
        console.error('Password reset failed during hash:', err);
        alert('An error occurred during password hashing. Please try again.');
    }
}

async function completeLogin(username) {
    appState.currentUser = username;
    localStorage.setItem('bharatpos_current_user', username);
    
    // UI Updates
    document.getElementById('authOverlay').style.display = 'none';
    document.body.classList.remove('auth-active');
    
    const headerBadge = document.getElementById('userHeaderBadge');
    const headerUsername = document.getElementById('headerUsername');
    const logoutBtn = document.getElementById('logoutBtn');
    
    if (headerBadge) headerBadge.style.display = 'inline-flex';
    if (headerUsername) headerUsername.innerText = username;
    if (logoutBtn) logoutBtn.style.display = 'inline-flex';
    
    // Clear inputs
    document.getElementById('authUsername').value = '';
    document.getElementById('authPassword').value = '';
    document.getElementById('authBizName').value = '';
    
    const submitBtn = document.getElementById('authSubmitBtn');
    const submitText = document.getElementById('authSubmitText');
    if (submitBtn && submitText) {
        submitBtn.disabled = false;
        submitText.innerText = currentAuthTab === 'login' ? 'Login' : 'Register';
    }
    
    // Load local storage details
    await loadFromLocalStorage(username);
    
    // Apply translations
    applyTranslations();
    
    // Re-initialize UI fields
    initFormDefaults();
    
    // Auto-open Business Profile setup panel if VPA/UPI ID is missing
    if (!appState.business.upiId) {
        switchWorkspaceView('viewProfile');
    } else {
        switchWorkspaceView('viewBilling');
    }
    
    // Re-render
    autoSetNextInvoiceNumber();
    renderInventory();
    
    if (appState.items.length === 0) {
        appState.items = [
            { id: 'default-1', name: 'Chocolate Truffle Cake - 1kg', price: 650.00, purchasePrice: 450.00, qty: 1, unit: 'pcs' },
            { id: 'default-2', name: 'Pineapple Pastry', price: 80.00, purchasePrice: 50.00, qty: 2, unit: 'pcs' },
            { id: 'default-3', name: 'Garlic Bread (Loaf)', price: 90.00, purchasePrice: 60.00, qty: 1, unit: 'pcs' }
        ];
    }
    calculateInvoice();
    renderHistory();

    // Update CRM Phone autocomplete
    updateCustomerPhoneDatalist();

    // Start inactivity logout timer
    resetInactivityTimer();
}

function handleLogout() {
    if (confirm(t('confirm_logout'))) {
        // Clear active session key
        sessionStorage.removeItem('bharatpos_session_key');
        activeEncryptionKey = null;
        
        if (inactivityTimer) {
            clearTimeout(inactivityTimer);
            inactivityTimer = null;
        }

        // Reset states
        appState.currentUser = null;
        localStorage.removeItem('bharatpos_current_user');
        
        appState.business = { name: '', upiId: '', phone: '', address: '' };
        appState.customer = { name: '', phone: '', invoiceNo: 'BR-1001', date: new Date().toISOString().split('T')[0] };
        appState.items = [];
        appState.totals = { subtotal: 0, gstAmount: 0, discount: 0, grandTotal: 0 };
        appState.history = [];
        appState.inventory = [];
        
        // UI resetting
        initFormDefaults();
        switchWorkspaceView('viewBilling');
        
        // Hide badge and logout button, show auth overlay
        document.getElementById('authOverlay').style.display = 'flex';
        document.body.classList.add('auth-active');
        document.getElementById('userHeaderBadge').style.display = 'none';
        document.getElementById('logoutBtn').style.display = 'none';
        
        // Re-calculate
        calculateInvoice();
    }
}

// Hash a password using Argon2id via WebAssembly (hash-wasm)
async function hashPassword(username, password, saltHex) {
    if (typeof hashwasm === 'undefined' || typeof hashwasm.argon2id === 'undefined') {
        alert('Argon2id cryptographic library is not loaded. Please verify your network connection and reload the page.');
        throw new Error('Argon2id is not loaded.');
    }
    
    let salt;
    if (saltHex) {
        // Convert hex string back to Uint8Array
        const bytes = [];
        for (let c = 0; c < saltHex.length; c += 2) {
            bytes.push(parseInt(saltHex.substr(c, 2), 16));
        }
        salt = new Uint8Array(bytes);
    } else {
        // Generate a random 16-byte salt
        salt = new Uint8Array(16);
        if (window.crypto && window.crypto.getRandomValues) {
            window.crypto.getRandomValues(salt);
        } else {
            for (let i = 0; i < salt.length; i++) {
                salt[i] = Math.floor(Math.random() * 256);
            }
        }
    }

    const hash = await hashwasm.argon2id({
        password: password,
        salt: salt,
        parallelism: 1,
        iterations: 2,
        memorySize: 4096, // 4MB RAM (perfect for quick execution under 50ms)
        hashLength: 32,
        outputType: 'hex'
    });
    
    // Return salt and hash as hex strings
    const calculatedSaltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    return {
        hash: hash,
        salt: calculatedSaltHex
    };
}

// ==========================================
// Inactivity Session Lock & Timer Handlers
// ==========================================
let inactivityTimer = null;
const INACTIVITY_TIMEOUT = 10 * 60 * 1000; // 10 minutes

function resetInactivityTimer() {
    if (!appState.currentUser) return; // Only track logged-in sessions
    
    if (inactivityTimer) {
        clearTimeout(inactivityTimer);
    }
    
    inactivityTimer = setTimeout(() => {
        if (appState.currentUser) {
            console.log('[Inactivity] Session timeout reached. Logging out...');
            alert('Your session has expired due to inactivity. Please log in again.');
            performAutoLogout();
        }
    }, INACTIVITY_TIMEOUT);
}

function performAutoLogout() {
    appState.currentUser = null;
    localStorage.removeItem('bharatpos_current_user');
    sessionStorage.removeItem('bharatpos_session_key');
    activeEncryptionKey = null;
    
    if (inactivityTimer) {
        clearTimeout(inactivityTimer);
        inactivityTimer = null;
    }
    
    appState.business = { name: '', upiId: '', phone: '', address: '' };
    appState.customer = { name: '', phone: '', invoiceNo: 'BR-1001', date: new Date().toISOString().split('T')[0] };
    appState.items = [];
    appState.totals = { subtotal: 0, gstAmount: 0, discount: 0, grandTotal: 0 };
    appState.history = [];
    appState.inventory = [];
    
    initFormDefaults();
    switchWorkspaceView('viewBilling');
    
    document.getElementById('authOverlay').style.display = 'flex';
    document.body.classList.add('auth-active');
    document.getElementById('userHeaderBadge').style.display = 'none';
    document.getElementById('logoutBtn').style.display = 'none';
    
    calculateInvoice();
}

// ==========================================
// Database Maintenance (Backup & Restore)
// ==========================================
async function exportStoreBackup() {
    if (!appState.currentUser) {
        alert('Please login first to export your backup.');
        return;
    }
    
    const backupData = {
        business: appState.business,
        inventory: appState.inventory,
        history: appState.history
    };
    
    const jsonStr = JSON.stringify(backupData);
    let fileContent;
    let filename;
    
    if (activeEncryptionKey) {
        try {
            const encrypted = await encryptData(jsonStr, activeEncryptionKey);
            const payload = {
                bharatpos_encrypted_backup: true,
                username: appState.currentUser,
                payload: encrypted
            };
            fileContent = JSON.stringify(payload, null, 2);
            filename = `BharatPOS_Backup_Encrypted_${appState.currentUser}_${new Date().toISOString().split('T')[0]}.json`;
        } catch (e) {
            console.error('Failed to encrypt backup:', e);
            alert('Error encrypting backup file.');
            return;
        }
    } else {
        const payload = {
            bharatpos_backup: true,
            username: appState.currentUser,
            business: appState.business,
            inventory: appState.inventory,
            history: appState.history
        };
        fileContent = JSON.stringify(payload, null, 2);
        filename = `BharatPOS_Backup_Plain_${appState.currentUser}_${new Date().toISOString().split('T')[0]}.json`;
    }
    
    const blob = new Blob([fileContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function importStoreBackup(input) {
    const file = input.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = async function(e) {
        try {
            const content = e.target.result;
            const data = JSON.parse(content);
            
            let decryptedState = null;
            
            if (data.bharatpos_encrypted_backup || data.vyaparflow_encrypted_backup) {
                if (!activeEncryptionKey) {
                    alert('This is an encrypted backup. Please login to decrypt and import it.');
                    input.value = '';
                    return;
                }
                
                try {
                    const decrypted = await decryptData(data.payload, activeEncryptionKey);
                    decryptedState = JSON.parse(decrypted);
                } catch (err) {
                    console.error('Decryption failed for backup:', err);
                    alert('Failed to decrypt the backup file. The backup was encrypted with a different key/password.');
                    input.value = '';
                    return;
                }
            } else if (data.bharatpos_backup || data.vyaparflow_backup) {
                decryptedState = data;
            } else {
                alert('Invalid backup file format.');
                input.value = '';
                return;
            }
            
            if (!decryptedState || typeof decryptedState !== 'object') {
                alert('Invalid backup data structure.');
                input.value = '';
                return;
            }
            
            if (decryptedState.business) appState.business = decryptedState.business;
            if (decryptedState.inventory) appState.inventory = decryptedState.inventory;
            if (decryptedState.history) appState.history = decryptedState.history;
            
            await saveBusinessProfile();
            await saveInventory();
            await saveHistory();
            
            initFormDefaults();
            updatePreview();
            renderInventory();
            renderHistory();
            calculateInvoice();
            
            alert('Database restored successfully from backup!');
        } catch (err) {
            console.error('Backup import parsing failed:', err);
            alert('Failed to import backup file. Ensure the file is not corrupted.');
        }
        
        input.value = '';
    };
    reader.readAsText(file);
}

// Global active drilldown invoices array for filtering/searching
let activeDrilldownInvoices = [];
let activeDrilldownType = '';
let activeDrilldownExtraVal = null;

function getAnalyticsDateRange(preset) {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    let start = new Date(today);
    let end = new Date(today);
    end.setHours(23, 59, 59, 999);
    
    if (preset === 'today') {
        // start and end are already today
    } else if (preset === 'yesterday') {
        start.setDate(start.getDate() - 1);
        end.setDate(end.getDate() - 1);
        end.setHours(23, 59, 59, 999);
    } else if (preset === 'last7') {
        start.setDate(start.getDate() - 6);
    } else if (preset === 'last30') {
        start.setDate(start.getDate() - 29);
    } else if (preset === 'thismonth') {
        start = new Date(today.getFullYear(), today.getMonth(), 1);
    } else if (preset === 'all') {
        start = new Date(1970, 0, 1);
    } else if (preset === 'custom') {
        const startVal = document.getElementById('analyticsStartDate') ? document.getElementById('analyticsStartDate').value : '';
        const endVal = document.getElementById('analyticsEndDate') ? document.getElementById('analyticsEndDate').value : '';
        if (startVal) {
            start = new Date(startVal);
            start.setHours(0,0,0,0);
        }
        if (endVal) {
            end = new Date(endVal);
            end.setHours(23,59,59,999);
        }
    }
    
    return { start, end };
}

function getFilteredInvoicesByDateRange() {
    const presetSelect = document.getElementById('analyticsDatePreset');
    const preset = presetSelect ? presetSelect.value : (appState.analyticsFilter.preset || 'last7');
    const { start, end } = getAnalyticsDateRange(preset);
    const startStr = start.toISOString().split('T')[0];
    const endStr = end.toISOString().split('T')[0];
    const history = appState.history || [];
    return history.filter(inv => inv.date && inv.date >= startStr && inv.date <= endStr);
}

function handleStatCardClick(type) {
    const rangeInvoices = getFilteredInvoicesByDateRange();
    let invoices = [];
    let title = '';
    
    if (type === 'sales') {
        invoices = rangeInvoices.filter(inv => inv.status === 'Paid');
        title = 'Total Sales Breakdown';
    } else if (type === 'profit') {
        invoices = rangeInvoices.filter(inv => inv.status === 'Paid');
        title = 'Profit Breakdown';
    } else if (type === 'upi') {
        invoices = rangeInvoices.filter(inv => inv.status === 'Paid' && (!inv.paymentMode || inv.paymentMode.toLowerCase() === 'upi'));
        title = 'UPI Sales Breakdown';
    } else if (type === 'cash') {
        invoices = rangeInvoices.filter(inv => inv.status === 'Paid' && inv.paymentMode && inv.paymentMode.toLowerCase() === 'cash');
        title = 'Cash Sales Breakdown';
    } else if (type === 'card') {
        invoices = rangeInvoices.filter(inv => inv.status === 'Paid' && inv.paymentMode && inv.paymentMode.toLowerCase() === 'card');
        title = 'Card Sales Breakdown';
    } else if (type === 'pending') {
        invoices = rangeInvoices.filter(inv => inv.status === 'Pending');
        title = 'Pending Invoices';
    } else if (type === 'refund') {
        invoices = rangeInvoices.filter(inv => inv.status === 'Refunded');
        title = 'Refunded Invoices';
    } else if (type === 'avg') {
        invoices = rangeInvoices.filter(inv => inv.status === 'Paid');
        title = 'Average Ticket Invoices';
    } else if (type === 'count') {
        invoices = rangeInvoices;
        title = 'All Transactions List';
    }
    
    activeDrilldownInvoices = invoices;
    activeDrilldownType = type;
    activeDrilldownExtraVal = null;
    openDrilldown(title, invoices, type);
}

function handleDateClickDrilldown(selectedDate) {
    const history = appState.history || [];
    const invoices = history.filter(inv => inv.date === selectedDate && inv.status === 'Paid');
    const formattedDate = new Date(selectedDate).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
    
    activeDrilldownInvoices = invoices;
    activeDrilldownType = 'date';
    activeDrilldownExtraVal = null;
    openDrilldown(`Sales for ${formattedDate}`, invoices, 'sales');
}

function handleProductClickDrilldown(productName) {
    const rangeInvoices = getFilteredInvoicesByDateRange();
    const invoices = rangeInvoices.filter(inv => {
        return inv.status === 'Paid' && inv.items && inv.items.some(item => item.name === productName);
    });
    
    activeDrilldownInvoices = invoices;
    activeDrilldownType = 'product';
    activeDrilldownExtraVal = productName;
    openDrilldown(`Sales of "${productName}"`, invoices, 'product', productName);
}

function handleCategoryClickDrilldown(categoryName) {
    const rangeInvoices = getFilteredInvoicesByDateRange();
    const invoices = rangeInvoices.filter(inv => {
        return inv.status === 'Paid' && inv.items && inv.items.some(item => {
            const matchedProduct = appState.inventory.find(p => p.name.toLowerCase() === item.name.toLowerCase());
            const cat = matchedProduct ? (matchedProduct.sku || 'General') : 'General';
            return cat === categoryName;
        });
    });
    
    activeDrilldownInvoices = invoices;
    activeDrilldownType = 'category';
    activeDrilldownExtraVal = categoryName;
    openDrilldown(`Sales of Category "${categoryName}"`, invoices, 'category', categoryName);
}

function openDrilldown(title, invoices, type, extraFilterVal = null) {
    const overlay = document.getElementById('drilldownOverlay');
    const titleEl = document.getElementById('drilldownTitle');
    const searchInput = document.getElementById('drilldownSearch');
    
    if (titleEl) titleEl.innerText = title;
    if (searchInput) searchInput.value = '';
    
    renderDrilldownTable(invoices, type, extraFilterVal);
    
    if (overlay) {
        overlay.style.display = 'flex';
        overlay.style.animation = 'authFadeIn 0.3s cubic-bezier(0.16, 1, 0.3, 1)';
    }
}

function closeDrilldown() {
    const overlay = document.getElementById('drilldownOverlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

function renderDrilldownTable(invoices, type, extraFilterVal = null, searchQuery = '') {
    const tbody = document.getElementById('drilldownTableBody');
    const totalSumEl = document.getElementById('drilldownTotalSum');
    const countEl = document.getElementById('drilldownCount');
    
    if (!tbody) return;
    tbody.innerHTML = '';
    
    const query = searchQuery.toLowerCase().trim();
    
    const filtered = invoices.filter(inv => {
        if (!query) return true;
        const name = (inv.customerName || '').toLowerCase();
        const no = (inv.invoiceNo || '').toLowerCase();
        const phone = (inv.customerPhone || '').toLowerCase();
        return name.includes(query) || no.includes(query) || phone.includes(query);
    });
    
    let totalSum = 0;
    
    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center text-muted" style="padding: 2rem 0; text-align: center;">No matching invoices found.</td>
            </tr>
        `;
    } else {
        filtered.forEach(inv => {
            let rowAmount = inv.totals ? inv.totals.grandTotal : 0;
            let displayAmount = rowAmount;
            
            if (type === 'profit') {
                let cogs = 0;
                if (inv.items) {
                    inv.items.forEach(item => {
                        cogs += (item.purchasePrice || 0) * item.qty;
                    });
                }
                const subtotal = inv.totals ? (inv.totals.subtotal || 0) : 0;
                const discount = inv.totals ? (inv.totals.discount || 0) : 0;
                const netRevenue = subtotal - discount;
                const profit = netRevenue - cogs;
                displayAmount = profit;
                totalSum += profit;
            } else if (type === 'product' && extraFilterVal) {
                let productSum = 0;
                if (inv.items) {
                    inv.items.forEach(item => {
                        if (item.name === extraFilterVal) {
                            productSum += item.price * item.qty;
                        }
                    });
                }
                displayAmount = productSum;
                totalSum += productSum;
            } else if (type === 'category' && extraFilterVal) {
                let categorySum = 0;
                if (inv.items) {
                    inv.items.forEach(item => {
                        const matchedProduct = appState.inventory.find(p => p.name.toLowerCase() === item.name.toLowerCase());
                        const cat = matchedProduct ? (matchedProduct.sku || 'General') : 'General';
                        if (cat === extraFilterVal) {
                            categorySum += item.price * item.qty;
                        }
                    });
                }
                displayAmount = categorySum;
                totalSum += categorySum;
            } else {
                totalSum += rowAmount;
            }
            
            const invDate = inv.date || '---';
            const formattedDate = invDate !== '---' ? new Date(invDate).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' }) : '---';
            const custName = inv.customerName || 'Guest';
            const payMode = inv.paymentMode ? inv.paymentMode.toUpperCase() : 'UPI';
            const invoiceNo = inv.invoiceNo || 'INV-000';
            
            const tr = document.createElement('tr');
            tr.className = 'drilldown-row';
            tr.innerHTML = `
                <td style="padding: 0.75rem 1rem; border-bottom: 1px solid var(--border-color); font-weight: 600;">#${invoiceNo}</td>
                <td style="padding: 0.75rem 1rem; border-bottom: 1px solid var(--border-color); color: var(--text-secondary);">${formattedDate}</td>
                <td style="padding: 0.75rem 1rem; border-bottom: 1px solid var(--border-color); color: var(--text-primary);">${escapeHtml(custName)}</td>
                <td style="padding: 0.75rem 1rem; border-bottom: 1px solid var(--border-color); color: var(--text-secondary);">${payMode}</td>
                <td style="padding: 0.75rem 1rem; border-bottom: 1px solid var(--border-color); text-align: right; font-weight: 600; color: var(--text-primary);">₹${displayAmount.toFixed(2)}</td>
                <td style="padding: 0.75rem 1rem; border-bottom: 1px solid var(--border-color); text-align: center;">
                    <button type="button" class="btn btn-secondary" style="padding: 0.25rem 0.5rem; font-size: 0.75rem; height: auto;" onclick="viewInvoiceFromDrilldown('${inv.id || invoiceNo}')">
                        <i data-lucide="eye" style="width: 14px; height: 14px; display: inline-block; vertical-align: middle;"></i> View
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }
    
    totalSumEl.innerText = `₹${totalSum.toFixed(2)}`;
    countEl.innerText = `(${filtered.length} Invoices)`;
    
    if (typeof lucide !== 'undefined' && lucide.createIcons) {
        lucide.createIcons();
    }
}

function viewInvoiceFromDrilldown(invoiceId) {
    closeDrilldown();
    switchWorkspaceView('viewBilling');
    const inv = appState.history.find(i => i.id === invoiceId || i.invoiceNo === invoiceId);
    if (inv) {
        // Expand the history card if it's collapsed
        const historyCard = document.getElementById('historyCard');
        if (historyCard) {
            historyCard.classList.remove('collapsed');
        }
        
        const searchInput = document.getElementById('searchHistoryInput');
        if (searchInput) {
            searchInput.value = inv.invoiceNo;
            filterHistory();
        }
        
        if (historyCard) {
            historyCard.scrollIntoView({ behavior: 'smooth' });
        }
    }
}

function initAnalyticsEvents() {
    const trendCanvas = document.getElementById('salesTrendChart');
    if (trendCanvas) {
        // Remove existing to prevent duplicate bindings if called multiple times
        const newTrendCanvas = trendCanvas.cloneNode(true);
        trendCanvas.parentNode.replaceChild(newTrendCanvas, trendCanvas);
        
        newTrendCanvas.addEventListener('click', (e) => {
            const rect = newTrendCanvas.getBoundingClientRect();
            const clickX = e.clientX - rect.left;
            
            const xPositions = newTrendCanvas._xPositions;
            const dateObjects = newTrendCanvas._dateObjects;
            if (!xPositions || !dateObjects) return;
            
            let closestIdx = -1;
            let minDistance = 25;
            for (let i = 0; i < xPositions.length; i++) {
                const dist = Math.abs(xPositions[i] - clickX);
                if (dist < minDistance) {
                    minDistance = dist;
                    closestIdx = i;
                }
            }
            
            if (closestIdx !== -1) {
                const selectedDate = dateObjects[closestIdx];
                handleDateClickDrilldown(selectedDate);
            }
        });
        newTrendCanvas.style.cursor = 'pointer';
    }

    const productsCanvas = document.getElementById('topProductsChart');
    if (productsCanvas) {
        const newProductsCanvas = productsCanvas.cloneNode(true);
        productsCanvas.parentNode.replaceChild(newProductsCanvas, productsCanvas);
        
        newProductsCanvas.addEventListener('click', (e) => {
            const rect = newProductsCanvas.getBoundingClientRect();
            const clickY = e.clientY - rect.top;
            
            const yPositions = newProductsCanvas._yPositions;
            const productNames = newProductsCanvas._productNames;
            if (!yPositions || !productNames) return;
            
            let closestIdx = -1;
            let minDistance = 20;
            for (let i = 0; i < yPositions.length; i++) {
                const dist = Math.abs(yPositions[i] - clickY);
                if (dist < minDistance) {
                    minDistance = dist;
                    closestIdx = i;
                }
            }
            
            if (closestIdx !== -1) {
                const productName = productNames[closestIdx];
                handleProductClickDrilldown(productName);
            }
        });
        newProductsCanvas.style.cursor = 'pointer';
    }

    const paymentCanvas = document.getElementById('paymentModeChart');
    if (paymentCanvas) {
        const newPaymentCanvas = paymentCanvas.cloneNode(true);
        paymentCanvas.parentNode.replaceChild(newPaymentCanvas, paymentCanvas);
        
        newPaymentCanvas.addEventListener('click', (e) => {
            const rect = newPaymentCanvas.getBoundingClientRect();
            const clickX = e.clientX - rect.left;
            const clickY = e.clientY - rect.top;
            
            const slices = newPaymentCanvas._slices;
            if (!slices || slices.length === 0) return;
            
            const centerX = slices[0].centerX;
            const centerY = slices[0].centerY;
            const radius = slices[0].radius;
            const innerRadius = slices[0].innerRadius;
            
            const dx = clickX - centerX;
            const dy = clickY - centerY;
            const dist = Math.sqrt(dx*dx + dy*dy);
            
            if (dist >= innerRadius && dist <= radius) {
                let clickAngle = Math.atan2(dy, dx);
                if (clickAngle < -Math.PI / 2) {
                    clickAngle += Math.PI * 2;
                }
                
                const matchedSlice = slices.find(slice => {
                    return clickAngle >= slice.startAngle && clickAngle < slice.endAngle;
                });
                
                if (matchedSlice) {
                    handleStatCardClick(matchedSlice.label.toLowerCase());
                }
            }
        });
        newPaymentCanvas.style.cursor = 'pointer';
    }

    const categoryCanvas = document.getElementById('categoryShareChart');
    if (categoryCanvas) {
        const newCategoryCanvas = categoryCanvas.cloneNode(true);
        categoryCanvas.parentNode.replaceChild(newCategoryCanvas, categoryCanvas);
        
        newCategoryCanvas.addEventListener('click', (e) => {
            const rect = newCategoryCanvas.getBoundingClientRect();
            const clickX = e.clientX - rect.left;
            const clickY = e.clientY - rect.top;
            
            const slices = newCategoryCanvas._slices;
            if (!slices || slices.length === 0) return;
            
            const centerX = slices[0].centerX;
            const centerY = slices[0].centerY;
            const radius = slices[0].radius;
            const innerRadius = slices[0].innerRadius;
            
            const dx = clickX - centerX;
            const dy = clickY - centerY;
            const dist = Math.sqrt(dx*dx + dy*dy);
            
            if (dist >= innerRadius && dist <= radius) {
                let clickAngle = Math.atan2(dy, dx);
                if (clickAngle < -Math.PI / 2) {
                    clickAngle += Math.PI * 2;
                }
                
                const matchedSlice = slices.find(slice => {
                    return clickAngle >= slice.startAngle && clickAngle < slice.endAngle;
                });
                
                if (matchedSlice) {
                    handleCategoryClickDrilldown(matchedSlice.label);
                }
            }
        });
        newCategoryCanvas.style.cursor = 'pointer';
    }
}

// ==========================================
// Sales Analytics Dashboard Renderers
// ==========================================
function renderAnalytics() {
    const history = appState.history || [];
    const presetSelect = document.getElementById('analyticsDatePreset');
    const preset = presetSelect ? presetSelect.value : (appState.analyticsFilter.preset || 'last7');
    
    let { start, end } = getAnalyticsDateRange(preset);
    
    const customDates = document.getElementById('analyticsCustomDates');
    if (preset === 'custom') {
        if (customDates) customDates.style.display = 'flex';
        const startInput = document.getElementById('analyticsStartDate');
        const endInput = document.getElementById('analyticsEndDate');
        if (startInput && !startInput.value) {
            startInput.value = start.toISOString().split('T')[0];
        }
        if (endInput && !endInput.value) {
            endInput.value = end.toISOString().split('T')[0];
        }
    } else {
        if (customDates) customDates.style.display = 'none';
    }
    
    const startStr = start.toISOString().split('T')[0];
    const endStr = end.toISOString().split('T')[0];
    
    // Filter history based on dates
    const filteredInvoices = history.filter(inv => {
        if (!inv.date) return false;
        return inv.date >= startStr && inv.date <= endStr;
    });
    
    // Construct dateObjects and dayLabels for the chart
    const salesByDay = {};
    const profitByDay = {};
    const dayLabels = [];
    const dateObjects = [];
    
    // If range is 1 day (today or yesterday), we adjust the chart start date back 1 day so it draws a comparison line
    let chartStart = new Date(start);
    if (preset === 'today' || preset === 'yesterday') {
        chartStart.setDate(chartStart.getDate() - 1);
    }
    
    let curr = new Date(chartStart);
    curr.setHours(12, 0, 0, 0);
    const stopDate = new Date(end);
    stopDate.setHours(12, 0, 0, 0);
    
    let chartDayCount = 0;
    while (curr <= stopDate && chartDayCount < 100) {
        const dateString = curr.toISOString().split('T')[0];
        salesByDay[dateString] = 0;
        profitByDay[dateString] = 0;
        
        const label = curr.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });
        dayLabels.push(label);
        dateObjects.push(dateString);
        
        curr.setDate(curr.getDate() + 1);
        chartDayCount++;
    }

    let totalSales = 0;
    let totalProfit = 0;
    let upiSales = 0;
    let cashSales = 0;
    let cardSales = 0;
    let pendingSales = 0;
    let totalRefunds = 0;
    let totalCount = filteredInvoices.length;
    let paidCount = 0;
    
    const productSales = {};
    const categorySales = {};
    
    filteredInvoices.forEach(inv => {
        const invTotal = inv.totals ? inv.totals.grandTotal : 0;
        const isPaid = inv.status === 'Paid';
        
        if (isPaid) {
            totalSales += invTotal;
            paidCount++;
            
            // Calculate COGS and Profit
            let cogs = 0;
            if (inv.items) {
                inv.items.forEach(item => {
                    cogs += (item.purchasePrice || 0) * item.qty;
                });
            }
            const subtotal = inv.totals ? (inv.totals.subtotal || 0) : 0;
            const discount = inv.totals ? (inv.totals.discount || 0) : 0;
            const netRevenue = subtotal - discount;
            const profit = netRevenue - cogs;
            totalProfit += profit;
            
            const mode = inv.paymentMode ? inv.paymentMode.toLowerCase() : 'upi';
            if (mode === 'cash') {
                cashSales += invTotal;
            } else if (mode === 'card') {
                cardSales += invTotal;
            } else {
                upiSales += invTotal;
            }
            
            const invDate = inv.date;
            if (salesByDay[invDate] !== undefined) {
                salesByDay[invDate] += invTotal;
            }
            if (profitByDay[invDate] !== undefined) {
                profitByDay[invDate] += profit;
            }
        } else if (inv.status === 'Pending') {
            pendingSales += invTotal;
        } else if (inv.status === 'Refunded') {
            totalRefunds += invTotal;
        }
        
        if (isPaid && inv.items) {
            inv.items.forEach(item => {
                const name = item.name;
                const qty = item.qty || 0;
                productSales[name] = (productSales[name] || 0) + qty;
                
                // Track category sales
                const matchedProduct = appState.inventory.find(p => p.name.toLowerCase() === name.toLowerCase());
                const category = matchedProduct ? (matchedProduct.sku || 'General') : 'General';
                const itemRevenue = item.price * qty;
                categorySales[category] = (categorySales[category] || 0) + itemRevenue;
            });
        }
    });
    
    const avgTicket = paidCount > 0 ? (totalSales / paidCount) : 0;
    
    const totalSalesEl = document.getElementById('analyticsTotalSales');
    const totalProfitEl = document.getElementById('analyticsTotalProfit');
    const upiSalesEl = document.getElementById('analyticsUpiSales');
    const cashSalesEl = document.getElementById('analyticsCashSales');
    const cardSalesEl = document.getElementById('analyticsCardSales');
    const pendingSalesEl = document.getElementById('analyticsPendingPayments');
    const refundedSalesEl = document.getElementById('analyticsRefundedSales');
    const avgTicketEl = document.getElementById('analyticsAvgTicket');
    const totalCountEl = document.getElementById('analyticsTotalCount');
    
    if (totalSalesEl) totalSalesEl.innerText = `₹${totalSales.toFixed(2)}`;
    if (totalProfitEl) totalProfitEl.innerText = `₹${totalProfit.toFixed(2)}`;
    if (upiSalesEl) upiSalesEl.innerText = `₹${upiSales.toFixed(2)}`;
    if (cashSalesEl) cashSalesEl.innerText = `₹${cashSales.toFixed(2)}`;
    if (cardSalesEl) cardSalesEl.innerText = `₹${cardSales.toFixed(2)}`;
    if (pendingSalesEl) pendingSalesEl.innerText = `₹${pendingSales.toFixed(2)}`;
    if (refundedSalesEl) refundedSalesEl.innerText = `₹${totalRefunds.toFixed(2)}`;
    if (avgTicketEl) avgTicketEl.innerText = `₹${avgTicket.toFixed(2)}`;
    if (totalCountEl) totalCountEl.innerText = totalCount;
    
    drawSalesTrendChart(dateObjects, dayLabels, salesByDay, profitByDay);
    drawTopProductsChart(productSales);
    drawPaymentModeChart(upiSales, cashSales, cardSales);
    drawCategoryShareChart(categorySales);
}

function drawSalesTrendChart(dateObjects, dayLabels, salesByDay, profitByDay) {
    const canvas = document.getElementById('salesTrendChart');
    if (!canvas) return;
    
    const rect = canvas.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);
    
    const salesData = dateObjects.map(date => salesByDay[date] || 0);
    const profitData = dateObjects.map(date => profitByDay[date] || 0);
    const maxVal = Math.max(...salesData, ...profitData, 100);
    
    const paddingLeft = 55;
    const paddingRight = 20;
    const paddingTop = 45;
    const paddingBottom = 40;
    
    const graphWidth = width - paddingLeft - paddingRight;
    const graphHeight = height - paddingTop - paddingBottom;
    
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    const textColor = isDark ? '#a5b4fc' : '#312e81';
    const gridColor = isDark ? 'rgba(99, 102, 241, 0.08)' : 'rgba(79, 70, 229, 0.08)';
    const salesLineColor = isDark ? '#6366f1' : '#4f46e5';
    const profitLineColor = isDark ? '#f97316' : '#ea580c';
    
    ctx.font = '10px var(--font-body)';
    ctx.fillStyle = textColor;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    
    const yGridLines = 4;
    for (let i = 0; i < yGridLines; i++) {
        const yVal = (maxVal / (yGridLines - 1)) * i;
        const yPos = height - paddingBottom - (graphHeight / (yGridLines - 1)) * i;
        
        ctx.fillText(`₹${Math.round(yVal)}`, paddingLeft - 10, yPos);
        
        ctx.beginPath();
        ctx.strokeStyle = gridColor;
        ctx.lineWidth = 1;
        ctx.moveTo(paddingLeft, yPos);
        ctx.lineTo(width - paddingRight, yPos);
        ctx.stroke();
    }
    
    const xPositions = [];
    if (salesData.length === 1) {
        xPositions.push(paddingLeft + graphWidth / 2);
    } else {
        for (let i = 0; i < salesData.length; i++) {
            const xPos = paddingLeft + (graphWidth / (salesData.length - 1)) * i;
            xPositions.push(xPos);
        }
    }
    
    // Cache xPositions and dateObjects for click events
    canvas._xPositions = xPositions;
    canvas._dateObjects = dateObjects;
    
    // --- DRAW SALES AREA & LINE ---
    ctx.beginPath();
    ctx.moveTo(xPositions[0], height - paddingBottom);
    for (let i = 0; i < salesData.length; i++) {
        const yPos = height - paddingBottom - (graphHeight * (salesData[i] / maxVal));
        ctx.lineTo(xPositions[i], yPos);
    }
    ctx.lineTo(xPositions[xPositions.length - 1], height - paddingBottom);
    ctx.closePath();
    
    const salesGradient = ctx.createLinearGradient(0, paddingTop, 0, height - paddingBottom);
    salesGradient.addColorStop(0, isDark ? 'rgba(99, 102, 241, 0.25)' : 'rgba(79, 70, 229, 0.2)');
    salesGradient.addColorStop(1, 'rgba(99, 102, 241, 0.0)');
    ctx.fillStyle = salesGradient;
    ctx.fill();
    
    ctx.beginPath();
    ctx.strokeStyle = salesLineColor;
    ctx.lineWidth = 3;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    for (let i = 0; i < salesData.length; i++) {
        const yPos = height - paddingBottom - (graphHeight * (salesData[i] / maxVal));
        if (i === 0) {
            ctx.moveTo(xPositions[i], yPos);
        } else {
            ctx.lineTo(xPositions[i], yPos);
        }
    }
    ctx.stroke();
    
    // --- DRAW PROFIT AREA & LINE ---
    ctx.beginPath();
    ctx.moveTo(xPositions[0], height - paddingBottom);
    for (let i = 0; i < profitData.length; i++) {
        const yPos = height - paddingBottom - (graphHeight * (profitData[i] / maxVal));
        ctx.lineTo(xPositions[i], yPos);
    }
    ctx.lineTo(xPositions[xPositions.length - 1], height - paddingBottom);
    ctx.closePath();
    
    const profitGradient = ctx.createLinearGradient(0, paddingTop, 0, height - paddingBottom);
    profitGradient.addColorStop(0, isDark ? 'rgba(249, 115, 22, 0.25)' : 'rgba(234, 88, 12, 0.2)');
    profitGradient.addColorStop(1, 'rgba(249, 115, 22, 0.0)');
    ctx.fillStyle = profitGradient;
    ctx.fill();
    
    ctx.beginPath();
    ctx.strokeStyle = profitLineColor;
    ctx.lineWidth = 2.5;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    for (let i = 0; i < profitData.length; i++) {
        const yPos = height - paddingBottom - (graphHeight * (profitData[i] / maxVal));
        if (i === 0) {
            ctx.moveTo(xPositions[i], yPos);
        } else {
            ctx.lineTo(xPositions[i], yPos);
        }
    }
    ctx.stroke();
    
    // Draw Dots & values
    for (let i = 0; i < salesData.length; i++) {
        const yPosSales = height - paddingBottom - (graphHeight * (salesData[i] / maxVal));
        const yPosProfit = height - paddingBottom - (graphHeight * (profitData[i] / maxVal));
        
        ctx.beginPath();
        ctx.arc(xPositions[i], yPosSales, 4, 0, Math.PI * 2);
        ctx.fillStyle = isDark ? '#ffffff' : salesLineColor;
        ctx.fill();
        ctx.strokeStyle = salesLineColor;
        ctx.lineWidth = 1.5;
        ctx.stroke();
        
        ctx.beginPath();
        ctx.arc(xPositions[i], yPosProfit, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = isDark ? '#ffffff' : profitLineColor;
        ctx.fill();
        ctx.strokeStyle = profitLineColor;
        ctx.lineWidth = 1.5;
        ctx.stroke();
        
        if (salesData[i] > 0) {
            ctx.font = 'bold 8.5px var(--font-body)';
            ctx.fillStyle = isDark ? '#e0e7ff' : '#312e81';
            ctx.textAlign = 'center';
            ctx.fillText(`₹${Math.round(salesData[i])}`, xPositions[i], yPosSales - 10);
        }
        if (profitData[i] > 0 && Math.abs(yPosSales - yPosProfit) > 15) {
            ctx.font = 'bold 8.5px var(--font-body)';
            ctx.fillStyle = isDark ? '#ffedd5' : '#7c2d12';
            ctx.textAlign = 'center';
            ctx.fillText(`₹${Math.round(profitData[i])}`, xPositions[i], yPosProfit + 10);
        }
    }
    
    // Draw legend
    ctx.font = '10px var(--font-body)';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    
    ctx.fillStyle = salesLineColor;
    ctx.beginPath();
    ctx.arc(paddingLeft + 10, 18, 5, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = textColor;
    ctx.fillText('Sales Revenue', paddingLeft + 20, 18);
    
    ctx.fillStyle = profitLineColor;
    ctx.beginPath();
    ctx.arc(paddingLeft + 120, 18, 5, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = textColor;
    ctx.fillText('Net Profit', paddingLeft + 130, 18);
    
    ctx.font = '10px var(--font-body)';
    ctx.fillStyle = textColor;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    
    let labelStep = 1;
    if (dayLabels.length > 10) {
        labelStep = Math.ceil(dayLabels.length / 8);
    }
    for (let i = 0; i < dayLabels.length; i += labelStep) {
        ctx.fillText(dayLabels[i], xPositions[i], height - paddingBottom + 8);
    }
}

function drawTopProductsChart(productSales) {
    const canvas = document.getElementById('topProductsChart');
    if (!canvas) return;
    
    const rect = canvas.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);
    
    const sortedProducts = Object.entries(productSales)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);
        
    if (sortedProducts.length === 0) {
        ctx.font = '14px var(--font-body)';
        ctx.fillStyle = '#64748b';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('No product sales data yet.', width / 2, height / 2);
        
        canvas._yPositions = [];
        canvas._productNames = [];
        return;
    }
    
    const maxQty = Math.max(...sortedProducts.map(p => p[1]), 1);
    
    const paddingLeft = 130;
    const paddingRight = 60;
    const paddingTop = 20;
    const paddingBottom = 20;
    
    const graphWidth = width - paddingLeft - paddingRight;
    const graphHeight = height - paddingTop - paddingBottom;
    
    const barCount = sortedProducts.length;
    const barHeight = Math.min(24, graphHeight / (barCount * 1.5));
    const spacing = (graphHeight - (barHeight * barCount)) / (barCount + 1);
    
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    const textColor = isDark ? '#a5b4fc' : '#312e81';
    const barColor = isDark ? '#6366f1' : '#4f46e5';
    
    ctx.font = '11px var(--font-body)';
    ctx.textBaseline = 'middle';
    
    const yPositions = [];
    const productNames = [];
    
    for (let i = 0; i < barCount; i++) {
        const [name, qty] = sortedProducts[i];
        const yPos = paddingTop + spacing + (barHeight + spacing) * i;
        
        yPositions.push(yPos + barHeight / 2);
        productNames.push(name);
        
        ctx.fillStyle = textColor;
        ctx.textAlign = 'right';
        let displayName = name;
        if (displayName.length > 20) {
            displayName = displayName.substring(0, 18) + '...';
        }
        ctx.fillText(displayName, paddingLeft - 10, yPos + barHeight / 2);
        
        const barWidth = graphWidth * (qty / maxQty);
        
        ctx.beginPath();
        ctx.fillStyle = barColor;
        
        const radius = 4;
        ctx.roundRect(paddingLeft, yPos, barWidth, barHeight, [0, radius, radius, 0]);
        ctx.fill();
        
        ctx.fillStyle = isDark ? '#e0e7ff' : '#1e1b4b';
        ctx.textAlign = 'left';
        ctx.font = 'bold 10px var(--font-body)';
        ctx.fillText(`${qty} units`, paddingLeft + barWidth + 8, yPos + barHeight / 2);
    }
    
    canvas._yPositions = yPositions;
    canvas._productNames = productNames;
}

function drawPaymentModeChart(upi, cash, card) {
    const canvas = document.getElementById('paymentModeChart');
    if (!canvas) return;
    
    const rect = canvas.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);
    
    const total = upi + cash + card;
    if (total === 0) {
        ctx.font = '14px var(--font-body)';
        ctx.fillStyle = '#64748b';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('No sales data to display.', width / 2, height / 2);
        
        canvas._slices = [];
        return;
    }
    
    const data = [
        { label: 'UPI', value: upi, color: '#6366f1' },
        { label: 'Cash', value: cash, color: '#10b981' },
        { label: 'Card', value: card, color: '#a855f7' }
    ];
    
    const centerX = width * 0.38;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) * 0.72;
    const innerRadius = radius * 0.55;
    
    let startAngle = -Math.PI / 2;
    const slices = [];
    
    data.forEach(slice => {
        const sliceAngle = (slice.value / total) * Math.PI * 2;
        if (sliceAngle === 0) return;
        
        // Save slice info for clicks
        slices.push({
            label: slice.label,
            startAngle: startAngle,
            endAngle: startAngle + sliceAngle,
            centerX: centerX,
            centerY: centerY,
            radius: radius,
            innerRadius: innerRadius
        });
        
        // Draw Outer Arc and Inner Arc for Donut
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
        ctx.arc(centerX, centerY, innerRadius, startAngle + sliceAngle, startAngle, true);
        ctx.closePath();
        
        ctx.fillStyle = slice.color;
        ctx.fill();
        
        startAngle += sliceAngle;
    });
    
    // Save on canvas for clicks
    canvas._slices = slices;
    canvas._totalVal = total;
    
    // Draw Legend on the right side
    const legendX = width * 0.72;
    const legendYStart = height / 2 - (data.length * 22) / 2 + 11;
    
    ctx.font = '11px var(--font-body)';
    ctx.textBaseline = 'middle';
    
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    const textColor = isDark ? '#e2e8f0' : '#1e1b4b';
    
    data.forEach((slice, idx) => {
        const percentage = ((slice.value / total) * 100).toFixed(0);
        const y = legendYStart + idx * 22;
        
        // Draw color circle
        ctx.fillStyle = slice.color;
        ctx.beginPath();
        ctx.arc(legendX - 15, y, 5, 0, Math.PI * 2);
        ctx.fill();
        
        // Draw label and percentage
        ctx.fillStyle = textColor;
        ctx.textAlign = 'left';
        ctx.fillText(`${slice.label}: ${percentage}%`, legendX, y);
    });
}

function drawCategoryShareChart(categorySales) {
    const canvas = document.getElementById('categoryShareChart');
    if (!canvas) return;
    
    const rect = canvas.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);
    
    const entries = Object.entries(categorySales).filter(e => e[1] > 0);
    const total = entries.reduce((sum, e) => sum + e[1], 0);
    
    if (total === 0) {
        ctx.font = '14px var(--font-body)';
        ctx.fillStyle = '#64748b';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('No sales data to display.', width / 2, height / 2);
        
        canvas._slices = [];
        return;
    }
    
    const colors = ['#6366f1', '#f97316', '#a855f7', '#10b981', '#3b82f6', '#ec4899', '#facc15'];
    
    const data = entries.map(([label, val], idx) => {
        return {
            label: label,
            value: val,
            color: colors[idx % colors.length]
        };
    }).sort((a, b) => b.value - a.value);
    
    const centerX = width * 0.38;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) * 0.72;
    const innerRadius = radius * 0.55;
    
    let startAngle = -Math.PI / 2;
    const slices = [];
    
    data.forEach(slice => {
        const sliceAngle = (slice.value / total) * Math.PI * 2;
        if (sliceAngle === 0) return;
        
        slices.push({
            label: slice.label,
            startAngle: startAngle,
            endAngle: startAngle + sliceAngle,
            centerX: centerX,
            centerY: centerY,
            radius: radius,
            innerRadius: innerRadius
        });
        
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
        ctx.arc(centerX, centerY, innerRadius, startAngle + sliceAngle, startAngle, true);
        ctx.closePath();
        
        ctx.fillStyle = slice.color;
        ctx.fill();
        
        startAngle += sliceAngle;
    });
    
    canvas._slices = slices;
    canvas._totalVal = total;
    
    const legendX = width * 0.72;
    const legendYStart = height / 2 - (data.length * 20) / 2 + 10;
    
    ctx.font = '10px var(--font-body)';
    ctx.textBaseline = 'middle';
    
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    const textColor = isDark ? '#e2e8f0' : '#1e1b4b';
    
    data.forEach((slice, idx) => {
        if (idx >= 6) return;
        const percentage = ((slice.value / total) * 100).toFixed(0);
        const y = legendYStart + idx * 20;
        
        ctx.fillStyle = slice.color;
        ctx.beginPath();
        ctx.arc(legendX - 15, y, 4.5, 0, Math.PI * 2);
        ctx.fill();
        
        ctx.fillStyle = textColor;
        ctx.textAlign = 'left';
        
        let labelText = slice.label;
        if (labelText.length > 12) {
            labelText = labelText.substring(0, 10) + '..';
        }
        ctx.fillText(`${labelText}: ${percentage}%`, legendX, y);
    });
}

// ==========================================
// CRM Customer Directory Helper
// ==========================================
function updateCustomerPhoneDatalist() {
    const datalist = document.getElementById('customerPhoneDatalist');
    if (!datalist) return;
    
    datalist.innerHTML = '';
    
    const customerMap = new Map();
    const history = appState.history || [];
    
    // Sort oldest to newest so newest values overwrite and stay current
    [...history].reverse().forEach(inv => {
        if (inv.customerPhone && inv.customerPhone.length === 10) {
            customerMap.set(inv.customerPhone, inv.customerName);
        }
    });
    
    customerMap.forEach((name, phone) => {
        const option = document.createElement('option');
        option.value = phone;
        option.textContent = name;
        datalist.appendChild(option);
    });
}

// ==========================================
// Admin Broadcast Alerts Monitoring
// ==========================================
let displayedBroadcasts = new Set();

function initBroadcastMonitoring() {
    // Check broadcasts immediately
    fetchBroadcastAlerts();
    
    // Poll every 10 seconds for new messages
    setInterval(fetchBroadcastAlerts, 10000);
}

async function fetchBroadcastAlerts() {
    try {
        const response = await fetch('./broadcasts.json?t=' + Date.now());
        if (!response.ok) return;
        const broadcasts = await response.json();
        
        if (Array.isArray(broadcasts)) {
            // Filter only active broadcasts
            const activeBroadcasts = broadcasts.filter(b => b.active);
            
            // Remove banners that are no longer active
            const existingBanners = document.querySelectorAll('.broadcast-banner');
            existingBanners.forEach(banner => {
                const id = parseInt(banner.getAttribute('data-id'));
                if (!activeBroadcasts.some(b => b.id === id)) {
                    removeBroadcastBanner(banner);
                }
            });
            
            // Show new active broadcasts
            activeBroadcasts.forEach(broadcast => {
                if (!displayedBroadcasts.has(broadcast.id)) {
                    displayBroadcastAlert(broadcast);
                }
            });
        }
    } catch (err) {
        // Silent catch to prevent console clutter
    }
}

function displayBroadcastAlert(broadcast) {
    let container = document.getElementById('broadcastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'broadcastContainer';
        container.className = 'broadcast-container';
        document.body.appendChild(container);
    }
    
    const banner = document.createElement('div');
    banner.className = `broadcast-banner ${broadcast.type || 'info'}`;
    banner.setAttribute('data-id', broadcast.id);
    
    let iconName = 'info';
    if (broadcast.type === 'warning') iconName = 'alert-triangle';
    else if (broadcast.type === 'critical') iconName = 'alert-octagon';
    
    banner.innerHTML = `
        <div class="broadcast-content">
            <div class="broadcast-icon">
                <i data-lucide="${iconName}"></i>
            </div>
            <div class="broadcast-details">
                <h4 class="broadcast-title">${broadcast.title}</h4>
                <p class="broadcast-message">${broadcast.message}</p>
            </div>
        </div>
        <button class="broadcast-close" aria-label="Close Announcement">
            <i data-lucide="x"></i>
        </button>
    `;
    
    // Wire up close button
    banner.querySelector('.broadcast-close').addEventListener('click', () => {
        removeBroadcastBanner(banner);
        displayedBroadcasts.add(broadcast.id); // Don't show again in this session
    });
    
    container.appendChild(banner);
    
    // Initialize icons for the new banner
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons({
            attrs: {
                class: 'lucide-icon'
            },
            nameAttr: 'data-lucide',
            node: banner
        });
    }
}

function removeBroadcastBanner(banner) {
    banner.classList.add('slide-up');
    banner.addEventListener('transitionend', () => {
        banner.remove();
        
        // Remove container if empty
        const container = document.getElementById('broadcastContainer');
        if (container && container.children.length === 0) {
            container.remove();
        }
    });
}

// ==========================================
// Multi-language Translation Mappings
// ==========================================
const UI_TRANSLATIONS = {
    en: {
        "#navBilling span": "Billing POS",
        "#navAnalytics span": "Sales Analytics",
        "#navProfile span": "Business Profile",
        "#navInventory span": "Stock Database",
        "#navAdmin span": "Admin Panel",
        "#navManagementGroup .nav-group-header span:first-of-type": "Settings & Setup",
        ".logo-area p.subtitle": "Smart Invoicing for India",
        "#customerCard h2": "2. Customer & Invoice Info",
        "label[for=\"custName\"]": "Customer Name *",
        "label[for=\"custPhone\"]": "Customer WhatsApp Number *",
        "label[for=\"invNumber\"]": "Invoice Number",
        "label[for=\"invDate\"]": "Date",
        "#itemsCard h2": "3. Line Items",
        "label[for=\"newItemName\"]": "Item Name / Description",
        "label[for=\"newItemPrice\"]": "Rate (₹)",
        "label[for=\"newItemQty\"]": "Qty",
        "label[for=\"newItemUnit\"]": "Unit",
        "#addItemBtn": "Add Item",
        "#cancelEditBtn": "Cancel",
        "#searchLineItemsInput": "Search added line items...",
        "#itemsTable th:nth-child(1)": "Item",
        "#itemsTable th:nth-child(2)": "Qty",
        "#itemsTable th:nth-child(3)": "Rate",
        "#itemsTable th:nth-child(4)": "Total",
        "#itemsTable th:nth-child(5)": "Action",
        "#financialCard h2": "4. Financial Adjustments",
        "label[for=\"paymentMode\"]": "Payment Mode",
        "label[for=\"discountType\"]": "Discount Type",
        "label[for=\"discountAmt\"]": "Discount Value",
        "label[for=\"roundOffActive\"]": "Bill Round-Off",
        "#saveInvoiceBtn": "Save to History",
        "#shareInvoiceBtn": "Share via WhatsApp",
        "#printPdfBtn": "Print / PDF",
        "#previewCard h2": "Live Receipt Invoice Preview",
        "#previewCard p.text-muted": "Real-time updates as you type",
        "#viewInventory h2": "Product Stock Database",
        "#viewInventory p": "Register products and monitor stock refill alerts",
        "#addProductCard h2": "Add New Product",
        "label[for=\"prodName\"]": "Product Name / SKU Description",
        "label[for=\"prodCategory\"]": "Category",
        "label[for=\"prodPrice\"]": "Selling Price (₹)",
        "label[for=\"prodPurchasePrice\"]": "Purchase Cost Price (₹)",
        "label[for=\"prodStock\"]": "Initial Stock Count",
        "label[for=\"prodPcsPerBox\"]": "Wholesale Pieces per Box",
        "label[for=\"prodRefillBoxes\"]": "Refill Stock by Boxes",
        "#btnApplyRefill": "Apply Refill",
        "label[for=\"prodThreshold\"]": "Low Stock Alert Threshold",
        "#saveProductBtn": "Save Product",
        "#cancelProductEditBtn": "Cancel",
        "#searchInventoryInput": "Search stock database...",
        "#inventoryTable th:nth-child(1)": "Product Name",
        "#inventoryTable th:nth-child(2)": "Category",
        "#inventoryTable th:nth-child(3)": "Selling Price",
        "#inventoryTable th:nth-child(4)": "Purchase Cost",
        "#inventoryTable th:nth-child(5)": "Current Stock",
        "#inventoryTable th:nth-child(6)": "Threshold",
        "#inventoryTable th:nth-child(7)": "Actions",
        "#btnExportInventoryExcel": "Export Template",
        "label[for=\"excelImportFile\"]": "Excel Template Upload",
        ".excel-dropzone p": "Drag & drop your updated catalog spreadsheet here or click to browse",
        "#historyCard h2": "Invoice Ledger History",
        "#historyCard p": "Review past invoices, cycle payment status, and dispatch receipts",
        "#searchHistoryInput": "Search ledger history...",
        "#historyTable th:nth-child(1)": "Invoice #",
        "#historyTable th:nth-child(2)": "Date",
        "#historyTable th:nth-child(3)": "Customer Info",
        "#historyTable th:nth-child(4)": "Items List",
        "#historyTable th:nth-child(5)": "Qty List",
        "#historyTable th:nth-child(6)": "Grand Total",
        "#historyTable th:nth-child(7)": "Mode",
        "#historyTable th:nth-child(8)": "Status",
        "#historyTable th:nth-child(9)": "Actions",
        "#btnExportLedgerExcel": "Export Ledger Excel",
        "#viewAnalytics h2": "Sales Analytics Dashboard",
        "#analyticsFilterTitle": "Sales Filter",
        "label[for=\"analyticsDatePreset\"]": "Preset:",
        "label[for=\"analyticsStartDate\"]": "Start:",
        "label[for=\"analyticsEndDate\"]": "End:",
        "#analyticsDatePreset option[value=\"today\"]": "Today",
        "#analyticsDatePreset option[value=\"yesterday\"]": "Yesterday",
        "#analyticsDatePreset option[value=\"last7\"]": "Last 7 Days",
        "#analyticsDatePreset option[value=\"last30\"]": "Last 30 Days",
        "#analyticsDatePreset option[value=\"thismonth\"]": "This Month",
        "#analyticsDatePreset option[value=\"all\"]": "All Time",
        "#analyticsDatePreset option[value=\"custom\"]": "Custom Range",
        "#drilldownTitle": "Sales Breakdown",
        "#drilldownTotalLabel": "Total Selected:",
        "#drilldownSearch": "Search invoices...",
        "#thInvNo": "Invoice #",
        "#thDate": "Date",
        "#thCustomer": "Customer",
        "#thPayMode": "Payment Mode",
        "#thAmount": "Amount",
        "#thAction": "Action",
        "#chartPaymentModeTitle": "Payment Mode Share",
        "#chartPaymentModeSub": "Paid Revenue",
        "#chartCategoryShareTitle": "Category Sales Share",
        "#chartCategoryShareSub": "Revenue Share",
        ".analytics-summary-cards div:nth-child(1) span": "Total Sales Revenue",
        "#analyticsTotalSalesSub": "Paid invoices only",
        ".analytics-summary-cards div:nth-child(2) span": "Total Net Profit",
        "#analyticsTotalProfitSub": "Net profit from paid sales",
        ".analytics-summary-cards div:nth-child(3) span": "UPI Sales",
        ".analytics-summary-cards div:nth-child(3) p": "Via UPI QR code",
        ".analytics-summary-cards div:nth-child(4) span": "Cash Sales",
        ".analytics-summary-cards div:nth-child(4) p": "Via Cash drawer",
        ".analytics-summary-cards div:nth-child(5) span": "Card Sales",
        ".analytics-summary-cards div:nth-child(5) p": "Via POS swipe",
        ".analytics-summary-cards div:nth-child(6) span": "Pending Payments",
        "#analyticsPendingPaymentsSub": "Outstanding dues",
        ".analytics-summary-cards div:nth-child(7) span": "Average Bill Ticket",
        "#analyticsAvgTicketSub": "Per transaction avg",
        ".analytics-summary-cards div:nth-child(8) span": "Refunded Sales",
        "#analyticsRefundedSalesSub": "Returned stock & cash",
        ".analytics-summary-cards div:nth-child(9) span": "Total Invoices",
        "#analyticsTotalCountSub": "All transactions count",
        "#viewProfile h2": "Business Profile Settings",
        "#viewProfile p": "Configure your store details and Indian UPI VPA for payment receipt codes",
        "label[for=\"bizName\"]": "Registered Business Name",
        "label[for=\"bizUpi\"]": "UPI VPA (Virtual Payment Address) *",
        "label[for=\"bizPhone\"]": "Support Phone Number",
        "label[for=\"bizAddress\"]": "Store Address",
        "label[for=\"bizGstin\"]": "GSTIN / VAT Number (Optional)",
        "#viewAdmin h2": "Terminal Admin Control Panel",
        "#viewAdmin p": "Manage bulk data backups, import master sheets, and security preferences",
        "#viewAdmin h3:nth-of-type(1)": "Ledger Backup Tools",
        "#viewAdmin p:nth-of-type(1)": "Export ledger or import merge sheets to sync cashier database.",
        "#btnExportBackup": "Export JSON Backup",
        "label[for=\"backupFile\"]": "Restore JSON Backup File",
        ".excel-dropzone:nth-of-type(1) p": "Drag & drop backup JSON file here or click to browse",
        "#viewAdmin h3:nth-of-type(2)": "Master Catalog Setup",
        "#viewAdmin p:nth-of-type(2)": "Import master catalogue sheets to seed product dropdowns.",
        "#btnDownloadExcelTemplate": "Download Excel Catalog Template",
        "#downloadTemplateBtn": "Download Excel Template",
        "#exportStockExcelBtn": "Export Current Stock",
        "label[for=\"catalogExcelFile\"]": "Import Catalog Excel Sheet",
        ".excel-dropzone:nth-of-type(2) p": "Drag & drop catalog Excel file here or click to browse",
        "#authOverlay h2": "Cashier Terminal Access",
        "label[for=\"authUsername\"]": "Terminal User ID",
        "label[for=\"authPassword\"]": "Access Password",
        "label[for=\"authBizName\"]": "Business Name (New Registration)",
        "#authSubmitText": "Login",
        "#authSwitchBtn": "Create New Account",
        "#forgotPasswordLink": "Forgot Password?",
        "#forgotPasswordCard h2": "Reset Admin Password",
        "label[for=\"forgotUsername\"]": "Enter Terminal User ID",
        "#btnSendOtp": "Generate OTP",
        "label[for=\"forgotOtp\"]": "Enter OTP",
        "label[for=\"forgotNewPassword\"]": "Enter New Access Password",
        "#forgotPasswordCard button[type=\"submit\"]": "Reset Access Password",
        "#forgotPasswordCard button[onclick=\"hideForgotPassword()\"]": "Cancel"
    },
    gu: {
        "#navBilling span": "બિલિંગ POS",
        "#navAnalytics span": "વેચાણ વિશ્લેષણ",
        "#navProfile span": "વ્યવસાય પ્રોફાઇલ",
        "#navInventory span": "સ્ટોક ડેટાબેઝ",
        "#navAdmin span": "એડમિન પેનલ",
        "#navManagementGroup .nav-group-header span:first-of-type": "સેટિંગ્સ અને સેટઅપ",
        ".logo-area p.subtitle": "ભારત માટે સ્માર્ટ ઇન્વોઇસિંગ",
        "#customerCard h2": "૨. ગ્રાહક અને ઇન્વોઇસ વિગતો",
        "label[for=\"custName\"]": "ગ્રાહકનું નામ *",
        "label[for=\"custPhone\"]": "ગ્રાહકનો વોટ્સએપ નંબર *",
        "label[for=\"invNumber\"]": "ઇન્વોઇસ નંબર",
        "label[for=\"invDate\"]": "તારીખ",
        "#itemsCard h2": "૩. વસ્તુઓની સૂચિ",
        "label[for=\"newItemName\"]": "વસ્તુનું નામ / વિગત",
        "label[for=\"newItemPrice\"]": "દર (₹)",
        "label[for=\"newItemQty\"]": "જથ્થો",
        "label[for=\"newItemUnit\"]": "એકમ",
        "#addItemBtn": "વસ્તુ ઉમેરો",
        "#cancelEditBtn": "રદ કરો",
        "#searchLineItemsInput": "ઉમેરેલી વસ્તુઓ શોધો...",
        "#itemsTable th:nth-child(1)": "વસ્તુ",
        "#itemsTable th:nth-child(2)": "જથ્થો",
        "#itemsTable th:nth-child(3)": "દર",
        "#itemsTable th:nth-child(4)": "કુલ",
        "#itemsTable th:nth-child(5)": "ક્રિયા",
        "#financialCard h2": "૪. નાણાકીય ગોઠવણો",
        "label[for=\"paymentMode\"]": "ચુકવણી મોડ",
        "label[for=\"discountType\"]": "ડિસ્કાઉન્ટ પ્રકાર",
        "label[for=\"discountAmt\"]": "ડિસ્કાઉન્ટ કિંમત",
        "label[for=\"roundOffActive\"]": "બિલ રાઉન્ડ-ઓફ",
        "#saveInvoiceBtn": "લેજરમાં સાચવો",
        "#shareInvoiceBtn": "વોટ્સએપ પર શેર કરો",
        "#printPdfBtn": "પ્રિન્ટ / PDF",
        "#previewCard h2": "લાઇવ પાવતી ઇન્વોઇસ પ્રિવ્યૂ",
        "#previewCard p.text-muted": "લખાણ સાથે રિયલ-ટાઇમ અપડેટ્સ",
        "#viewInventory h2": "ઉત્પાદન સ્ટોક ડેટાબેઝ",
        "#viewInventory p": "ઉત્પાદનો રજીસ્ટર કરો અને સ્ટોક ચેતવણીઓ જુઓ",
        "#addProductCard h2": "નવું ઉત્પાદન ઉમેરો",
        "label[for=\"prodName\"]": "ઉત્પાદનનું નામ / SKU વિગત",
        "label[for=\"prodCategory\"]": "કેટેગરી",
        "label[for=\"prodPrice\"]": "વેચાણ કિંમત (₹)",
        "label[for=\"prodPurchasePrice\"]": "ખરીદી કિંમત (₹)",
        "label[for=\"prodStock\"]": "પ્રારંભિક સ્ટોક",
        "label[for=\"prodPcsPerBox\"]": "બોક્સ દીઠ જથ્થો (પીસ)",
        "label[for=\"prodRefillBoxes\"]": "સ્ટોક રિફિલ (બોક્સ દ્વારા)",
        "#btnApplyRefill": "રિફિલ લાગુ કરો",
        "label[for=\"prodThreshold\"]": "ઓછા સ્ટોકની ચેતવણી મર્યાદા",
        "#saveProductBtn": "ઉત્પાદન સાચવો",
        "#cancelProductEditBtn": "રદ કરો",
        "#searchInventoryInput": "સ્ટોક ડેટાબેઝ શોધો...",
        "#inventoryTable th:nth-child(1)": "ઉત્પાદનનું નામ",
        "#inventoryTable th:nth-child(2)": "કેટેગરી",
        "#inventoryTable th:nth-child(3)": "વેચાણ કિંમત",
        "#inventoryTable th:nth-child(4)": "ખરીદી કિંમત",
        "#inventoryTable th:nth-child(5)": "વર્તમાન સ્ટોક",
        "#inventoryTable th:nth-child(6)": "ચેતવણી મર્યાદા",
        "#inventoryTable th:nth-child(7)": "ક્રિયાઓ",
        "#btnExportInventoryExcel": "એક્સેલ નિકાસ",
        "label[for=\"excelImportFile\"]": "એક્સેલ ટેમ્પલેટ અપલોડ",
        ".excel-dropzone p": "તમારું અપડેટ કરેલ સ્પ્રેડશીટ અહીં ખેંચો અથવા બ્રાઉઝ કરો",
        "#historyCard h2": "ઇન્વોઇસ લેજર ઇતિહાસ",
        "#historyCard p": "પાછલા ઇન્વોઇસ જુઓ, પેમેન્ટ સ્ટેટસ બદલો અને પાવતીઓ મોકલો",
        "#searchHistoryInput": "લેજર ઇતિહાસ શોધો...",
        "#historyTable th:nth-child(1)": "ઇન્વોઇસ #",
        "#historyTable th:nth-child(2)": "તારીખ",
        "#historyTable th:nth-child(3)": "ગ્રાહકની વિગત",
        "#historyTable th:nth-child(4)": "વસ્તુઓની યાદી",
        "#historyTable th:nth-child(5)": "જથ્થો યાદી",
        "#historyTable th:nth-child(6)": "કુલ રકમ",
        "#historyTable th:nth-child(7)": "મોડ",
        "#historyTable th:nth-child(8)": "સ્ટેટસ",
        "#historyTable th:nth-child(9)": "ક્રિયાઓ",
        "#btnExportLedgerExcel": "લેજર એક્સેલ નિકાસ",
        "#viewAnalytics h2": "વેચાણ વિશ્લેષણ ડેશબોર્ડ",
        "#analyticsFilterTitle": "વેચાણ ફિલ્ટર",
        "label[for=\"analyticsDatePreset\"]": "પ્રીસેટ:",
        "label[for=\"analyticsStartDate\"]": "શરૂઆત:",
        "label[for=\"analyticsEndDate\"]": "અંત:",
        "#analyticsDatePreset option[value=\"today\"]": "આજે",
        "#analyticsDatePreset option[value=\"yesterday\"]": "ગઈકાલે",
        "#analyticsDatePreset option[value=\"last7\"]": "છેલ્લા ૭ દિવસ",
        "#analyticsDatePreset option[value=\"last30\"]": "છેલ્લા ૩૦ દિવસ",
        "#analyticsDatePreset option[value=\"thismonth\"]": "આ મહિને",
        "#analyticsDatePreset option[value=\"all\"]": "કુલ સમય",
        "#analyticsDatePreset option[value=\"custom\"]": "કસ્ટમ મર્યાદા",
        "#drilldownTitle": "વેચાણ વિગતો",
        "#drilldownTotalLabel": "કુલ પસંદ કરેલ:",
        "#drilldownSearch": "ઇન્વોઇસ શોધો...",
        "#thInvNo": "ઇન્વોઇસ #",
        "#thDate": "તારીખ",
        "#thCustomer": "ગ્રાહક",
        "#thPayMode": "ચુકવણી મોડ",
        "#thAmount": "રકમ",
        "#thAction": "ક્રિયા",
        "#chartPaymentModeTitle": "ચુકવણી પદ્ધતિ હિસ્સો",
        "#chartPaymentModeSub": "ચૂકવેલ આવક",
        "#chartCategoryShareTitle": "શ્રેણી વેચાણ હિસ્સો",
        "#chartCategoryShareSub": "આવક હિસ્સો",
        ".analytics-summary-cards div:nth-child(1) span": "કુલ વેચાણ આવક",
        "#analyticsTotalSalesSub": "માત્ર ચૂકવેલ ઇન્વોઇસ",
        ".analytics-summary-cards div:nth-child(2) span": "કુલ ચોખ્ખો નફો",
        "#analyticsTotalProfitSub": "ચૂકવેલ વેચાણ પર નફો",
        ".analytics-summary-cards div:nth-child(3) span": "UPI વેચાણ",
        ".analytics-summary-cards div:nth-child(3) p": "UPI QR કોડ દ્વારા",
        ".analytics-summary-cards div:nth-child(4) span": "રોકડ વેચાણ",
        ".analytics-summary-cards div:nth-child(4) p": "કેશ બોક્સ દ્વારા",
        ".analytics-summary-cards div:nth-child(5) span": "કાર્ડ વેચાણ",
        ".analytics-summary-cards div:nth-child(5) p": "કાર્ડ સ્વાઇપ દ્વારા",
        ".analytics-summary-cards div:nth-child(6) span": "બાકી ચુકવણીઓ",
        "#analyticsPendingPaymentsSub": "બાકી લેણાં",
        ".analytics-summary-cards div:nth-child(7) span": "સરેરાશ બિલ ટિકિટ",
        "#analyticsAvgTicketSub": "પ્રતિ ટ્રાન્ઝેક્શન સરેરાશ",
        ".analytics-summary-cards div:nth-child(8) span": "રીફંડ કરેલ વેચાણ",
        "#analyticsRefundedSalesSub": "પરત કરેલ સ્ટોક અને રોકડ",
        ".analytics-summary-cards div:nth-child(9) span": "કુલ ઇન્વોઇસ",
        "#analyticsTotalCountSub": "કુલ વ્યવહારોની સંખ્યા",
        "#viewProfile h2": "વ્યવસાય પ્રોફાઇલ સેટિંગ્સ",
        "#viewProfile p": "તમારી સ્ટોર વિગતો અને ચુકવણી માટે UPI ID સેટ કરો",
        "label[for=\"bizName\"]": "નોંધાયેલ વ્યવસાયનું નામ",
        "label[for=\"bizUpi\"]": "UPI ID (Virtual Payment Address) *",
        "label[for=\"bizPhone\"]": "સપોર્ટ ફોન નંબર",
        "label[for=\"bizAddress\"]": "સ્ટોરનું સરનામું",
        "label[for=\"bizGstin\"]": "GSTIN / VAT નંબર (વૈકલ્પિક)",
        "#viewAdmin h2": "ટર્મિનલ એડમિન કંટ્રોલ પેનલ",
        "#viewAdmin p": "ડેટા બેકઅપ, માસ્ટર શીટ્સ આયાત અને સુરક્ષા પસંદગીઓ સંચાલિત કરો",
        "#viewAdmin h3:nth-of-type(1)": "લેજર બેકઅપ ટૂલ્સ",
        "#viewAdmin p:nth-of-type(1)": "ડેટાબેઝ સિંક કરવા માટે લેજર નિકાસ અથવા આયાત કરો.",
        "#btnExportBackup": "JSON બેકઅપ નિકાસ કરો",
        "label[for=\"backupFile\"]": "JSON બેકઅપ ફાઇલ પુનઃસ્થાપિત કરો",
        ".excel-dropzone:nth-of-type(1) p": "બેકઅપ JSON ફાઇલ અહીં ખેંચો અથવા બ્રાઉઝ કરો",
        "#viewAdmin h3:nth-of-type(2)": "માસ્ટર કેટલોગ સેટઅપ",
        "#viewAdmin p:nth-of-type(2)": "ઉત્પાદન ડ્રોપડાઉન સેટ કરવા માટે કેટલોગ આયાત કરો.",
        "#btnDownloadExcelTemplate": "કેટલોગ એક્સેલ નમૂનો ડાઉનલોડ કરો",
        "#downloadTemplateBtn": "એક્સેલ નમૂનો ડાઉનલોડ કરો",
        "#exportStockExcelBtn": "વર્તમાન સ્ટોક નિકાસ કરો",
        "label[for=\"catalogExcelFile\"]": "એક્સેલ કેટલોગ પત્રક આયાત કરો",
        ".excel-dropzone:nth-of-type(2) p": "કેટલોગ એક્સેલ ફાઇલ અહીં ખેંચો અથવા બ્રાઉઝ કરો",
        "#authOverlay h2": "કેશિયર ટર્મિનલ એક્સેસ",
        "label[for=\"authUsername\"]": "ટર્મિનલ યુઝર ID",
        "label[for=\"authPassword\"]": "એક્સેસ પાસવર્ડ",
        "label[for=\"authBizName\"]": "વ્યવસાયનું નામ (નવી નોંધણી)",
        "#authSubmitText": "લોગિન",
        "#authSwitchBtn": "નવું ખાતું બનાવો",
        "#forgotPasswordLink": "પાસવર્ડ ભૂલી ગયા છો?",
        "#forgotPasswordCard h2": "એડમિન પાસવર્ડ રીસેટ કરો",
        "label[for=\"forgotUsername\"]": "ટર્મિનલ યુઝર ID દાખલ કરો",
        "#btnSendOtp": "OTP જનરેટ કરો",
        "label[for=\"forgotOtp\"]": "OTP દાખલ કરો",
        "label[for=\"forgotNewPassword\"]": "નવો એક્સેસ પાસવર્ડ દાખલ કરો",
        "#forgotPasswordCard button[type=\"submit\"]": "એક્સેસ પાસવર્ડ રીસેટ કરો",
        "#forgotPasswordCard button[onclick=\"hideForgotPassword()\"]": "Cancel"
    }
};

const MESSAGES = {
    en: {
        guest: "Guest",
        no_invoices: 'No invoices saved yet. Generate one and click "Save to History".',
        no_products: 'No items in inventory. Add products above.',
        no_items_added: 'No items added yet. Fill out the row above to begin.',
        complete_profile: 'Please complete the Business Profile first.',
        add_items: 'Please add items to the invoice before saving.',
        enter_cust_name: 'Please enter a customer name.',
        confirm_delete_invoice: 'Are you sure you want to permanently delete this invoice from ledger?',
        confirm_delete_product: 'Are you sure you want to permanently delete this product?',
        confirm_overwrite_invoice: (no) => `Invoice #${no} already exists. Do you want to overwrite it?`,
        confirm_discard_workspace: (no) => `This will discard your current unsaved invoice workspace. Re-open Invoice #${no}?`,
        first_time_setup: 'First-time cashier terminal setup. Register your admin credentials.',
        invoice_saved: 'Invoice saved successfully to Ledger!',
        invalid_phone: 'Please enter a valid 10-digit Indian mobile number for the customer.',
        set_upi: 'Please set your UPI ID in Business Profile before sharing.',
        add_one_item: 'Please add at least one line item to the invoice.',
        whatsapp_opening: (no) => `Opening WhatsApp chat...\n\nYour invoice PDF (Invoice_${no}.pdf) has been downloaded to your downloads folder. Please attach it in the chat!`,
        low_stock_warning: (stock, unit, name, qty) => `Warning: Only ${stock} ${unit} of "${name}" in stock. You are trying to sell ${qty} ${unit}. Proceed anyway?`,
        confirm_new_invoice: 'Start a new invoice? This will clear your current billing workspace details.',
        confirm_logout: 'Are you sure you want to log out of your session?',
        no_products_to_export: 'There is no product data in inventory to export.'
    },
    gu: {
        guest: "મહેમાન",
        no_invoices: 'હજુ સુધી કોઈ ઇન્વોઇસ સાચવેલ નથી. એક બનાવો અને "Save to History" પર ક્લિક કરો.',
        no_products: 'સ્ટોક ડેટાબેઝમાં કોઈ ઉત્પાદનો નથી. ઉપરથી ઉમેરો.',
        no_items_added: 'હજી સુધી કોઈ વસ્તુ ઉમેરવામાં આવી નથી. શરૂ કરવા માટે ઉપરની લાઇન ભરો.',
        complete_profile: 'કૃપા કરીને પહેલા વ્યવસાય પ્રોફાઇલ પૂર્ણ કરો.',
        add_items: 'કૃપા કરીને ઇન્વોઇસ સાચવતા પહેલા વસ્તુઓ ઉમેરો.',
        enter_cust_name: 'કૃપા કરીને ગ્રાહકનું નામ દાખલ કરો.',
        confirm_delete_invoice: 'શું તમે ખરેખર આ ઇન્વોઇસને લેજરમાંથી કાયમ માટે કાઢી નાખવા માંગો છો?',
        confirm_delete_product: 'શું તમે ખરેખર આ ઉત્પાદનને કાયમ માટે કાઢી નાખવા માંગો છો?',
        confirm_overwrite_invoice: (no) => `ઇન્વોઇસ #${no} પહેલેથી અસ્તિત્વમાં છે. શું તમે તેને ફરીથી લખવા માંગો છો?`,
        confirm_discard_workspace: (no) => `આ તમારા વર્તમાન અણસાચવેલા ઇન્વોઇસને રદ કરશે. શું ઇન્વોઇસ #${no} ફરીથી ખોલવું છે?`,
        first_time_setup: 'પહેલી વાર કેશિયર ટર્મિનલ સેટઅપ. તમારા એડમિન ઓળખપત્રોની નોંધણી કરો.',
        invoice_saved: 'ઇન્વોઇસ સફળતાપૂર્વક લેજરમાં સાચવવામાં આવ્યું!',
        invalid_phone: 'કૃપા કરીને ગ્રાહક માટે માન્ય ૧૦-આંકડાનો ભારતીય મોબાઇલ નંબર દાખલ કરો.',
        set_upi: 'કૃપા કરીને શેર કરતા પહેલા વ્યવસાય પ્રોફાઇલમાં તમારી UPI ID સેટ કરો.',
        add_one_item: 'કૃપા કરીને ઇન્વોઇસમાં ઓછામાં ઓછી એક વસ્તુ ઉમેરો.',
        whatsapp_opening: (no) => `વોટ્સએપ ચેટ ખોલી રહ્યા છીએ...\n\nતમારું ઇન્વોઇસ PDF (Invoice_${no}.pdf) તમારા ડાઉનલોડ ફોલ્ડરમાં ડાઉનલોડ થઈ ગયું છે. કૃપા કરીને તેને ચેટમાં મોકલો!`,
        low_stock_warning: (stock, unit, name, qty) => `ચેતવણી: સ્ટોકમાં "${name}" ના માત્ર ${stock} ${unit} છે. તમે ${qty} ${unit} વેચવાનો પ્રયાસ કરી રહ્યા છો. તો પણ આગળ વધવું છે?`,
        confirm_new_invoice: 'નવું ઇન્વોઇસ શરૂ કરવું છે? આ તમારા વર્તમાન બિલિંગ સ્થાનની વિગતો ભૂંસી નાખશે.',
        confirm_logout: 'શું તમે ખરેખર તમારા સત્રમાંથી લોગ આઉટ થવા માંગો છો?',
        no_products_to_export: 'નિકાસ કરવા માટે સ્ટોકમાં કોઈ ઉત્પાદનો નથી.'
    }
};

function t(key, ...args) {
    const lang = appState.language || 'en';
    const dict = MESSAGES[lang] || MESSAGES['en'];
    const item = dict[key] || MESSAGES['en'][key] || key;
    if (typeof item === 'function') {
        return item(...args);
    }
    return item;
}

function applyTranslations() {
    const lang = appState.language || 'en';
    const dict = UI_TRANSLATIONS[lang] || UI_TRANSLATIONS['en'];
    
    // 1. Translate elements with selectors
    for (const [selector, text] of Object.entries(dict)) {
        const elements = document.querySelectorAll(selector);
        elements.forEach(el => {
            if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
                if (el.type === 'button' || el.type === 'submit') {
                    el.value = text;
                } else {
                    el.placeholder = text;
                }
            } else {
                // Preserve child Lucide icon element if it exists
                const icon = el.querySelector('i, svg');
                if (icon) {
                    el.innerHTML = '';
                    el.appendChild(icon);
                    el.appendChild(document.createTextNode(' ' + text));
                } else {
                    el.innerText = text;
                }
            }
        });
    }

    // 2. Handle specific dynamic header updates
    const headerUsername = document.getElementById('headerUsername');
    if (headerUsername && (!appState.currentUser || appState.currentUser === 'Guest')) {
        headerUsername.innerText = t('guest');
    }
    
    // 3. Keep live receipt preview dynamically translated
    updatePreview();
}




