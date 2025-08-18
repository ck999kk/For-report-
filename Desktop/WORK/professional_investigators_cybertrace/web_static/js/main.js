/*
Professional Phone Intelligence System - Main JavaScript
Version: 1.0.0
Professional Grade Interactive Features
*/

// Global Variables
let socket = null;
let appConfig = {
    apiBaseUrl: '/api',
    socketNamespace: '/',
    debugMode: false,
    autoRefreshInterval: 30000
};

// Application State
let appState = {
    currentUser: null,
    activeInvestigations: [],
    systemStatus: 'unknown',
    notifications: [],
    isOnline: true
};

// Utility Functions
const Utils = {
    // Debounce function for search inputs
    debounce: function(func, wait, immediate) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                timeout = null;
                if (!immediate) func(...args);
            };
            const callNow = immediate && !timeout;
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
            if (callNow) func(...args);
        };
    },

    // Throttle function for scroll events
    throttle: function(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        }
    },

    // Format phone numbers
    formatPhoneNumber: function(phone) {
        // Remove all non-digits
        const cleaned = phone.replace(/\D/g, '');
        
        // Check if it's a US number
        if (cleaned.length === 10) {
            return `+1 (${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`;
        } else if (cleaned.length === 11 && cleaned[0] === '1') {
            return `+1 (${cleaned.slice(1, 4)}) ${cleaned.slice(4, 7)}-${cleaned.slice(7)}`;
        }
        
        // For international numbers, just add + if not present
        return phone.startsWith('+') ? phone : '+' + phone;
    },

    // Format file sizes
    formatFileSize: function(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // Format duration
    formatDuration: function(milliseconds) {
        const seconds = Math.floor(milliseconds / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        
        if (hours > 0) {
            return `${hours}h ${minutes % 60}m`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s`;
        } else {
            return `${seconds}s`;
        }
    },

    // Generate unique IDs
    generateId: function() {
        return '_' + Math.random().toString(36).substr(2, 9);
    },

    // Validate email addresses
    isValidEmail: function(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    },

    // Validate phone numbers (basic)
    isValidPhoneNumber: function(phone) {
        const cleaned = phone.replace(/\D/g, '');
        return cleaned.length >= 10 && cleaned.length <= 15;
    },

    // Copy text to clipboard
    copyToClipboard: function(text) {
        if (navigator.clipboard) {
            return navigator.clipboard.writeText(text);
        } else {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            return Promise.resolve();
        }
    },

    // Show notification
    showNotification: function(message, type = 'info', duration = 5000) {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = `
            top: 20px;
            right: 20px;
            z-index: 9999;
            min-width: 300px;
        `;
        
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after duration
        if (duration > 0) {
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, duration);
        }
        
        return notification;
    },

    // Show loading spinner
    showLoading: function(element, text = 'Loading...') {
        const loadingHtml = `
            <div class="d-flex justify-content-center align-items-center py-4">
                <div class="spinner-border text-primary me-2" role="status">
                    <span class="visually-hidden">${text}</span>
                </div>
                <span class="text-muted">${text}</span>
            </div>
        `;
        
        if (typeof element === 'string') {
            document.getElementById(element).innerHTML = loadingHtml;
        } else {
            element.innerHTML = loadingHtml;
        }
    },

    // Hide loading spinner
    hideLoading: function(element) {
        if (typeof element === 'string') {
            element = document.getElementById(element);
        }
        
        const loading = element.querySelector('.spinner-border');
        if (loading) {
            loading.parentNode.remove();
        }
    }
};

// API Service
const API = {
    // Generic API request function
    request: async function(endpoint, options = {}) {
        const url = appConfig.apiBaseUrl + endpoint;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin'
        };
        
        const requestOptions = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(url, requestOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            } else {
                return await response.text();
            }
            
        } catch (error) {
            console.error('API Request failed:', error);
            throw error;
        }
    },

    // GET request
    get: function(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    },

    // POST request
    post: function(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },

    // PUT request
    put: function(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    },

    // DELETE request
    delete: function(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    },

    // File upload
    uploadFile: function(endpoint, formData) {
        return this.request(endpoint, {
            method: 'POST',
            body: formData,
            headers: {} // Let browser set content-type for FormData
        });
    },

    // System status
    getSystemStatus: function() {
        return this.get('/system/status');
    },

    // Phone validation
    validatePhone: function(phoneNumber) {
        return this.post('/validate_phone', { phone_number: phoneNumber });
    },

    // Start investigation
    startInvestigation: function(phoneNumber, investigationType = 'comprehensive') {
        return this.post('/start_investigation', {
            phone_number: phoneNumber,
            investigation_type: investigationType
        });
    },

    // Get investigation status
    getInvestigationStatus: function(investigationId) {
        return this.get(`/investigation_status/${investigationId}`);
    },

    // List investigations
    listInvestigations: function() {
        return this.get('/investigations');
    },

    // Download report
    downloadReport: function(investigationId) {
        window.location.href = `${appConfig.apiBaseUrl}/download_report/${investigationId}`;
    },

    // Upload evidence
    uploadEvidence: function(investigationId, file) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('investigation_id', investigationId);
        
        return this.uploadFile('/upload_evidence', formData);
    },

    // Get session info
    getSessionInfo: function() {
        return this.get('/session_info');
    }
};

// WebSocket Manager
const SocketManager = {
    socket: null,
    reconnectAttempts: 0,
    maxReconnectAttempts: 5,
    reconnectDelay: 1000,

    init: function() {
        if (typeof io === 'undefined') {
            console.warn('Socket.IO not loaded, real-time features disabled');
            return;
        }

        this.connect();
    },

    connect: function() {
        try {
            this.socket = io(appConfig.socketNamespace);
            
            this.socket.on('connect', () => {
                console.log('WebSocket connected');
                appState.isOnline = true;
                this.reconnectAttempts = 0;
                this.updateConnectionStatus(true);
            });

            this.socket.on('disconnect', () => {
                console.log('WebSocket disconnected');
                appState.isOnline = false;
                this.updateConnectionStatus(false);
                this.scheduleReconnect();
            });

            this.socket.on('error', (error) => {
                console.error('WebSocket error:', error);
            });

            this.socket.on('investigation_completed', (data) => {
                this.handleInvestigationCompleted(data);
            });

            this.socket.on('investigation_error', (data) => {
                this.handleInvestigationError(data);
            });

            this.socket.on('progress_update', (data) => {
                this.handleProgressUpdate(data);
            });

            socket = this.socket; // Set global socket reference

        } catch (error) {
            console.error('Failed to initialize WebSocket:', error);
        }
    },

    scheduleReconnect: function() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
            
            console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`);
            
            setTimeout(() => {
                this.connect();
            }, delay);
        } else {
            console.error('Max reconnection attempts reached');
            Utils.showNotification('Lost connection to server. Please refresh the page.', 'danger', 0);
        }
    },

    updateConnectionStatus: function(isOnline) {
        const indicator = document.querySelector('.connection-status');
        if (indicator) {
            indicator.className = `connection-status ${isOnline ? 'online' : 'offline'}`;
            indicator.title = isOnline ? 'Connected' : 'Disconnected';
        }
    },

    handleInvestigationCompleted: function(data) {
        console.log('Investigation completed:', data);
        
        Utils.showNotification(
            `Investigation completed for ${data.phone_number}`,
            'success'
        );
        
        // Dispatch custom event
        window.dispatchEvent(new CustomEvent('investigationCompleted', {
            detail: data
        }));
    },

    handleInvestigationError: function(data) {
        console.error('Investigation error:', data);
        
        Utils.showNotification(
            `Investigation failed: ${data.error}`,
            'danger'
        );
        
        // Dispatch custom event
        window.dispatchEvent(new CustomEvent('investigationError', {
            detail: data
        }));
    },

    handleProgressUpdate: function(data) {
        console.log('Progress update:', data);
        
        // Dispatch custom event
        window.dispatchEvent(new CustomEvent('progressUpdate', {
            detail: data
        }));
    }
};

// Form Validation
const FormValidator = {
    rules: {
        required: function(value) {
            return value.trim().length > 0;
        },
        
        email: function(value) {
            return Utils.isValidEmail(value);
        },
        
        phone: function(value) {
            return Utils.isValidPhoneNumber(value);
        },
        
        minLength: function(value, min) {
            return value.length >= min;
        },
        
        maxLength: function(value, max) {
            return value.length <= max;
        }
    },

    validate: function(form) {
        const errors = [];
        const elements = form.querySelectorAll('[data-validate]');
        
        elements.forEach(element => {
            const rules = element.dataset.validate.split('|');
            const value = element.value;
            const fieldName = element.name || element.id || 'Field';
            
            rules.forEach(rule => {
                const [ruleName, parameter] = rule.split(':');
                
                if (this.rules[ruleName]) {
                    const isValid = parameter ? 
                        this.rules[ruleName](value, parameter) : 
                        this.rules[ruleName](value);
                    
                    if (!isValid) {
                        errors.push({
                            element: element,
                            field: fieldName,
                            rule: ruleName,
                            message: this.getErrorMessage(fieldName, ruleName, parameter)
                        });
                    }
                }
            });
        });
        
        this.displayErrors(errors);
        return errors.length === 0;
    },

    getErrorMessage: function(field, rule, parameter) {
        const messages = {
            required: `${field} is required`,
            email: `${field} must be a valid email address`,
            phone: `${field} must be a valid phone number`,
            minLength: `${field} must be at least ${parameter} characters`,
            maxLength: `${field} must not exceed ${parameter} characters`
        };
        
        return messages[rule] || `${field} is invalid`;
    },

    displayErrors: function(errors) {
        // Clear previous errors
        document.querySelectorAll('.validation-error').forEach(error => {
            error.remove();
        });
        
        // Add new errors
        errors.forEach(error => {
            const errorElement = document.createElement('div');
            errorElement.className = 'validation-error text-danger small mt-1';
            errorElement.textContent = error.message;
            
            error.element.classList.add('is-invalid');
            error.element.parentNode.appendChild(errorElement);
        });
    },

    clearErrors: function(form) {
        form.querySelectorAll('.validation-error').forEach(error => {
            error.remove();
        });
        
        form.querySelectorAll('.is-invalid').forEach(element => {
            element.classList.remove('is-invalid');
        });
    }
};

// Performance Monitor
const PerformanceMonitor = {
    metrics: {
        pageLoadTime: 0,
        apiResponseTimes: [],
        memoryUsage: 0
    },

    init: function() {
        this.measurePageLoad();
        this.startMemoryMonitoring();
    },

    measurePageLoad: function() {
        window.addEventListener('load', () => {
            const navigation = performance.getEntriesByType('navigation')[0];
            this.metrics.pageLoadTime = navigation.loadEventEnd - navigation.fetchStart;
            
            if (appConfig.debugMode) {
                console.log(`Page loaded in ${this.metrics.pageLoadTime}ms`);
            }
        });
    },

    measureApiCall: function(startTime, endTime) {
        const responseTime = endTime - startTime;
        this.metrics.apiResponseTimes.push(responseTime);
        
        if (appConfig.debugMode) {
            console.log(`API call took ${responseTime}ms`);
        }
    },

    startMemoryMonitoring: function() {
        if (performance.memory) {
            setInterval(() => {
                this.metrics.memoryUsage = performance.memory.usedJSHeapSize;
            }, 30000); // Check every 30 seconds
        }
    },

    getMetrics: function() {
        return { ...this.metrics };
    }
};

// Accessibility Helpers
const A11y = {
    init: function() {
        this.setupKeyboardNavigation();
        this.setupScreenReaderSupport();
        this.setupFocusManagement();
    },

    setupKeyboardNavigation: function() {
        // Handle escape key to close modals
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const modal = document.querySelector('.modal.show');
                if (modal) {
                    const modalInstance = bootstrap.Modal.getInstance(modal);
                    if (modalInstance) {
                        modalInstance.hide();
                    }
                }
            }
        });
    },

    setupScreenReaderSupport: function() {
        // Add screen reader announcements for dynamic content
        const announceToScreenReader = (message) => {
            const announcement = document.createElement('div');
            announcement.setAttribute('aria-live', 'polite');
            announcement.setAttribute('aria-atomic', 'true');
            announcement.className = 'sr-only';
            announcement.textContent = message;
            
            document.body.appendChild(announcement);
            
            setTimeout(() => {
                document.body.removeChild(announcement);
            }, 1000);
        };

        // Listen for investigation events
        window.addEventListener('investigationCompleted', (e) => {
            announceToScreenReader(`Investigation completed for ${e.detail.phone_number}`);
        });
    },

    setupFocusManagement: function() {
        // Ensure proper focus management for modals
        document.addEventListener('shown.bs.modal', (e) => {
            const modal = e.target;
            const focusableElements = modal.querySelectorAll(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );
            
            if (focusableElements.length > 0) {
                focusableElements[0].focus();
            }
        });
    }
};

// Application Initialization
const App = {
    init: function() {
        this.setupEventListeners();
        this.initializeComponents();
        this.loadInitialData();
    },

    setupEventListeners: function() {
        // Global error handling
        window.addEventListener('error', this.handleGlobalError);
        window.addEventListener('unhandledrejection', this.handleUnhandledRejection);
        
        // Online/offline detection
        window.addEventListener('online', () => {
            appState.isOnline = true;
            Utils.showNotification('Connection restored', 'success');
        });
        
        window.addEventListener('offline', () => {
            appState.isOnline = false;
            Utils.showNotification('Connection lost', 'warning');
        });
        
        // Session info modal
        const sessionInfoBtn = document.getElementById('session-info');
        if (sessionInfoBtn) {
            sessionInfoBtn.addEventListener('click', this.showSessionInfo);
        }
    },

    initializeComponents: function() {
        // Initialize all components
        SocketManager.init();
        PerformanceMonitor.init();
        A11y.init();
        
        // Initialize tooltips and popovers
        this.initializeBootstrapComponents();
        
        // Setup form validation
        this.setupFormValidation();
        
        // Setup file upload areas
        this.setupFileUploads();
    },

    initializeBootstrapComponents: function() {
        // Initialize tooltips
        const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltips.forEach(tooltip => {
            new bootstrap.Tooltip(tooltip);
        });
        
        // Initialize popovers
        const popovers = document.querySelectorAll('[data-bs-toggle="popover"]');
        popovers.forEach(popover => {
            new bootstrap.Popover(popover);
        });
    },

    setupFormValidation: function() {
        // Add validation to all forms with data-validate attribute
        const forms = document.querySelectorAll('form[data-validate]');
        forms.forEach(form => {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                
                if (FormValidator.validate(form)) {
                    // Form is valid, proceed with submission
                    form.submit();
                }
            });
            
            // Real-time validation
            const inputs = form.querySelectorAll('input, textarea, select');
            inputs.forEach(input => {
                input.addEventListener('blur', () => {
                    FormValidator.validate(form);
                });
            });
        });
    },

    setupFileUploads: function() {
        const uploadAreas = document.querySelectorAll('.file-drop-zone');
        uploadAreas.forEach(area => {
            area.addEventListener('dragover', (e) => {
                e.preventDefault();
                area.classList.add('dragover');
            });
            
            area.addEventListener('dragleave', () => {
                area.classList.remove('dragover');
            });
            
            area.addEventListener('drop', (e) => {
                e.preventDefault();
                area.classList.remove('dragover');
                
                const files = e.dataTransfer.files;
                this.handleFileUpload(files, area);
            });
        });
    },

    handleFileUpload: function(files, dropArea) {
        Array.from(files).forEach(file => {
            if (this.validateFile(file)) {
                // Handle the file upload
                console.log('Uploading file:', file.name);
                
                // Show progress
                const progress = document.createElement('div');
                progress.innerHTML = `
                    <div class="alert alert-info">
                        <i class="fas fa-upload me-2"></i>
                        Uploading ${file.name}...
                        <div class="progress mt-2">
                            <div class="progress-bar" style="width: 0%"></div>
                        </div>
                    </div>
                `;
                
                dropArea.appendChild(progress);
                
                // Simulate upload progress
                let progressValue = 0;
                const progressBar = progress.querySelector('.progress-bar');
                const interval = setInterval(() => {
                    progressValue += 10;
                    progressBar.style.width = progressValue + '%';
                    
                    if (progressValue >= 100) {
                        clearInterval(interval);
                        progress.querySelector('.alert').className = 'alert alert-success';
                        progress.querySelector('.alert').innerHTML = `
                            <i class="fas fa-check me-2"></i>
                            ${file.name} uploaded successfully
                        `;
                    }
                }, 200);
            }
        });
    },

    validateFile: function(file) {
        const maxSize = 16 * 1024 * 1024; // 16MB
        const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf', 'text/plain'];
        
        if (file.size > maxSize) {
            Utils.showNotification(`File ${file.name} is too large (max 16MB)`, 'danger');
            return false;
        }
        
        if (!allowedTypes.includes(file.type)) {
            Utils.showNotification(`File type ${file.type} is not allowed`, 'danger');
            return false;
        }
        
        return true;
    },

    loadInitialData: function() {
        // Load system status
        API.getSystemStatus()
            .then(status => {
                appState.systemStatus = status.status;
                console.log('System status:', status);
            })
            .catch(error => {
                console.error('Failed to load system status:', error);
            });
        
        // Load session info if logged in
        if (document.body.dataset.loggedIn === 'true') {
            this.loadSessionInfo();
        }
    },

    loadSessionInfo: function() {
        API.getSessionInfo()
            .then(sessionInfo => {
                appState.currentUser = sessionInfo;
                console.log('Session info:', sessionInfo);
            })
            .catch(error => {
                console.error('Failed to load session info:', error);
            });
    },

    showSessionInfo: function() {
        if (!appState.currentUser) {
            Utils.showNotification('Session information not available', 'warning');
            return;
        }
        
        const modalBody = document.getElementById('sessionModalBody');
        modalBody.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <h6>Session Details</h6>
                    <table class="table table-sm">
                        <tr><td><strong>Session ID:</strong></td><td>${appState.currentUser.session_id}</td></tr>
                        <tr><td><strong>Investigator:</strong></td><td>${appState.currentUser.investigator}</td></tr>
                        <tr><td><strong>Created:</strong></td><td>${new Date(appState.currentUser.created_at).toLocaleString()}</td></tr>
                        <tr><td><strong>Last Activity:</strong></td><td>${new Date(appState.currentUser.last_activity).toLocaleString()}</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <h6>Statistics</h6>
                    <table class="table table-sm">
                        <tr><td><strong>Investigations:</strong></td><td>${appState.currentUser.investigation_count}</td></tr>
                        <tr><td><strong>Status:</strong></td><td><span class="badge bg-${appState.currentUser.is_active ? 'success' : 'danger'}">${appState.currentUser.is_active ? 'Active' : 'Inactive'}</span></td></tr>
                        <tr><td><strong>Connection:</strong></td><td><span class="badge bg-${appState.isOnline ? 'success' : 'danger'}">${appState.isOnline ? 'Online' : 'Offline'}</span></td></tr>
                    </table>
                </div>
            </div>
        `;
        
        const modal = new bootstrap.Modal(document.getElementById('sessionModal'));
        modal.show();
    },

    handleGlobalError: function(error) {
        console.error('Global error:', error);
        
        if (appConfig.debugMode) {
            Utils.showNotification(`Error: ${error.message}`, 'danger');
        }
    },

    handleUnhandledRejection: function(event) {
        console.error('Unhandled promise rejection:', event.reason);
        
        if (appConfig.debugMode) {
            Utils.showNotification(`Promise rejection: ${event.reason}`, 'danger');
        }
    }
};

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're in debug mode
    appConfig.debugMode = localStorage.getItem('debugMode') === 'true';
    
    // Initialize the application
    App.init();
    
    console.log('Professional Phone Intelligence System initialized');
});

// Export utilities for global use
window.Utils = Utils;
window.API = API;
window.FormValidator = FormValidator;