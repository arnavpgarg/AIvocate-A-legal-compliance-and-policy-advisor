// API Client for AIvocate Compliance System
class ComplianceAPI {
    constructor(baseURL = 'http://localhost:8000') {
        this.baseURL = baseURL;
        this.token = localStorage.getItem('access_token');
    }

    // Authentication
    async login(email, password) {
        try {
            const formData = new FormData();
            formData.append('username', email);
            formData.append('password', password);

            const response = await fetch(`${this.baseURL}/token`, {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                const data = await response.json();
                this.token = data.access_token;
                localStorage.setItem('access_token', this.token);
                return data;
            } else {
                const error = await response.json();
                throw new Error(error.detail || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            throw error;
        }
    }

    logout() {
        this.token = null;
        localStorage.removeItem('access_token');
        window.location.href = '/login';
    }

    getAuthHeaders() {
        return {
            'Authorization': `Bearer ${this.token}`,
            'Content-Type': 'application/json'
        };
    }

    // Documents API
    async uploadDocument(file) {
        try {
            const formData = new FormData();
            formData.append('file', file);

            const response = await fetch(`${this.baseURL}/documents/upload`, {
                method: 'POST',
                body: formData
                // Don't set Content-Type header - browser sets it automatically for FormData
            });

            if (response.ok) {
                return await response.json();
            } else {
                const errorText = await response.text();
                let errorMessage = 'Upload failed';

                try {
                    const error = JSON.parse(errorText);
                    errorMessage = error.detail || errorMessage;
                } catch (e) {
                    errorMessage = errorText || errorMessage;
                }

                throw new Error(errorMessage);
            }
        } catch (error) {
            console.error('Upload error:', error);
            throw error;
        }
    }

    async getDocuments(page = 1, limit = 10, status = null) {
        try {
            let url = `${this.baseURL}/documents?page=${page}&limit=${limit}`;
            if (status) {
                url += `&status=${status}`;
            }

            const response = await fetch(url, {
                headers: this.getAuthHeaders()
            });

            if (response.ok) {
                return await response.json();
            } else {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to fetch documents');
            }
        } catch (error) {
            console.error('Documents error:', error);
            throw error;
        }
    }

    // Analyses API
    async startAnalysis(documentId, frameworkIds = [], customRuleIds = []) {
        try {
            const response = await fetch(`${this.baseURL}/documents/${documentId}/analyses`, {
                method: 'POST',
                headers: this.getAuthHeaders(),
                body: JSON.stringify({
                    framework_ids: frameworkIds,
                    custom_rule_ids: customRuleIds
                })
            });

            if (response.ok) {
                return await response.json();
            } else {
                const error = await response.json();
                throw new Error(error.detail || 'Analysis failed');
            }
        } catch (error) {
            console.error('Analysis error:', error);
            throw error;
        }
    }

    async getAnalysisResults(analysisId) {
        try {
            const response = await fetch(`${this.baseURL}/analyses/${analysisId}/results`, {
                headers: this.getAuthHeaders()
            });

            if (response.ok) {
                return await response.json();
            } else {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to fetch analysis results');
            }
        } catch (error) {
            console.error('Analysis results error:', error);
            throw error;
        }
    }

    // Users API
    async getUsers(status = null, roleId = null) {
        try {
            let url = `${this.baseURL}/users`;
            const params = new URLSearchParams();
            if (status) params.append('status', status);
            if (roleId) params.append('role_id', roleId);
            if (params.toString()) url += `?${params}`;

            const response = await fetch(url, {
                headers: this.getAuthHeaders()
            });

            if (response.ok) {
                return await response.json();
            } else {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to fetch users');
            }
        } catch (error) {
            console.error('Users error:', error);
            throw error;
        }
    }

    // Reports API
    async generateReport(reportType, filters = {}) {
        try {
            const response = await fetch(`${this.baseURL}/reports`, {
                method: 'POST',
                headers: this.getAuthHeaders(),
                body: JSON.stringify({
                    report_type: reportType,
                    filters: filters
                })
            });

            if (response.ok) {
                return await response.json();
            } else {
                const error = await response.json();
                throw new Error(error.detail || 'Report generation failed');
            }
        } catch (error) {
            console.error('Report error:', error);
            throw error;
        }
    }

    async getReports() {
        try {
            const response = await fetch(`${this.baseURL}/reports`, {
                headers: this.getAuthHeaders()
            });

            if (response.ok) {
                return await response.json();
            } else {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to fetch reports');
            }
        } catch (error) {
            console.error('Reports error:', error);
            throw error;
        }
    }

    // Custom Rules API
    async getCustomRules() {
        try {
            const response = await fetch(`${this.baseURL}/rules/custom`, {
                headers: this.getAuthHeaders()
            });

            if (response.ok) {
                return await response.json();
            } else {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to fetch custom rules');
            }
        } catch (error) {
            console.error('Custom rules error:', error);
            throw error;
        }
    }

    async createCustomRule(rule) {
        try {
            const response = await fetch(`${this.baseURL}/rules/custom`, {
                method: 'POST',
                headers: this.getAuthHeaders(),
                body: JSON.stringify(rule)
            });

            if (response.ok) {
                return await response.json();
            } else {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to create custom rule');
            }
        } catch (error) {
            console.error('Create custom rule error:', error);
            throw error;
        }
    }

    // Utility methods
    isAuthenticated() {
        return this.token !== null;
    }

    async makeRequest(url, options = {}) {
        try {
            const response = await fetch(url, {
                headers: this.getAuthHeaders(),
                ...options
            });

            if (response.status === 401) {
                this.logout();
                throw new Error('Session expired. Please login again.');
            }

            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                throw new Error(error.detail || `Request failed: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API request error:', error);
            throw error;
        }
    }
}

// Create global API instance
const api = new ComplianceAPI();
