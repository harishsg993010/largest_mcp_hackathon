// MCP Auth Platform - Main JavaScript

// API Base URL - Change this to your backend URL in production
const API_BASE_URL = 'http://localhost:5000/api';

// Debug mode - set to true to enable console logging
const DEBUG = true;

// Log function that only logs in debug mode
function debugLog(...args) {
  if (DEBUG) {
    console.log(...args);
  }
}

// DOM Elements
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const logoutBtn = document.getElementById('logout-btn');
const agentsList = document.getElementById('agents-list');
const createAgentForm = document.getElementById('create-agent-form');
const delegationsList = document.getElementById('delegations-list');
const createDelegationForm = document.getElementById('create-delegation-form');
const alertContainer = document.getElementById('alert-container');

// Check if user is logged in
function checkAuth() {
  const token = localStorage.getItem('access_token');
  if (token) {
    // Show authenticated UI
    document.querySelectorAll('.auth-required').forEach(el => el.style.display = 'block');
    document.querySelectorAll('.auth-hidden').forEach(el => el.style.display = 'none');
    
    // Load user info
    getUserInfo();
    
    // Load agents if on agents page
    if (agentsList) {
      getAgents();
    }
    
    // Load delegations if on delegations page
    if (delegationsList) {
      getDelegations();
    }
  } else {
    // Show non-authenticated UI
    document.querySelectorAll('.auth-required').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.auth-hidden').forEach(el => el.style.display = 'block');
  }
}

// Show alert message
function showAlert(message, type = 'danger') {
  if (!alertContainer) return;
  
  const alert = document.createElement('div');
  alert.className = `alert alert-${type}`;
  alert.textContent = message;
  
  // Add close button
  const closeBtn = document.createElement('span');
  closeBtn.innerHTML = '&times;';
  closeBtn.className = 'close-alert';
  closeBtn.onclick = () => alert.remove();
  alert.appendChild(closeBtn);
  
  alertContainer.appendChild(alert);
  
  // Auto-remove after 5 seconds
  setTimeout(() => {
    alert.remove();
  }, 5000);
}

// API request helper
async function apiRequest(endpoint, method = 'GET', data = null) {
  // Try both XMLHttpRequest and fetch to maximize compatibility
  return new Promise((resolve, reject) => {
    // Format the endpoint
    if (endpoint && !endpoint.endsWith('/')) {
      endpoint = endpoint + '/';
    }
    
    if (endpoint && !endpoint.startsWith('/')) {
      endpoint = '/' + endpoint;
    }
    
    const url = `${API_BASE_URL}${endpoint}`;
    debugLog(`Making API request to: ${url}`);
    
    // Set up headers
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };
    
    const token = localStorage.getItem('access_token');
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
      debugLog('Using token for authentication');
    }
    
    // Try XMLHttpRequest first (more compatible with older browsers)
    const xhr = new XMLHttpRequest();
    xhr.open(method, url, true);
    
    // Set headers
    Object.keys(headers).forEach(key => {
      xhr.setRequestHeader(key, headers[key]);
    });
    
    xhr.onload = function() {
      debugLog(`XHR response received: ${xhr.status}`);
      
      let responseData;
      
      // Parse response
      try {
        if (xhr.status === 204) {
          responseData = {};
        } else if (xhr.getResponseHeader('Content-Type') && 
                  xhr.getResponseHeader('Content-Type').includes('application/json')) {
          responseData = JSON.parse(xhr.responseText);
        } else {
          responseData = { message: xhr.responseText };
        }
      } catch (e) {
        responseData = { message: xhr.responseText || 'No response data' };
      }
      
      // Check if response is OK
      if (xhr.status >= 200 && xhr.status < 300) {
        debugLog('Request successful', responseData);
        resolve(responseData);
      } else {
        debugLog('Request failed', xhr.status, responseData);
        const error = new Error(responseData.error || responseData.message || `Request failed with status ${xhr.status}`);
        error.status = xhr.status;
        error.response = responseData;
        showAlert(error.message);
        reject(error);
      }
    };
    
    xhr.onerror = function() {
      debugLog('XHR network error, falling back to fetch');
      
      // Fall back to fetch if XHR fails
      const fetchOptions = {
        method,
        headers,
        credentials: 'include',
        mode: 'cors'
      };
      
      // Only add body for non-GET requests
      if (method !== 'GET' && data) {
        fetchOptions.body = JSON.stringify(data);
      }
      
      fetch(url, fetchOptions)
        .then(response => {
          debugLog(`Fetch response received: ${response.status}`);
          
          // For 204 No Content responses, return empty object
          if (response.status === 204) {
            return {};
          }
          
          // Check content type
          const contentType = response.headers.get('content-type');
          if (contentType && contentType.includes('application/json')) {
            return response.json().then(data => ({ data, response }));
          } else {
            return response.text().then(text => ({ 
              data: { message: text }, 
              response 
            }));
          }
        })
        .then(({ data, response }) => {
          if (response.ok) {
            debugLog('Fetch request successful', data);
            resolve(data);
          } else {
            debugLog('Fetch request failed', response.status, data);
            const error = new Error(data.error || data.message || `Request failed with status ${response.status}`);
            error.status = response.status;
            error.response = data;
            showAlert(error.message);
            reject(error);
          }
        })
        .catch(error => {
          debugLog('Fetch error:', error);
          showAlert(error.message || 'Network error. Please check your connection.');
          reject(error);
        });
    };
    
    // Send the request
    try {
      if (method !== 'GET' && data) {
        xhr.send(JSON.stringify(data));
      } else {
        xhr.send();
      }
    } catch (e) {
      debugLog('Error sending XHR:', e);
      xhr.onerror();
    }
  });
}

// User Authentication

// Login
async function login(username, password) {
  try {
    debugLog('Attempting login with:', { username });
    showAlert('Logging in...', 'info');
    
    // Use our improved apiRequest function
    const data = await apiRequest('/auth/login', 'POST', { username, password });
    debugLog('Login successful, received tokens:', data);
    
    // Store tokens and user info
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    if (data.user_id) {
      localStorage.setItem('user_id', data.user_id);
    }
    
    // Store user data if available
    if (data.user) {
      localStorage.setItem('user_data', JSON.stringify(data.user));
    }
    
    // Update UI
    checkAuth();
    
    // Show success message
    showAlert('Login successful! Redirecting...', 'success');
    
    // Redirect to dashboard after a short delay
    setTimeout(() => {
      window.location.href = 'dashboard.html';
    }, 1000);
    
    return data;
  } catch (error) {
    debugLog('Login error:', error);
    showAlert(`Login failed: ${error.message}`, 'danger');
    throw error;
  }
}

// Register
async function register(userData) {
  try {
    const data = await apiRequest('/auth/register', 'POST', userData);
    showAlert('Registration successful! Please login.', 'success');
    
    // Redirect to login
    window.location.href = 'login.html';
    
    return data;
  } catch (error) {
    throw error;
  }
}

// Logout
function logout() {
  // Remove tokens
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  
  // Update UI
  checkAuth();
  
  // Redirect to home
  window.location.href = 'index.html';
}

// Get user info
async function getUserInfo() {
  try {
    const data = await apiRequest('/users/me');
    
    // Update UI with user info
    const userNameElements = document.querySelectorAll('.user-name');
    userNameElements.forEach(el => {
      el.textContent = data.user.username;
    });
    
    return data.user;
  } catch (error) {
    // If unauthorized, logout
    if (error.message === 'Unauthorized' || error.message === 'Token expired') {
      logout();
    }
    throw error;
  }
}

// Agent Management

// Get all agents
async function getAgents() {
  try {
    const data = await apiRequest('/agents');
    
    if (agentsList) {
      agentsList.innerHTML = '';
      
      if (data.agents.length === 0) {
        agentsList.innerHTML = '<p>No agents found. Create your first agent!</p>';
        return;
      }
      
      data.agents.forEach(agent => {
        const agentCard = document.createElement('div');
        agentCard.className = 'agent-card';
        agentCard.innerHTML = `
          <div class="agent-icon">${agent.agent_type.charAt(0).toUpperCase()}</div>
          <div class="agent-info">
            <h3 class="agent-name">${agent.instance_id}</h3>
            <p class="agent-type">${agent.agent_type} | ${agent.agent_model} | ${agent.agent_provider}</p>
          </div>
          <span class="agent-status status-${agent.trust_level}">${agent.trust_level}</span>
          <div class="agent-actions">
            <button class="btn btn-primary btn-sm view-agent" data-id="${agent.id}">View</button>
            <button class="btn btn-danger btn-sm delete-agent" data-id="${agent.id}">Delete</button>
          </div>
        `;
        
        agentsList.appendChild(agentCard);
      });
      
      // Add event listeners for agent actions
      document.querySelectorAll('.view-agent').forEach(btn => {
        btn.addEventListener('click', () => {
          window.location.href = `agent-details.html?id=${btn.dataset.id}`;
        });
      });
      
      document.querySelectorAll('.delete-agent').forEach(btn => {
        btn.addEventListener('click', async () => {
          if (confirm('Are you sure you want to delete this agent?')) {
            await deleteAgent(btn.dataset.id);
            getAgents();
          }
        });
      });
    }
    
    return data.agents;
  } catch (error) {
    throw error;
  }
}

// Create agent
async function createAgent(agentData) {
  try {
    const data = await apiRequest('/agents', 'POST', agentData);
    showAlert('Agent created successfully!', 'success');
    
    // Refresh agents list
    getAgents();
    
    return data.agent;
  } catch (error) {
    throw error;
  }
}

// Get agent details
async function getAgentDetails(agentId) {
  try {
    const data = await apiRequest(`/agents/${agentId}`);
    return data.agent;
  } catch (error) {
    throw error;
  }
}

// Update agent
async function updateAgent(agentId, agentData) {
  try {
    const data = await apiRequest(`/agents/${agentId}`, 'PUT', agentData);
    showAlert('Agent updated successfully!', 'success');
    return data.agent;
  } catch (error) {
    throw error;
  }
}

// Delete agent
async function deleteAgent(agentId) {
  try {
    await apiRequest(`/agents/${agentId}`, 'DELETE');
    showAlert('Agent deleted successfully!', 'success');
  } catch (error) {
    throw error;
  }
}

// Generate agent token
async function generateAgentToken(agentId, tokenData) {
  try {
    const data = await apiRequest(`/agents/${agentId}/token`, 'POST', tokenData);
    showAlert('Agent token generated successfully!', 'success');
    return data;
  } catch (error) {
    throw error;
  }
}

// Attestation Management

// Verify attestation
async function verifyAttestation(attestationData) {
  try {
    const data = await apiRequest('/attestation/verify', 'POST', attestationData);
    showAlert('Attestation verified successfully!', 'success');
    return data;
  } catch (error) {
    throw error;
  }
}

// Get attestation nonce
async function getAttestationNonce() {
  try {
    const data = await apiRequest('/attestation/nonce');
    return data.nonce;
  } catch (error) {
    throw error;
  }
}

// Delegation Management

// Get all delegations
async function getDelegations() {
  try {
    const data = await apiRequest('/delegation');
    
    if (delegationsList) {
      delegationsList.innerHTML = '';
      
      if (data.delegations.length === 0) {
        delegationsList.innerHTML = '<p>No delegations found.</p>';
        return;
      }
      
      data.delegations.forEach(delegation => {
        const delegationCard = document.createElement('div');
        delegationCard.className = 'card mb-3';
        delegationCard.innerHTML = `
          <div class="card-header">
            <h3 class="card-title">Delegation: ${delegation.purpose || 'No purpose specified'}</h3>
          </div>
          <div class="card-body">
            <p><strong>Delegatee:</strong> ${delegation.delegatee_id}</p>
            <p><strong>Scope:</strong> ${delegation.scope}</p>
            <p><strong>Created:</strong> ${new Date(delegation.delegated_at).toLocaleString()}</p>
            <p><strong>Expires:</strong> ${delegation.expires_at ? new Date(delegation.expires_at).toLocaleString() : 'Never'}</p>
            <p><strong>Status:</strong> ${delegation.is_active ? '<span class="status-verified">Active</span>' : '<span class="status-unverified">Inactive</span>'}</p>
          </div>
          <div class="card-footer">
            <button class="btn btn-danger btn-sm revoke-delegation" data-id="${delegation.id}">Revoke</button>
          </div>
        `;
        
        delegationsList.appendChild(delegationCard);
      });
      
      // Add event listeners for delegation actions
      document.querySelectorAll('.revoke-delegation').forEach(btn => {
        btn.addEventListener('click', async () => {
          if (confirm('Are you sure you want to revoke this delegation?')) {
            await revokeDelegation(btn.dataset.id);
            getDelegations();
          }
        });
      });
    }
    
    return data.delegations;
  } catch (error) {
    throw error;
  }
}

// Create delegation
async function createDelegation(delegationData) {
  try {
    const data = await apiRequest('/delegation', 'POST', delegationData);
    showAlert('Delegation created successfully!', 'success');
    
    // Refresh delegations list
    getDelegations();
    
    return data;
  } catch (error) {
    throw error;
  }
}

// Revoke delegation
async function revokeDelegation(delegationId) {
  try {
    await apiRequest(`/delegation/${delegationId}`, 'DELETE');
    showAlert('Delegation revoked successfully!', 'success');
  } catch (error) {
    throw error;
  }
}

// Get delegation chain
async function getDelegationChain() {
  try {
    const data = await apiRequest('/delegation/chain');
    return data.delegation_chain;
  } catch (error) {
    throw error;
  }
}

// Event Listeners

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  // Check authentication status
  checkAuth();
  
  // Login form
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      
      try {
        await login(username, password);
      } catch (error) {
        showAlert(error.message);
      }
    });
  }
  
  // Register form
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const userData = {
        username: document.getElementById('username').value,
        email: document.getElementById('email').value,
        password: document.getElementById('password').value,
        first_name: document.getElementById('first-name').value,
        last_name: document.getElementById('last-name').value
      };
      
      try {
        await register(userData);
      } catch (error) {
        showAlert(error.message);
      }
    });
  }
  
  // Logout button
  if (logoutBtn) {
    logoutBtn.addEventListener('click', (e) => {
      e.preventDefault();
      logout();
    });
  }
  
  // Create agent form
  if (createAgentForm) {
    createAgentForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const agentData = {
        instance_id: document.getElementById('instance-id').value,
        agent_type: document.getElementById('agent-type').value,
        agent_model: document.getElementById('agent-model').value,
        agent_version: document.getElementById('agent-version').value,
        agent_provider: document.getElementById('agent-provider').value,
        capabilities: document.getElementById('capabilities').value.split(',').map(cap => cap.trim())
      };
      
      try {
        await createAgent(agentData);
        createAgentForm.reset();
      } catch (error) {
        showAlert(error.message);
      }
    });
  }
  
  // Create delegation form
  if (createDelegationForm) {
    createDelegationForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const delegationData = {
        delegatee_id: document.getElementById('delegatee-id').value,
        scope: document.getElementById('scope').value,
        purpose: document.getElementById('purpose').value,
        expires_in: parseInt(document.getElementById('expires-in').value) * 3600 // Convert hours to seconds
      };
      
      // Add constraints if provided
      const constraints = document.getElementById('constraints').value;
      if (constraints) {
        try {
          delegationData.constraints = JSON.parse(constraints);
        } catch (error) {
          showAlert('Invalid JSON in constraints field');
          return;
        }
      }
      
      try {
        await createDelegation(delegationData);
        createDelegationForm.reset();
      } catch (error) {
        showAlert(error.message);
      }
    });
  }
});

// Modal functionality
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = 'block';
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = 'none';
  }
}

// Close modal when clicking outside
window.addEventListener('click', (e) => {
  if (e.target.classList.contains('modal')) {
    e.target.style.display = 'none';
  }
});
