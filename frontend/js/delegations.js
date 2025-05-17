/**
 * Delegations management functionality
 */

// Load delegations when the page loads
document.addEventListener('DOMContentLoaded', function() {
  if (window.location.pathname.includes('delegations.html')) {
    loadDelegations();
    setupDelegationForm();
  }
});

// Load delegations from the API
async function loadDelegations() {
  try {
    const delegationsContainer = document.getElementById('delegations-list');
    if (!delegationsContainer) return;
    
    delegationsContainer.innerHTML = '<p>Loading delegations...</p>';
    
    // Use the updated API request with trailing slash
    const delegations = await apiRequest('/delegation/');
    
    if (delegations.length === 0) {
      delegationsContainer.innerHTML = '<p>No delegations found. Create your first delegation below.</p>';
      return;
    }
    
    let html = '';
    delegations.forEach(delegation => {
      html += `
        <div class="delegation-card">
          <h3>Delegation #${delegation.id.substring(0, 8)}</h3>
          <p><strong>Delegator:</strong> ${delegation.delegator_type === 'user' ? 'User' : 'Agent'} (${delegation.delegator_id})</p>
          <p><strong>Delegatee:</strong> ${delegation.delegatee_type === 'user' ? 'User' : 'Agent'} (${delegation.delegatee_id})</p>
          <p><strong>Scope:</strong> ${delegation.scope.join(', ')}</p>
          <p><strong>Expires:</strong> ${new Date(delegation.expires_at).toLocaleString()}</p>
          <div class="delegation-actions">
            <button class="btn btn-primary btn-sm" onclick="viewDelegationDetails('${delegation.id}')">View Details</button>
            <button class="btn btn-danger btn-sm" onclick="revokeDelegation('${delegation.id}')">Revoke</button>
          </div>
        </div>
      `;
    });
    
    delegationsContainer.innerHTML = html;
  } catch (error) {
    console.error('Error loading delegations:', error);
    showAlert('Failed to load delegations. Please try again.');
  }
}

// Setup delegation creation form
async function setupDelegationForm() {
  const delegationForm = document.getElementById('delegation-form');
  if (!delegationForm) return;
  
  // Load agents for the dropdown
  try {
    const agents = await apiRequest('/agents/');
    const delegateeSelect = document.getElementById('delegatee-id');
    
    agents.forEach(agent => {
      const option = document.createElement('option');
      option.value = agent.id;
      option.textContent = `${agent.instance_id} (${agent.agent_type})`;
      delegateeSelect.appendChild(option);
    });
  } catch (error) {
    console.error('Error loading agents for delegation form:', error);
  }
  
  delegationForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const delegationData = {
      delegator_type: 'user', // Current user is always the delegator
      delegator_id: localStorage.getItem('user_id'),
      delegatee_type: 'agent', // Currently only supporting delegation to agents
      delegatee_id: document.getElementById('delegatee-id').value,
      scope: document.getElementById('scope').value.split(',').map(s => s.trim()),
      expires_at: document.getElementById('expires-at').value
    };
    
    try {
      // Use the updated API request with trailing slash
      await apiRequest('/delegation/', 'POST', delegationData);
      showAlert('Delegation created successfully!', 'success');
      delegationForm.reset();
      loadDelegations();
    } catch (error) {
      console.error('Error creating delegation:', error);
      showAlert('Failed to create delegation. Please try again.');
    }
  });
}

// View delegation details
async function viewDelegationDetails(delegationId) {
  try {
    // Use the updated API request with trailing slash
    const delegation = await apiRequest(`/delegation/${delegationId}/`);
    
    // Create a modal to display delegation details
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-content">
        <span class="close">&times;</span>
        <h2>Delegation Details</h2>
        <p><strong>ID:</strong> ${delegation.id}</p>
        <p><strong>Delegator Type:</strong> ${delegation.delegator_type}</p>
        <p><strong>Delegator ID:</strong> ${delegation.delegator_id}</p>
        <p><strong>Delegatee Type:</strong> ${delegation.delegatee_type}</p>
        <p><strong>Delegatee ID:</strong> ${delegation.delegatee_id}</p>
        <p><strong>Scope:</strong> ${delegation.scope.join(', ')}</p>
        <p><strong>Created At:</strong> ${new Date(delegation.created_at).toLocaleString()}</p>
        <p><strong>Expires At:</strong> ${new Date(delegation.expires_at).toLocaleString()}</p>
        <p><strong>Status:</strong> ${delegation.is_active ? 'Active' : 'Inactive'}</p>
      </div>
    `;
    
    document.body.appendChild(modal);
    
    // Close modal when clicking on the close button
    const closeBtn = modal.querySelector('.close');
    closeBtn.addEventListener('click', function() {
      document.body.removeChild(modal);
    });
    
    // Close modal when clicking outside the modal content
    window.addEventListener('click', function(event) {
      if (event.target === modal) {
        document.body.removeChild(modal);
      }
    });
  } catch (error) {
    console.error('Error fetching delegation details:', error);
    showAlert('Failed to load delegation details. Please try again.');
  }
}

// Revoke a delegation
async function revokeDelegation(delegationId) {
  if (!confirm('Are you sure you want to revoke this delegation?')) return;
  
  try {
    // Use the updated API request with trailing slash
    await apiRequest(`/delegation/${delegationId}/revoke/`, 'POST');
    showAlert('Delegation revoked successfully!', 'success');
    loadDelegations();
  } catch (error) {
    console.error('Error revoking delegation:', error);
    showAlert('Failed to revoke delegation. Please try again.');
  }
}
