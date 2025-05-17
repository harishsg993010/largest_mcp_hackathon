/**
 * Agents management functionality
 */

// Load agents when the page loads
document.addEventListener('DOMContentLoaded', function() {
  if (window.location.pathname.includes('agents.html')) {
    loadAgents();
    setupAgentForm();
  }
});

// Load agents from the API
async function loadAgents() {
  try {
    const agentsContainer = document.getElementById('agents-list');
    if (!agentsContainer) return;
    
    agentsContainer.innerHTML = '<p>Loading agents...</p>';
    
    // Use the updated API request with trailing slash
    const agents = await apiRequest('/agents/');
    
    if (agents.length === 0) {
      agentsContainer.innerHTML = '<p>No agents found. Create your first agent below.</p>';
      return;
    }
    
    let html = '';
    agents.forEach(agent => {
      html += `
        <div class="agent-card">
          <h3>${agent.instance_id}</h3>
          <p><strong>Type:</strong> ${agent.agent_type}</p>
          <p><strong>Model:</strong> ${agent.agent_model}</p>
          <p><strong>Provider:</strong> ${agent.agent_provider}</p>
          <div class="agent-actions">
            <button class="btn btn-primary btn-sm" onclick="viewAgentDetails('${agent.id}')">View Details</button>
            <button class="btn btn-danger btn-sm" onclick="deleteAgent('${agent.id}')">Delete</button>
          </div>
        </div>
      `;
    });
    
    agentsContainer.innerHTML = html;
  } catch (error) {
    console.error('Error loading agents:', error);
    showAlert('Failed to load agents. Please try again.');
  }
}

// Setup agent creation form
function setupAgentForm() {
  const agentForm = document.getElementById('agent-form');
  if (!agentForm) return;
  
  agentForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const agentData = {
      instance_id: document.getElementById('instance-id').value,
      agent_type: document.getElementById('agent-type').value,
      agent_model: document.getElementById('agent-model').value,
      agent_provider: document.getElementById('agent-provider').value,
      capabilities: document.getElementById('capabilities').value.split(',').map(cap => cap.trim())
    };
    
    try {
      // Use the updated API request with trailing slash
      await apiRequest('/agents/', 'POST', agentData);
      showAlert('Agent created successfully!', 'success');
      agentForm.reset();
      loadAgents();
    } catch (error) {
      console.error('Error creating agent:', error);
      showAlert('Failed to create agent. Please try again.');
    }
  });
}

// View agent details
async function viewAgentDetails(agentId) {
  try {
    debugLog(`Viewing details for agent: ${agentId}`);
    
    // Redirect to the agent details page instead of showing a modal
    window.location.href = `agent-details.html?id=${agentId}`;
  } catch (error) {
    console.error('Error navigating to agent details:', error);
    showAlert('Failed to navigate to agent details. Please try again.');
  }
}

// Delete an agent
async function deleteAgent(agentId) {
  if (!confirm('Are you sure you want to delete this agent?')) return;
  
  try {
    // Use the updated API request with trailing slash
    await apiRequest(`/agents/${agentId}/`, 'DELETE');
    showAlert('Agent deleted successfully!', 'success');
    loadAgents();
  } catch (error) {
    console.error('Error deleting agent:', error);
    showAlert('Failed to delete agent. Please try again.');
  }
}
