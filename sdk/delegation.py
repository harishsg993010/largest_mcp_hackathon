"""
Delegation module for the MCP Auth SDK.

This module implements the delegation chain functionality
specified in the OpenID Connect for Agents (OIDC-A) 1.0 specification.
"""

import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class DelegationStep:
    """
    Represents a single step in a delegation chain.
    
    Each step includes information about the delegator (entity granting permission),
    the delegatee (entity receiving permission), and the scope and constraints
    of the delegation.
    """
    issuer: str
    subject: str
    audience: str
    delegated_at: int
    scope: str
    purpose: Optional[str] = None
    constraints: Optional[Dict] = None
    jti: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """
        Convert the delegation step to a dictionary.
        
        Returns:
            Dict: Dictionary representation of the delegation step
        """
        result = {
            'iss': self.issuer,
            'sub': self.subject,
            'aud': self.audience,
            'delegated_at': self.delegated_at,
            'scope': self.scope
        }
        
        if self.purpose:
            result['purpose'] = self.purpose
        
        if self.constraints:
            result['constraints'] = self.constraints
        
        if self.jti:
            result['jti'] = self.jti
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'DelegationStep':
        """
        Create a delegation step from a dictionary.
        
        Args:
            data: Dictionary containing delegation step data
            
        Returns:
            DelegationStep: Delegation step instance
        """
        return cls(
            issuer=data.get('iss'),
            subject=data.get('sub'),
            audience=data.get('aud'),
            delegated_at=data.get('delegated_at'),
            scope=data.get('scope'),
            purpose=data.get('purpose'),
            constraints=data.get('constraints'),
            jti=data.get('jti')
        )


class DelegationChain:
    """
    Represents a chain of delegation steps.
    
    A delegation chain represents the sequence of authority delegation
    from the original user through potentially multiple agents.
    """
    
    def __init__(self, steps: List[DelegationStep] = None):
        """
        Initialize a delegation chain.
        
        Args:
            steps: List of delegation steps
        """
        self.steps = steps or []
    
    def add_step(self, step: DelegationStep) -> None:
        """
        Add a step to the delegation chain.
        
        Args:
            step: Delegation step to add
        """
        self.steps.append(step)
    
    def validate(self) -> bool:
        """
        Validate the delegation chain.
        
        Performs the following validation checks:
        1. Order verification: Confirms chronological order based on delegated_at
        2. Audience matching: Confirms aud of step N matches sub of step N+1
        3. Scope reduction: Verifies scope in each step is a subset of the delegator's scopes
        
        Returns:
            bool: True if the chain is valid
        """
        if not self.steps:
            return True  # Empty chain is valid
        
        # Check chronological order
        for i in range(1, len(self.steps)):
            if self.steps[i].delegated_at < self.steps[i-1].delegated_at:
                return False
        
        # Check audience matching
        for i in range(len(self.steps) - 1):
            if self.steps[i].audience != self.steps[i+1].subject:
                return False
        
        # Check scope reduction
        for i in range(1, len(self.steps)):
            prev_scopes = set(self.steps[i-1].scope.split())
            current_scopes = set(self.steps[i].scope.split())
            
            # Current scopes must be a subset of previous scopes
            if not current_scopes.issubset(prev_scopes):
                return False
        
        return True
    
    def get_effective_scope(self) -> str:
        """
        Get the effective scope of the delegation chain.
        
        The effective scope is the scope of the last step in the chain.
        
        Returns:
            str: Effective scope
        """
        if not self.steps:
            return ""
        
        return self.steps[-1].scope
    
    def get_original_delegator(self) -> str:
        """
        Get the original delegator in the chain.
        
        Returns:
            str: Subject ID of the original delegator
        """
        if not self.steps:
            return ""
        
        return self.steps[0].subject
    
    def get_final_delegatee(self) -> str:
        """
        Get the final delegatee in the chain.
        
        Returns:
            str: Audience ID of the final delegatee
        """
        if not self.steps:
            return ""
        
        return self.steps[-1].audience
    
    def to_list(self) -> List[Dict]:
        """
        Convert the delegation chain to a list of dictionaries.
        
        Returns:
            List[Dict]: List of delegation step dictionaries
        """
        return [step.to_dict() for step in self.steps]
    
    @classmethod
    def from_list(cls, data: List[Dict]) -> 'DelegationChain':
        """
        Create a delegation chain from a list of dictionaries.
        
        Args:
            data: List of delegation step dictionaries
            
        Returns:
            DelegationChain: Delegation chain instance
        """
        steps = [DelegationStep.from_dict(step_data) for step_data in data]
        return cls(steps)
    
    def __len__(self) -> int:
        """
        Get the length of the delegation chain.
        
        Returns:
            int: Number of steps in the chain
        """
        return len(self.steps)
    
    def __getitem__(self, index: int) -> DelegationStep:
        """
        Get a step from the delegation chain by index.
        
        Args:
            index: Index of the step
            
        Returns:
            DelegationStep: Delegation step at the specified index
        """
        return self.steps[index]
