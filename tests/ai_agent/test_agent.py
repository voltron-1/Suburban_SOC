import pytest
from unittest.mock import patch, MagicMock
from agent import Agent, AlertContext

@pytest.fixture
def agent():
    return Agent()

@pytest.fixture
def payload():
    return {
        "tenant_id": "test-tenant",
        "source_ip": "192.168.1.10",
        "source_mac": "00:11:22:33:44:55",
        "severity": "critical",
        "raw_log": "Brute force attack detected"
    }

@patch('agent.is_duplicate')
@patch('agent.write_checkpoint')
@patch('agent.is_excluded')
@patch('agent._append_pending_action')
@patch('agent.analyze_alert_with_ai')
@patch('agent.create_case')
def test_phase_1_draft_human_gate(mock_case, mock_ai, mock_append, mock_excluded, mock_write, mock_dup, agent, payload):
    # Setup mocks
    mock_dup.return_value = False
    mock_excluded.return_value = False
    mock_ai.return_value = "AI summary"
    mock_case.return_value = "case-123"
    
    # Run Phase 1
    result = agent.run(payload)
    
    # Verify Human Gate: must park at PENDING_APPROVAL and draft action
    assert result.status_code == 200
    assert result.response['status'] == 'pending_approval'
    mock_append.assert_called_once()
    assert mock_append.call_args[0][0]['target_ip'] == "192.168.1.10"
    
    # Verify Checkpoints
    assert mock_write.call_count == 2
    # First checkpoint: PERCEIVING
    assert mock_write.call_args_list[0][0][2] == "PERCEIVING"
    # Second checkpoint: PENDING_APPROVAL
    assert mock_write.call_args_list[1][0][2] == "PENDING_APPROVAL"

@patch('agent.is_duplicate')
def test_idempotency_duplicate_rejected(mock_dup, agent, payload):
    mock_dup.return_value = True
    result = agent.run(payload)
    
    assert result.status_code == 200
    assert result.response['status'] == 'ignored'

@patch('agent.is_awaiting_approval')
@patch('agent.read_checkpoint')
@patch('agent._execute_isolation')
@patch('agent.write_checkpoint')
def test_phase_2_execution(mock_write, mock_exec, mock_read, mock_awaiting, agent, payload):
    # Setup mocks
    mock_awaiting.return_value = True
    mock_read.return_value = {"context": payload}
    mock_exec.return_value = (True, "Blocked on router")
    
    # Run Phase 2
    result = agent.execute_approved("test-tenant", "fake-alert-id", "human")
    
    # Verify execution and final checkpoint
    assert result.status_code == 200
    assert result.response['status'] == 'executed'
    mock_exec.assert_called_once_with("00:11:22:33:44:55", "192.168.1.10", "test-tenant")
    mock_write.assert_called_once_with("test-tenant", "fake-alert-id", "EXECUTED")

@patch('agent.is_awaiting_approval')
def test_phase_2_state_rejection(mock_awaiting, agent):
    mock_awaiting.return_value = False
    
    result = agent.execute_approved("test-tenant", "fake-alert-id")
    
    assert result.status_code == 409
    assert result.response['status'] == 'error'
