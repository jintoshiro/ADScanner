import pytest
from types import SimpleNamespace
from adscanner.checks.base import ScanContext, CheckStatus
from adscanner.checks.smb_probe import probe_smb_signing

def test_smb_probe_failure():
    """Mock SMBConnection để giả lập lỗi timeout."""
    from unittest.mock import patch
    with patch("adscanner.collector.smb_probe.SMBConnection", side_effect=OSError("timeout")):
        p = probe_smb_signing("dc01", timeout=1)
    assert p.signing_required is None
    assert "timeout" in p.error