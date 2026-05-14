import pytest
from app.scanners.s3_scanner import check_s3_buckets, _demo_findings as s3_demo
from app.scanners.sg_scanner import check_security_groups, _demo_findings as sg_demo
from app.scanners.iam_scanner import check_iam_keys, _demo_findings as iam_demo
from app.scanners.encryption_scanner import check_encryption, _demo_findings as enc_demo


class TestS3Scanner:
    def test_returns_list(self):
        result = check_s3_buckets()
        assert isinstance(result, list)

    def test_findings_have_required_fields(self):
        result = s3_demo()
        for finding in result:
            assert "resource_id" in finding
            assert "scan_type" in finding
            assert "severity" in finding
            assert "finding" in finding
            assert "recommendation" in finding
            assert "cis_benchmark" in finding

    def test_severity_is_valid(self):
        result = s3_demo()
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for finding in result:
            assert finding["severity"] in valid_severities

    def test_scan_type_is_s3(self):
        result = s3_demo()
        for finding in result:
            assert finding["scan_type"] == "s3"


class TestSecurityGroupScanner:
    def test_returns_list(self):
        result = check_security_groups()
        assert isinstance(result, list)

    def test_findings_have_required_fields(self):
        result = sg_demo()
        for finding in result:
            assert "resource_id" in finding
            assert "severity" in finding
            assert "cis_benchmark" in finding

    def test_severity_is_valid(self):
        result = sg_demo()
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for finding in result:
            assert finding["severity"] in valid_severities

    def test_scan_type_is_security_group(self):
        result = sg_demo()
        for finding in result:
            assert finding["scan_type"] == "security_group"


class TestIAMScanner:
    def test_returns_list(self):
        result = check_iam_keys()
        assert isinstance(result, list)

    def test_findings_have_required_fields(self):
        result = iam_demo()
        for finding in result:
            assert "resource_id" in finding
            assert "severity" in finding
            assert "cis_benchmark" in finding

    def test_root_user_is_critical(self):
        result = iam_demo()
        root_findings = [f for f in result if "root" in f["resource_id"]]
        for finding in root_findings:
            assert finding["severity"] == "CRITICAL"

    def test_scan_type_is_iam(self):
        result = iam_demo()
        for finding in result:
            assert finding["scan_type"] == "iam"


class TestEncryptionScanner:
    def test_returns_list(self):
        result = check_encryption()
        assert isinstance(result, list)

    def test_findings_have_required_fields(self):
        result = enc_demo()
        for finding in result:
            assert "resource_id" in finding
            assert "severity" in finding
            assert "cis_benchmark" in finding

    def test_severity_is_valid(self):
        result = enc_demo()
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for finding in result:
            assert finding["severity"] in valid_severities

    def test_scan_type_is_encryption(self):
        result = enc_demo()
        for finding in result:
            assert finding["scan_type"] == "encryption"