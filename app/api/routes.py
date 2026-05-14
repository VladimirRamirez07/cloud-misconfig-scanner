from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.database.models import ScanResult
from app.scanners.s3_scanner import check_s3_buckets
from app.scanners.sg_scanner import check_security_groups
from app.scanners.iam_scanner import check_iam_keys
from app.scanners.encryption_scanner import check_encryption
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

class ScanRequest(BaseModel):
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    region: Optional[str] = "us-east-1"

def save_findings(findings, db):
    for f in findings:
        record = ScanResult(
            scan_type=f["scan_type"],
            resource_id=f["resource_id"],
            severity=f["severity"],
            finding=f["finding"],
            recommendation=f["recommendation"],
            cis_benchmark=f["cis_benchmark"]
        )
        db.add(record)
    db.commit()

@router.post("/scan/s3")
def scan_s3(request: ScanRequest, db: Session = Depends(get_db)):
    findings = check_s3_buckets(request.aws_access_key, request.aws_secret_key, request.region)
    save_findings(findings, db)
    return {"scan_type": "s3", "total_findings": len(findings), "findings": findings}

@router.post("/scan/security-groups")
def scan_security_groups(request: ScanRequest, db: Session = Depends(get_db)):
    findings = check_security_groups(request.aws_access_key, request.aws_secret_key, request.region)
    save_findings(findings, db)
    return {"scan_type": "security_group", "total_findings": len(findings), "findings": findings}

@router.post("/scan/iam")
def scan_iam(request: ScanRequest, db: Session = Depends(get_db)):
    findings = check_iam_keys(request.aws_access_key, request.aws_secret_key, request.region)
    save_findings(findings, db)
    return {"scan_type": "iam", "total_findings": len(findings), "findings": findings}

@router.post("/scan/encryption")
def scan_encryption(request: ScanRequest, db: Session = Depends(get_db)):
    findings = check_encryption(request.aws_access_key, request.aws_secret_key, request.region)
    save_findings(findings, db)
    return {"scan_type": "encryption", "total_findings": len(findings), "findings": findings}

@router.post("/scan/all")
def scan_all(request: ScanRequest, db: Session = Depends(get_db)):
    all_findings = []
    all_findings += check_s3_buckets(request.aws_access_key, request.aws_secret_key, request.region)
    all_findings += check_security_groups(request.aws_access_key, request.aws_secret_key, request.region)
    all_findings += check_iam_keys(request.aws_access_key, request.aws_secret_key, request.region)
    all_findings += check_encryption(request.aws_access_key, request.aws_secret_key, request.region)
    save_findings(all_findings, db)

    summary = {
        "CRITICAL": len([f for f in all_findings if f["severity"] == "CRITICAL"]),
        "HIGH": len([f for f in all_findings if f["severity"] == "HIGH"]),
        "MEDIUM": len([f for f in all_findings if f["severity"] == "MEDIUM"]),
        "LOW": len([f for f in all_findings if f["severity"] == "LOW"]),
    }

    return {
        "total_findings": len(all_findings),
        "summary": summary,
        "findings": all_findings
    }

@router.get("/report")
def get_report(db: Session = Depends(get_db)):
    results = db.query(ScanResult).order_by(ScanResult.created_at.desc()).limit(100).all()
    return {
        "total": len(results),
        "results": [
            {
                "id": r.id,
                "scan_type": r.scan_type,
                "resource_id": r.resource_id,
                "severity": r.severity,
                "finding": r.finding,
                "recommendation": r.recommendation,
                "cis_benchmark": r.cis_benchmark,
                "created_at": str(r.created_at)
            } for r in results
        ]
    }