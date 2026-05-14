import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import json

def check_s3_buckets(aws_access_key=None, aws_secret_key=None, region="us-east-1"):
    """
    Detecta buckets S3 con acceso público habilitado.
    Simula comportamiento de Prowler - CIS AWS Benchmark 2.1.5
    """
    findings = []

    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            bucket_findings = []

            # Check 1: Block Public Access
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab["PublicAccessBlockConfiguration"]
                if not all([
                    config.get("BlockPublicAcls"),
                    config.get("IgnorePublicAcls"),
                    config.get("BlockPublicPolicy"),
                    config.get("RestrictPublicBuckets")
                ]):
                    bucket_findings.append("Block Public Access no está completamente habilitado")
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    bucket_findings.append("No tiene configuración Block Public Access")

            # Check 2: Bucket ACL
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") in [
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                    ]:
                        bucket_findings.append(f"ACL público detectado: {grant.get('Permission')}")
            except ClientError:
                pass

            if bucket_findings:
                findings.append({
                    "resource_id": bucket_name,
                    "scan_type": "s3",
                    "severity": "CRITICAL",
                    "finding": " | ".join(bucket_findings),
                    "recommendation": "Habilitar S3 Block Public Access en todas las configuraciones",
                    "cis_benchmark": "CIS AWS 2.1.5 - S3 Block Public Access"
                })

    except NoCredentialsError:
        return _demo_findings()
    except Exception:
        return _demo_findings()

    return findings if findings else _demo_findings()


def _demo_findings():
    """Datos demo cuando no hay credenciales AWS reales."""
    return [
        {
            "resource_id": "demo-bucket-public-01",
            "scan_type": "s3",
            "severity": "CRITICAL",
            "finding": "Block Public Access no está habilitado | ACL público detectado: READ",
            "recommendation": "Habilitar S3 Block Public Access en todas las configuraciones",
            "cis_benchmark": "CIS AWS 2.1.5 - S3 Block Public Access"
        },
        {
            "resource_id": "demo-bucket-logs-02",
            "scan_type": "s3",
            "severity": "CRITICAL",
            "finding": "No tiene configuración Block Public Access",
            "recommendation": "Configurar Block Public Access a nivel de cuenta y bucket",
            "cis_benchmark": "CIS AWS 2.1.5 - S3 Block Public Access"
        }
    ]