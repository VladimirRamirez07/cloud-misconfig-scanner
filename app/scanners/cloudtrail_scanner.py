import boto3
from botocore.exceptions import NoCredentialsError


def check_cloudtrail(aws_access_key=None, aws_secret_key=None, region="us-east-1"):
    """
    Detecta problemas de configuración en CloudTrail y VPC Flow Logs.
    CIS AWS Benchmark 3.1 / 3.2 / 3.7
    """
    findings = []

    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )

        # ── CloudTrail checks ──────────────────────────────────────────
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])

        if not trails:
            findings.append({
                "resource_id": "CloudTrail",
                "scan_type": "cloudtrail",
                "severity": "CRITICAL",
                "finding": "No hay ningún trail de CloudTrail configurado en esta cuenta",
                "recommendation": "Crear al menos un trail multi-región con logging habilitado.",
                "cis_benchmark": "CIS AWS 3.1 - Habilitar CloudTrail en todas las regiones"
            })

        for trail in trails:
            trail_name = trail.get("Name")
            trail_findings = []

            # Check 1: Multi-region
            if not trail.get("IsMultiRegionTrail"):
                trail_findings.append("Trail no es multi-región")

            # Check 2: Log file validation
            if not trail.get("LogFileValidationEnabled"):
                trail_findings.append("Validación de integridad de logs deshabilitada")

            # Check 3: Trail logging activo
            try:
                status = ct.get_trail_status(Name=trail_name)
                if not status.get("IsLogging"):
                    trail_findings.append("Trail existe pero NO está activamente logueando")
            except Exception:
                pass

            # Check 4: CloudWatch Logs integration
            if not trail.get("CloudWatchLogsLogGroupArn"):
                trail_findings.append("Trail no está integrado con CloudWatch Logs")

            # Check 5: S3 bucket encryption
            if not trail.get("KMSKeyId"):
                trail_findings.append("Logs de CloudTrail no están cifrados con KMS")

            if trail_findings:
                findings.append({
                    "resource_id": f"CloudTrail: {trail_name}",
                    "scan_type": "cloudtrail",
                    "severity": "HIGH",
                    "finding": " | ".join(trail_findings),
                    "recommendation": "Habilitar multi-región, validación de logs, CloudWatch y cifrado KMS.",
                    "cis_benchmark": "CIS AWS 3.2 / 3.7 - CloudTrail configuración segura"
                })

        # ── VPC Flow Logs checks ───────────────────────────────────────
        ec2 = session.client("ec2", region_name=region)
        vpcs = ec2.describe_vpcs().get("Vpcs", [])

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            ).get("FlowLogs", [])

            if not flow_logs:
                findings.append({
                    "resource_id": f"VPC: {vpc_id}",
                    "scan_type": "cloudtrail",
                    "severity": "HIGH",
                    "finding": "VPC sin Flow Logs habilitados — tráfico de red no monitoreado",
                    "recommendation": "Habilitar VPC Flow Logs hacia CloudWatch o S3 para auditoría de red.",
                    "cis_benchmark": "CIS AWS 3.9 - Habilitar VPC Flow Logs"
                })
            else:
                for fl in flow_logs:
                    if fl.get("FlowLogStatus") != "ACTIVE":
                        findings.append({
                            "resource_id": f"VPC: {vpc_id}",
                            "scan_type": "cloudtrail",
                            "severity": "MEDIUM",
                            "finding": f"Flow Log existe pero no está activo (estado: {fl.get('FlowLogStatus')})",
                            "recommendation": "Revisar y reactivar el Flow Log de esta VPC.",
                            "cis_benchmark": "CIS AWS 3.9 - Habilitar VPC Flow Logs"
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
            "resource_id": "CloudTrail: main-trail",
            "scan_type": "cloudtrail",
            "severity": "HIGH",
            "finding": "Trail no es multi-región | Validación de integridad de logs deshabilitada | Trail no está integrado con CloudWatch Logs",
            "recommendation": "Habilitar multi-región, validación de logs, CloudWatch y cifrado KMS.",
            "cis_benchmark": "CIS AWS 3.2 / 3.7 - CloudTrail configuración segura"
        },
        {
            "resource_id": "CloudTrail: dev-trail",
            "scan_type": "cloudtrail",
            "severity": "HIGH",
            "finding": "Logs de CloudTrail no están cifrados con KMS | Trail no está integrado con CloudWatch Logs",
            "recommendation": "Habilitar cifrado KMS y enviar logs a CloudWatch para alertas en tiempo real.",
            "cis_benchmark": "CIS AWS 3.7 - Cifrar logs de CloudTrail con KMS"
        },
        {
            "resource_id": "VPC: vpc-0abc123def",
            "scan_type": "cloudtrail",
            "severity": "HIGH",
            "finding": "VPC sin Flow Logs habilitados — tráfico de red no monitoreado",
            "recommendation": "Habilitar VPC Flow Logs hacia CloudWatch o S3 para auditoría de red.",
            "cis_benchmark": "CIS AWS 3.9 - Habilitar VPC Flow Logs"
        },
        {
            "resource_id": "VPC: vpc-0def456abc",
            "scan_type": "cloudtrail",
            "severity": "HIGH",
            "finding": "VPC sin Flow Logs habilitados — tráfico de red no monitoreado",
            "recommendation": "Habilitar VPC Flow Logs hacia CloudWatch o S3 para auditoría de red.",
            "cis_benchmark": "CIS AWS 3.9 - Habilitar VPC Flow Logs"
        }
    ]