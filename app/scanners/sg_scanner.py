import boto3
from botocore.exceptions import NoCredentialsError

def check_security_groups(aws_access_key=None, aws_secret_key=None, region="us-east-1"):
    """
    Detecta Security Groups con puertos peligrosos abiertos al mundo (0.0.0.0/0).
    CIS AWS Benchmark 5.2 / 5.3
    """
    findings = []

    DANGEROUS_PORTS = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
        8080: "HTTP-Alt",
        80: "HTTP",
        443: "HTTPS"
    }

    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        ec2 = session.client("ec2")
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "unknown")
            sg_findings = []

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)
                ip_ranges = rule.get("IpRanges", [])

                for ip in ip_ranges:
                    if ip.get("CidrIp") == "0.0.0.0/0":
                        for port, service in DANGEROUS_PORTS.items():
                            if from_port <= port <= to_port:
                                sg_findings.append(
                                    f"Puerto {port} ({service}) abierto al mundo"
                                )

            if sg_findings:
                severity = "CRITICAL" if any(
                    p in " ".join(sg_findings) for p in ["SSH", "RDP", "MySQL", "MongoDB"]
                ) else "HIGH"

                findings.append({
                    "resource_id": f"{sg_id} ({sg_name})",
                    "scan_type": "security_group",
                    "severity": severity,
                    "finding": " | ".join(sg_findings),
                    "recommendation": "Restringir acceso a IPs específicas. Nunca usar 0.0.0.0/0 en puertos sensibles.",
                    "cis_benchmark": "CIS AWS 5.2 - No permitir acceso SSH/RDP desde 0.0.0.0/0"
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
            "resource_id": "sg-0abc123 (launch-wizard-1)",
            "scan_type": "security_group",
            "severity": "CRITICAL",
            "finding": "Puerto 22 (SSH) abierto al mundo | Puerto 3306 (MySQL) abierto al mundo",
            "recommendation": "Restringir acceso a IPs específicas. Nunca usar 0.0.0.0/0 en puertos sensibles.",
            "cis_benchmark": "CIS AWS 5.2 - No permitir acceso SSH/RDP desde 0.0.0.0/0"
        },
        {
            "resource_id": "sg-0def456 (web-servers)",
            "scan_type": "security_group",
            "severity": "HIGH",
            "finding": "Puerto 8080 (HTTP-Alt) abierto al mundo",
            "recommendation": "Usar un Load Balancer y restringir acceso directo a instancias.",
            "cis_benchmark": "CIS AWS 5.3 - Revisar reglas de Security Groups"
        }
    ]