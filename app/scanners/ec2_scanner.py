from app.models.finding import Finding
from botocore.exceptions import ClientError


class EC2Scanner:

    def __init__(self, awsclient):
        self.awsclient = awsclient


    def scan(self):
        findings = []
        security_groups = self.list_security_groups()

        for sg in security_groups:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "Unnamed Security Group")

            if not self.check_ssh_open(sg):
                finding = Finding(
                    resource_type="EC2 Security Group",
                    resource_name=sg_name,
                    check="SSH OPEN TO THE WORLD",
                    severity="High",
                    recommendation="Restrict SSH access to specific IP addresses or ranges to enhance security."
                )
                findings.append(finding)

            if not self.check_rdp_open(sg):
                finding = Finding(
                    resource_type="EC2 Security Group",
                    resource_name=sg_name,
                    check="RDP OPEN TO THE WORLD",
                    severity="High",
                    recommendation="Restrict RDP access to specific IP addresses or ranges to enhance security."
                )
                findings.append(finding)

            if not self.check_all_ports_open(sg):
                finding = Finding(
                    resource_type="EC2 Security Group",
                    resource_name=sg_name,
                    check="ALL PORTS OPEN TO THE WORLD",
                    severity="High",
                    recommendation="Restrict access to specific ports and IP addresses or ranges to enhance security."
                )
                findings.append(finding)

            if not self.check_dangerous_ports_open(sg):
                finding = Finding(
                    resource_type="EC2 Security Group",
                    resource_name=sg_name,
                    check="DANGEROUS PORTS OPEN TO THE WORLD",
                    severity="High",
                    recommendation="Restrict access to dangerous ports (21, 23, 3306, 5432, 6379, 27017) and IP addresses or ranges to enhance security."
                )
                findings.append(finding)

            if not self.check_ssh_ipv6_open(sg):
                finding = Finding(
                    resource_type="EC2 Security Group",
                    resource_name=sg_name,
                    check="SSH OPEN TO THE WORLD (IPv6)",
                    severity="High",
                    recommendation="Restrict SSH access over IPv6 to specific IP addresses or ranges to enhance security."
                )
                findings.append(finding)

        return findings

    def list_security_groups(self):
      try:
        response = self.awsclient.ec2.describe_security_groups()
        return response.get("SecurityGroups", [])

      except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code", "Unknown")
        raise RuntimeError(
            f"Failed to list EC2 security groups. AWS error: {error_code}"
        ) from error
    def is_port_open_to_world(self, security_group, port, ip_version=4):
      for permission in security_group.get("IpPermissions", []):
        protocol = permission.get("IpProtocol")
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        if protocol == "-1":
            port_matches = True
        elif (
            protocol == "tcp"
            and from_port is not None
            and to_port is not None
        ):
            port_matches = from_port <= port <= to_port
        else:
            port_matches = False

        if not port_matches:
            continue

        if ip_version == 4:
            for ip_range in permission.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    return True

        elif ip_version == 6:
            for ipv6_range in permission.get("Ipv6Ranges", []):
                if ipv6_range.get("CidrIpv6") == "::/0":
                    return True

      return False
    def check_ssh_open(self, security_group):
        return not self.is_port_open_to_world(security_group, 22)
    def check_rdp_open(self, security_group):
        return not self.is_port_open_to_world(security_group, 3389)
    def check_all_ports_open(self, security_group):
        for permission in security_group.get("IpPermissions", []):

            if (
                permission.get("IpProtocol") == "-1"
                and permission.get("FromPort") is None
                and permission.get("ToPort") is None
            ):
                for ip_range in permission.get("IpRanges", []):

                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        return False

        return True
    def check_dangerous_ports_open(self, security_group):
      dangerous_ports = [21, 23, 3306, 5432, 6379, 27017]

      for permission in security_group.get("IpPermissions", []):
        protocol = permission.get("IpProtocol")
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        # All protocols are allowed
        if protocol == "-1":
            port_is_dangerous = True

        # Check whether the TCP range includes a dangerous port
        elif (
            protocol == "tcp"
            and from_port is not None
            and to_port is not None
        ):
            port_is_dangerous = any(
                from_port <= port <= to_port
                for port in dangerous_ports
            )

        else:
            port_is_dangerous = False

        if not port_is_dangerous:
            continue

        # Check unrestricted IPv4 access
        for ip_range in permission.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                return False

        # Check unrestricted IPv6 access
        for ipv6_range in permission.get("Ipv6Ranges", []):
            if ipv6_range.get("CidrIpv6") == "::/0":
                return False

      return True

    def check_ssh_ipv6_open(self, security_group):
      return not self.is_port_open_to_world(
        security_group, 22, ip_version=6
      )
    