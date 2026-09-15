from app.models.finding import Finding


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
        response = self.awsclient.ec2.describe_security_groups()
        return response["SecurityGroups"]

    def check_ssh_open(self, security_group):
        for permission in security_group.get("IpPermissions", []):

            if (
                permission.get("IpProtocol") == "tcp"
                and permission.get("FromPort") == 22
                and permission.get("ToPort") == 22
            ):
                for ip_range in permission.get("IpRanges", []):

                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        return False

        return True
    def check_rdp_open(self, security_group):
        for permission in security_group.get("IpPermissions", []):

            if (
                permission.get("IpProtocol") == "tcp"
                and permission.get("FromPort") == 3389
                and permission.get("ToPort") == 3389
            ):
                for ip_range in permission.get("IpRanges", []):

                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        return False

        return True
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
        dangerous_ports = [21, 23,3306, 5432,6379, 27017]
        for permission in security_group.get("IpPermissions", []):
            if (
                permission.get("IpProtocol") == "tcp"
                and permission.get("FromPort") in dangerous_ports
                and permission.get("ToPort") in dangerous_ports
            ):
                for ip_range in permission.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        return False

        return True
    def check_ssh_ipv6_open(self, security_group):
        for permission in security_group.get("IpPermissions", []):
            if (
                permission.get("IpProtocol") == "tcp"
                and permission.get("FromPort") == 22
                and permission.get("ToPort") == 22
            ):
                for ipv6_range in permission.get("Ipv6Ranges", []):
                    if ipv6_range.get("CidrIpv6") == "::/0":
                        return False

        return True
    