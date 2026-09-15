from app.scanners.ec2_scanner import EC2Scanner

class FakeAWSClient:
    def __init__(self):
        self.ec2 = FakeEC2Client()


class FakeEC2Client:

    def describe_instances(self):
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-1234567890abcdef0",
                            "State": {"Name": "running"},
                            "Tags": [
                                {"Key": "Name", "Value": "TestInstance"}
                            ],
                        }
                    ]
                }
            ]
        }

    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-001",
                    "GroupName": "test-sg-22-open",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpProtocol": "tcp",
                            "IpRanges": [
                                {"CidrIp": "0.0.0.0/0"}
                            ],
                        }
                    ],
                },
                {
                    "GroupId": "sg-002",
                    "GroupName": "test-sg-22-restricted",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpProtocol": "tcp",
                            "IpRanges": [
                                {"CidrIp": "192.168.1.0/24"}
                            ],
                        }
                    ],
                },
                {
                    "GroupId": "sg-003",
                    "GroupName": "test-sg-rdp-open",
                    "IpPermissions": [
                        {
                            "FromPort": 3389,
                            "ToPort": 3389,
                            "IpProtocol": "tcp",
                            "IpRanges": [
                                {"CidrIp": "0.0.0.0/0"}
                            ],
                        }
                    ],
                },
                {
                    "GroupId": "sg-004",
                    "GroupName": "test-sg-all-open",
                    "IpPermissions": [
                        {
                            "IpProtocol": "-1",
                            "IpRanges": [
                                {"CidrIp": "0.0.0.0/0"}
                            ]
                        }
                    ]
                },
                {
                    "GroupId": "sg-005",
                    "GroupName": "test-sg-dangerous-ports-open",
                    "IpPermissions": [
                        {
                            "FromPort": 3306,
                            "ToPort": 3306,
                            "IpProtocol": "tcp",
                            "IpRanges": [
                                {"CidrIp": "0.0.0.0/0"}
                            ]
                        }
                    ]
                },
                {
                    "GroupId": "sg-006",
                    "GroupName": "test-sg-ssh-ipv6-open",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpProtocol": "tcp",
                            "Ipv6Ranges": [
                                {"CidrIpv6": "::/0"}
                            ],
                        }
                    ]
                }
            ]
        }

def test_fake_ec2_client():
    fake_ec2_client = FakeEC2Client()

    response = fake_ec2_client.describe_security_groups()

    security_groups = response["SecurityGroups"]

    assert len(security_groups) == 6
    assert security_groups[0]["GroupId"] == "sg-001"
    assert security_groups[1]["GroupId"] == "sg-002"
    assert security_groups[2]["GroupId"] == "sg-003"
    assert security_groups[3]["GroupId"] == "sg-004"
    assert security_groups[4]["GroupId"] == "sg-005"
    assert security_groups[5]["GroupId"] == "sg-006"

def test_check_ssh_open():
    scanner = EC2Scanner(None)

    security_groups = FakeEC2Client().describe_security_groups()["SecurityGroups"]

    assert scanner.check_ssh_open(security_groups[0]) == False
    assert scanner.check_ssh_open(security_groups[1]) == True
    assert scanner.check_ssh_open(security_groups[2]) == True

def test_check_rdp_open():
    scanner = EC2Scanner(None)

    security_groups = FakeEC2Client().describe_security_groups()["SecurityGroups"]

    assert scanner.check_rdp_open(security_groups[0]) == True
    assert scanner.check_rdp_open(security_groups[1]) == True
    assert scanner.check_rdp_open(security_groups[2]) == False
    assert scanner.check_rdp_open(security_groups[3]) == True

def test_check_all_ports_open():
    scanner = EC2Scanner(None)

    security_groups = FakeEC2Client().describe_security_groups()["SecurityGroups"]

    assert scanner.check_all_ports_open(security_groups[0]) == True
    assert scanner.check_all_ports_open(security_groups[1]) == True
    assert scanner.check_all_ports_open(security_groups[2]) == True
    assert scanner.check_all_ports_open(security_groups[3]) == False

def test_check_dangerous_ports_open():
    scanner = EC2Scanner(None)

    security_groups = FakeEC2Client().describe_security_groups()["SecurityGroups"]

    assert scanner.check_dangerous_ports_open(security_groups[0]) == True
    assert scanner.check_dangerous_ports_open(security_groups[1]) == True
    assert scanner.check_dangerous_ports_open(security_groups[2]) == True
    assert scanner.check_dangerous_ports_open(security_groups[3]) == True
    assert scanner.check_dangerous_ports_open(security_groups[4]) == False
def test_check_ssh_ipv6_open():
    scanner = EC2Scanner(None)

    security_groups = FakeEC2Client().describe_security_groups()["SecurityGroups"]

    assert scanner.check_ssh_ipv6_open(security_groups[5]) == False

def test_ec2_scanner():
    awsclient = FakeAWSClient()
    scanner = EC2Scanner(awsclient)

    findings = scanner.scan()

    assert len(findings) == 5
    checks = [finding.check for finding in findings]
    assert "SSH OPEN TO THE WORLD" in checks
    assert "RDP OPEN TO THE WORLD" in checks
    assert "ALL PORTS OPEN TO THE WORLD" in checks
    assert "DANGEROUS PORTS OPEN TO THE WORLD" in checks
    assert "SSH OPEN TO THE WORLD (IPv6)" in checks


