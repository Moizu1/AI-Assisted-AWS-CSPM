from sqlalchemy import false, true

from app.clients.aws_client import AWSClient


class IAMScanner:

    def __init__(self, awsclient):
        self.awsclient = awsclient

    def scan(self):
        users = self.list_users()
        for user in users:
            print (user)

    def list_users(self):

        response = self.awsclient.iam.list_users()

        return response["Users"]

    def check_mfa_enabled(self, user):
        username = user["UserName"]
        response = self.awsclient.iam.list_mfa_devices(UserName=username)
        return len(response["MFADevices"]) > 0
    


