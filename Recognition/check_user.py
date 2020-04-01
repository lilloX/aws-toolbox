#!/usr/bin/env python

import argparse
import configparser
import json
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from pygments import highlight, lexers, formatters
from sty import fg

# You can change the default region here or specify the -r option on the CLi
DefaultAWSRegion = 'eu-west-1'
VerboseMode = False
StealthMode = False

parser = argparse.ArgumentParser(description="Check the AWS credentials to understand the permissions associated")
# Optional arguments
parser.add_argument("-v", help="increase output verbosity, show JSON documents", action="store_true")
parser.add_argument("-c", help="stealth mode, run only the canary token check", action="store_true")
group = parser.add_argument_group('Profile mode')
group2 = parser.add_mutually_exclusive_group()
group2.add_argument("-l", help="list available profiles", action="store_true")
group2.add_argument("-p", dest="profile", help="check a user from the available profiles")

group = parser.add_argument_group('Credentials mode')
group.add_argument("-u", dest="AccessKeyId", help="Access Key Id")
group.add_argument("-s", dest="SecretAccessKeyId", help="Secret Access Key Id")
group.add_argument("-t", dest="SecurityToken", help="Session token")
args = parser.parse_args()

VerboseMode = args.v
StealthMode = args.c


def print_json(text):
    if VerboseMode:
        formatted_json = json.dumps(text, indent=4)
        colorful_json = highlight(formatted_json, lexers.JsonLexer(), formatters.TerminalFormatter())
        print(colorful_json)
    else:
        print_text('Enable verbose mode (-v) to see the policy document', '')


def print_text(text, type):
    if type == "error":
        fgColor = fg(255, 0, 0)
        prep = '[!] '
    elif type == "action":
        fgColor = fg(255, 194, 0)
        prep = '[*] '
    elif type == "ok":
        fgColor = fg(54, 205, 20)
        prep = '[+] '
    else:
        fgColor = fg(255, 255, 255)
        prep = ''
    print(fgColor + prep + text + fg.rs)


class AWSCred(object):
    """
    The AWScred class holds all the information about the account to be checked:
    """
    CurrentRegion: str = DefaultAWSRegion
    AccessKeyId: str = ''
    SecretAccessKeyId: str = ''
    SecurityToken: str = ''
    isCanary: bool = False
    AccountId: str = ''
    UserId: str = ''
    UserName: str = ''
    InlineUserPolicies: list = []
    AttachedUserPolicies: list = []
    InlineGroupPolicies: list = []
    AttachedGroupPolicies: list = []
    Groups: list = []
    STSClient: boto3.client("sts") = ''
    IAMClient: boto3.client("iam") = ''

    # Functions

    # Check if it is a canary token. Invoking the Simple DB API  will not raise an event in CloudTrail, so no alarms
    # will be triggered if it is a canary
    def check_canary(self):
        try:
            boto3.client('sdb', aws_access_key_id=self.AccessKeyId, aws_secret_access_key=self.SecretAccessKeyId,
                         aws_session_token=self.SecurityToken, region_name=self.CurrentRegion).list_domains()
        except ClientError as error:
            if error.response['Error']['Code'] == 'AuthorizationFailure':
                message = error.response['Error']['Message']
                if 'canarytokens.com' in message or 'canarytokens.org' in message:
                    self.isCanary = True
                elif 'arn:aws:iam::' in message and '/SpaceCrab/' in message:
                    self.isCanary = True
                elif 'arn:aws:iam::534261010715:' in message or 'arn:aws:sts::534261010715:' in message:
                    self.isCanary = True
                else:
                    self.isCanary = False
            else:
                pass
        return self.isCanary

    def get_account_info(self):
        try:
            tmp = self.STSClient.get_caller_identity()
            self.AccountId = tmp["Account"]
            self.UserId = tmp["UserId"]
            self.UserName = tmp["Arn"][tmp["Arn"].find('/') + 1:]
        except ClientError as error:
            print_text(error.response["Error"]["Message"], 'error')
            exit(1)

    def get_groups(self):
        '''
        Get the group list for the given user

        '''
        try:
            self.Groups = self.IAMClient.list_groups_for_user(UserName=self.UserName)["Groups"]
            for i in range(0, len(self.Groups)):
                print_text('Group: {}'.format(self.Groups[i]["GroupName"]), '')
        except ClientError as error:
            print_text(error.response["Error"]["Message"], 'error')

    def get_user_permissions(self):
        print_text('Inline User Policies and policy documents', 'action')
        try:
            # Try to list the policy belonging the user. Fails if the permission iam:ListUserPolicies is missing
            self.InlineUserPolicies = self.IAMClient.list_user_policies(UserName=self.UserName)['PolicyNames']
            print_text('Inline Policies: {}'.format(self.InlineUserPolicies), 'ok')
            for i in range(0, len(self.InlineUserPolicies)):
                print_text("Policy document for {}".format(self.InlineUserPolicies[i]), 'ok')
                try:
                    # Try to recover the document policy. Fails if the permission iam:GetUserPolicy is missing
                    policy = self.IAMClient.get_user_policy(UserName=self.UserName,
                                                            PolicyName=self.InlineUserPolicies[i])
                    print_json(policy)
                except ClientError as error:
                    print_text(error.response["Error"]["Message"], 'error')
        except ClientError as error:
            print_text(error.response["Error"]["Message"], 'error')

        print_text('Attached User Policies and policy documents', 'action')
        try:
            # Try to list the policy attached to the user. Fails if the permission iam:ListAttachedUserPolicies is missing
            self.AttachedUserPolicies = self.IAMClient.list_attached_user_policies(UserName=self.UserName)[
                'AttachedPolicies']
            print_text('Attached Policies: {}'.format(self.AttachedUserPolicies), 'ok')
            for i in range(0, len(self.AttachedUserPolicies)):
                print_text("Policy document for {}".format(self.AttachedUserPolicies[i]["PolicyName"]), 'ok')
                # Retrieve the policy information, will fail if iam:GetPolicy is missing
                policy = self.IAMClient.get_policy(PolicyArn=self.AttachedUserPolicies[i]["PolicyArn"])
                # Retrieve the policy document, will fail if iam:GetPolicyVersion is missing
                policy_version = self.IAMClient.get_policy_version(
                    PolicyArn=self.AttachedUserPolicies[i]["PolicyArn"],
                    VersionId=policy['Policy']['DefaultVersionId']
                )
                print_json(policy_version['PolicyVersion']['Document'])
        except ClientError as error:
            print_text(error.response["Error"]["Message"], 'error')
        # Try to list the group policies.

        print_text('Group(s) Policies and policy documents', 'action')
        for i in range(0, len(self.Groups)):
            group = self.Groups[i]["GroupName"]
            try:
                # Try to list the inline group policies. Fails if the permission iam:ListUserPolicies is missing
                self.InlineGroupPolicies = self.IAMClient.list_group_policies(GroupName=str(group))['PolicyNames']
                print_text('Inline Policies for the {} group: {}'.format(group, self.InlineGroupPolicies), 'ok')
                for i in range(0, len(self.InlineGroupPolicies)):
                    print_text("Policy document for {}".format(self.InlineGroupPolicies[i]), 'ok')
                    try:
                        # Try to recover the document policy. Fails if the permission iam:GetUserPolicy is missing
                        policy = self.IAMClient.get_group_policy(GroupName=group,
                                                                 PolicyName=self.InlineGroupPolicies[i])
                        print_json(policy)
                    except ClientError as error:
                        print_text(error.response["Error"]["Message"], 'error')

            except ClientError as error:
                print_text(error.response["Error"]["Message"], 'error')

                print('2')

            try:
                # Try to list the policy attached to the user. Fails if the permission iam:ListAttachedUserPolicies is missing
                self.AttachedGroupPolicies = self.IAMClient.list_attached_group_policies(GroupName=group)[
                    'AttachedPolicies']
                print_text('Attached Policies for the {} group: {}'.format(group, self.AttachedGroupPolicies), 'ok')
                for i in range(0, len(self.AttachedGroupPolicies)):
                    print_text("Policy document for {}".format(self.AttachedGroupPolicies[i]["PolicyName"]), 'ok')
                    # Retrieve the policy information, will fail if iam:GetPolicy is missing
                    policy = self.IAMClient.get_policy(PolicyArn=self.AttachedGroupPolicies[i]["PolicyArn"])
                    # Retrieve the policy document, will fail if iam:GetPolicyVersion is missing
                    policy_version = self.IAMClient.get_policy_version(
                        PolicyArn=self.AttachedGroupPolicies[i]["PolicyArn"],
                        VersionId=policy['Policy']['DefaultVersionId']
                    )
                    print_json(policy_version['PolicyVersion']['Document'])
            except ClientError as error:
                print_text(error.response["Error"]["Message"], 'error')

    def __init__(self, aws_access_key_id, aws_secret_access_key, aws_session_token, region_name):
        self.AccessKeyId = aws_access_key_id
        self.SecretAccessKeyId = aws_secret_access_key
        self.SecurityToken = aws_session_token
        self.CurrentRegion = region_name
        # Check if it is a canary, if so exit
        if self.check_canary():
            print_text('Canary token detected, quit', 'error')
            exit(1)
        else:
            print_text('Not a know canary token', 'ok')
            if not StealthMode:
                # Initialize the clients
                self.IAMClient = boto3.client('iam', aws_access_key_id=self.AccessKeyId,
                                              aws_secret_access_key=self.SecretAccessKeyId,
                                              aws_session_token=self.SecurityToken,
                                              region_name=self.CurrentRegion)
                self.STSClient = boto3.client('sts', aws_access_key_id=self.AccessKeyId,
                                              aws_secret_access_key=self.SecretAccessKeyId,
                                              aws_session_token=self.SecurityToken,
                                              region_name=self.CurrentRegion)
                self.get_account_info()
                print_text(
                    'Account ID: {} \nUser Name :{}\tUser ID: {}'.format(self.AccountId, self.UserName, self.UserId),
                    '')
                self.get_groups()

                self.get_user_permissions()
            else:
                print_text('Stealth mode enabled, end of tests', '')
                exit(0)


if __name__ == '__main__':
    if args.l:
        parser = configparser.ConfigParser()
        aws_config = str(Path.home()) + "/.aws/credentials"
        print_text("Available profiles", 'action')
        try:
            parser.read(aws_config)
            for sect in parser.sections():
                print(sect)
        except:
            print_text('Error reading the credentials file {}'.format(aws_config), 'error')
            exit(1)
        exit(0)
    if args.profile:
        print_text('Using {} profile'.format(args.profile), 'action')
        parser = configparser.ConfigParser()
        aws_config = str(Path.home()) + "/.aws/credentials"
        try:
            parser.read(aws_config)
            for sect in parser.sections():
                if sect == args.profile:
                    for k, v in parser.items(sect):
                        if k == 'aws_access_key_id':
                            AccessKeyId = v
                        elif k == 'aws_secret_access_key':
                            SecretAccessKeyId = v
                        # Check if the credential are from an assume role or from a real user
                        if k == 'aws_session_token' and 'ASIA' in AccessKeyId:
                            SecurityToken = v
                        else:
                            SecurityToken = ''
        except:
            print_text('Error reading the credentials file {}'.format(aws_config), 'error')
            exit(1)
    if (args.AccessKeyId and args.SecretAccessKeyId):
        AccessKeyId=args.AccessKeyId
        SecretAccessKeyId=args.SecretAccessKeyId
        if 'ASIA' in AccessKeyId:
            SecurityToken = args.SecurityToken
        else:
            SecurityToken = ''

    a = AWSCred(AccessKeyId, SecretAccessKeyId, SecurityToken, 'eu-west-1')
