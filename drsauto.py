import boto3
from botocore.exceptions import ClientError
import subprocess

sess = boto3.Session(profile_name='default')
iamclient = sess.client('iam')

print('''Bienvenido al script para automatizar Elastic Disaster Recovery.
         Primero creemos los permisos basicos para el despliegue
         ''')

try:
    DRSAgentUser = iamclient.create_user(UserName='DRSAgentUser',)
except ClientError as error:
    if error.response['Error']['Code']=='EntityAlreadyExist':
        print('El usuario DRSAgentUser ya existe')
        #return 'el usuario ya existe'
    else:
        print('Error inesperado al crear el usuario', error)
        #return 'no se pudo crear el usuario', error

try:
    failback = iamclient.create_user(UserName='failback',)
except ClientError as error:
    if error.response['Error']['Code']=='EntityAlreadyExist':
        print('El usuario DRSAgentUser ya existe')
        #return 'el usuario ya existe'
    else:
        print('Error inesperado al crear el usuario', error)
        #return 'no se pudo crear el usuario', error

iamclient.attach_user_policy(
    UserName='DRSAgentUser',
    PolicyArn='arn:aws:iam::aws:policy/AWSElasticDisasterRecoveryAgentInstallationPolicy'
)

iamclient.attach_user_policy(
    UserName='failback',
    PolicyArn='arn:aws:iam::aws:policy/AWSElasticDisasterRecoveryFailbackInstallationPolicy'
)


DRSAgentKeys = iamclient.create_access_key(UserName='DRSAgentUser')
failbackKeys = iamclient.create_access_key(UserName='failback')
try:
    with open('config.txt','w') as f:
        f.write('DRSAgentUser access keys: '+ DRSAgentKeys['AccessKey']['AccessKeyId'])
        f.write('DRSAgentUser secret keys: '+ DRSAgentKeys['AccessKey']['SecretAccessKey'])
        f.write('Failback user access keys: '+ failbackKeys['AccessKey']['AccessKeyId'])
        f.write('Failback user secret keys: '+ failbackKeys['AccessKey']['SecretAccessKey'])
except FileNotFoundError:
    print('Error')
