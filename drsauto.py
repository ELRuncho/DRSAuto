import time
import boto3
from botocore.exceptions import ClientError
import subprocess


sess = boto3.Session(profile_name='default')
iamclient = sess.client('iam')
ec2_client= sess.client('ec2')
ec2 = sess.resource('ec2')

#creates DRS necesary users
def drsusers():

    try:
        DRSAgentUser = iamclient.create_user(UserName='DRSAgentUser',)
        print("DRSAgentUser creado")
    except ClientError as error:
        if error.response['Error']['Code']=='EntityAlreadyExist':
            print('El usuario DRSAgentUser ya existe')
            #return 'el usuario ya existe'
        else:
            print('Error inesperado al crear el usuario', error)
            #return 'no se pudo crear el usuario', error

    try:
        failback = iamclient.create_user(UserName='drsfailback',)
        print("drsfailback creado")
    except ClientError as error:
        if error.response['Error']['Code']=='EntityAlreadyExist':
            print('El usuario drsfailback ya existe')
            #return 'el usuario ya existe'
        else:
            print('Error inesperado al crear el usuario', error)
            #return 'no se pudo crear el usuario', error

    iamclient.attach_user_policy(
        UserName='DRSAgentUser',
        PolicyArn='arn:aws:iam::aws:policy/AWSElasticDisasterRecoveryAgentInstallationPolicy'
    )

    iamclient.attach_user_policy(
        UserName='drsfailback',
        PolicyArn='arn:aws:iam::aws:policy/AWSElasticDisasterRecoveryFailbackInstallationPolicy'
    )


    DRSAgentKeys = iamclient.create_access_key(UserName='DRSAgentUser')
    failbackKeys = iamclient.create_access_key(UserName='drsfailback')
    try:
        with open('config.txt','w') as f:
            f.write('DRSAgentUser access keys: '+ DRSAgentKeys['AccessKey']['AccessKeyId'])
            f.write('\nDRSAgentUser secret keys: '+ DRSAgentKeys['AccessKey']['SecretAccessKey'])
            f.write('\nFailback user access keys: '+ failbackKeys['AccessKey']['AccessKeyId'])
            f.write('\nFailback user secret keys: '+ failbackKeys['AccessKey']['SecretAccessKey'])
    except FileNotFoundError:
        print('Error')

#checks for valid value on vpc input
def check_vpc_value(prompt):
    while True:
        value=input(prompt)
        if value not in ("DEFAULT","ESPECIFICA"):
            print("Opcion invalida")
        else:
            break

    return value

# provides info on a vpc
def describe_vpc(tag, tag_value, max_items=1):
    try:
        response = ec2_client.describe_vpcs(
                        Filters=[
                            {
                                'Name':f'tag:{tag}',
                                'Values': [tag_value]
                            },
                        ],
                        MaxResults = max_items
                    )
    except ClientError as error:
        print("Error al describir la vpc: ", error)
    else:
        return response

def molith_infra():
    pass

def front_back_infra():
    pass

def three_tier_infra():
    pass

print("\nAhora debes instalar los ")

if __name__ == '__main__':

    print("""
        _____  _____   _____           _    _ _______ ____  
        |  __ \|  __ \ / ____|     /\  | |  | |__   __/ __ \ 
        | |  | | |__) | (___      /  \ | |  | |  | | | |  | |
        | |  | |  _  / \___ \    / /\ \| |  | |  | | | |  | |
        | |__| | | \ \ ____) |  / ____ \ |__| |  | | | |__| |
        |_____/|_|  \_\_____/  /_/    \_\____/   |_|  \____/ 
        """)
    print('''\nBienvenido al script para automatizar Elastic Disaster Recovery.''')
    continuar = input("Estas listo para continuar (Y/N):")
    if continuar == 'Y':
        print("\n Muy bien ahora crearemos los permisos basicos")
        drsusers()
        time.sleep(2)
        print("\nPermisos basicos creados")
        print("\nRecuerda que para desplegar tu DR te recomendamos tener una VPC con subredes publicas y privadas")

        vpc_option = check_vpc_value("Para el DR quieres usar una vpc especifica o quieres usar la vpc default del script?(ESPECIFICA/DEFAULT): ")

        if vpc_option == "DEFAULT":
            describe_vpc('NAME','NABPVPC')
        elif vpc_option=="ESPECIFICA":
            tag_value=input("Cual es el nombre de la VPC que quieres usar")

        print("Como se ve la arquitectura a la que quieres crearle un DR?\n")

        print("""
            1)
                ____________    
                |            |  
                | Web Server |  
                | App Server |  
                |  Database  |  
                |____________| 
        """)
        time.sleep(2)
        print("""
            2)
                ____________          ____________       
                |            |        |            |
                |            |        | App Server |
                | Web Server |<======>|            |        
                |            |        | Database   |
                |____________|        |____________|
        """)
        time.sleep(2)
        print("""
            3)
                ____________          ____________          ___________      
                |            |        |            |        |           |
                |            |        |            |        |           |
                | Web Server |<======>| App Server |<======>|  Database |
                |            |        |            |        |           |
                |____________|        |____________|        |___________|
        """)
        time.sleep(2)

        appstyle=int(input("Selecciona el tipo que mas se te acomoda (1, 2 o 3): "))

        if appstyle==1:
            molith_infra()
        elif appstyle==2:
            front_back_infra()
        elif appstyle==3:
            three_tier_infra()

        print("\nAhora crearemos el replication settings template")
        time.sleep(1)


        # looking for NABPVPC's

        # listing NABPVPC's subnets

        # selecting staging subnet

    else:
        print("deacuerdo, que tengas un feliz dia")
