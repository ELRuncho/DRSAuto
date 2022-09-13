from re import T
import time
import boto3
from botocore.exceptions import ClientError
import random



sess = boto3.Session(profile_name='default')
iamclient = sess.client('iam')
ec2_client= sess.client('ec2')
ec2 = sess.resource('ec2')
drs= sess.client('drs')

#creates DRS necesary users
def drsusers():

    try:
        DRSAgentUser = iamclient.create_user(UserName='DRSAgentUser',)
        print("DRSAgentUser creado")
    except ClientError as error:
        if error.response['Error']['Code']=='EntityAlreadyExist':
            print('El usuario DRSAgentUser ya existe')
            #return 'el usuario ya existe'
            pass
        else:
            print('Error inesperado al crear el usuario', error)
            #return 'no se pudo crear el usuario', error
            pass

    try:
        failback = iamclient.create_user(UserName='drsfailback',)
        print("drsfailback creado")
    except ClientError as error:
        if error.response['Error']['Code']=='EntityAlreadyExist':
            print('El usuario drsfailback ya existe')
            #return 'el usuario ya existe'
            pass
        else:
            print('Error inesperado al crear el usuario', error)
            #return 'no se pudo crear el usuario', error
            pass

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
            f.write('Aqui encontraras los pasos para configurar el agente de replicacion de DRS y otros recursos que necesites configurar en premisas')
            f.write('\n*--------------------------------------------------------------------------------------------------------------------------------*')
            f.write('\n*--------------------------------------------------------------------------------------------------------------------------------*')
            f.write('\nEl comando en linux para descargar el cliente es: wget -O ./aws-replication-installer-init.py https://aws-elastic-disaster-recovery-' + sess.region_name + '.s3.amazonaws.com/latest/linux/aws-replication-installer-init.py')
            f.write('\nEn Windows se puede descargar el agende de esta url: https://aws-elastic-disaster-recovery-' + sess.region_name + '.s3.amazonaws.com/latest/windows/AwsReplicationWindowsInstaller.exe')
            f.write('\n*--------------------------------------------------------------------------------------------------------------------------------*')
            f.write('\n*----------------------------Estas son las credenciales para que el agente de replicacion se conecte con AWS--------------------------------------------------------------*')
            f.write('\nDRSAgentUser access keys: '+ DRSAgentKeys['AccessKey']['AccessKeyId'])
            f.write('\nDRSAgentUser secret keys: '+ DRSAgentKeys['AccessKey']['SecretAccessKey'])
            f.write('\nFailback user access keys: '+ failbackKeys['AccessKey']['AccessKeyId'])
            f.write('\nFailback user secret keys: '+ failbackKeys['AccessKey']['SecretAccessKey'])
            f.write('\n*--------------------------------------------------------------------------------------------------------------------------------*')
            f.write('\n*--------------------------------------------------------------------------------------------------------------------------------*')
            f.write('\nPara instalar el agente de DRS en LINUX, una vez descargado, debes correr el siguiente comando: ')
            f.write('\nsudo python aws-replcation-installer-init.py')
            f.write('\nPara instalar el agente de DRS en WINDOWS, una vez descargado, ejecuta el archivo : ')
            f.write('\nAwsReplicationWindowsInstaller.exe')
            f.write('\nSigue los prompts y usa las llaves de el DRSAgentUser que aparecen mas arriba')
    except FileNotFoundError:
        print('Error')

    users={
            'DRSAgentAccessKey':DRSAgentKeys['AccessKey']['AccessKeyId'],
            'DRSAgentSecret':DRSAgentKeys['AccessKey']['SecretAccessKey'],
            'FailbackKey':failbackKeys['AccessKey']['AccessKeyId'],
            'FailbackSecret':failbackKeys['AccessKey']['SecretAccessKey']
          }
    return users


def check_input_value(prompt,proper_values):
    """
        Checks for valid input
    """
    while True:
        value=input(prompt)
        if value not in proper_values:
            print("Opcion invalida")
        else:
            break

    return value


def describe_vpc(tag_value):
    """
        Provides info on a VPC
    """
    try:
        response = ec2_client.describe_vpcs(
                        Filters=[
                            {
                                'Name':'tag:Name',
                                'Values': [tag_value]
                            },
                        ],
                        #MaxResults = max_items
                    )
    except ClientError as error:
        print("Error al describir la vpc: ", error)
    else:
        return response

def find_staging_subnet(vpcid):
    """
        Looks for a public subnet for staging environmet
    """
    try:
        subnets=ec2_client.describe_subnets(
            Filters=[{
                'Name': 'vpc-id',
                'Values':[vpcid]
            }]
        )
        subnet_ids = [sn['SubnetId'] for sn in subnets['Subnets']]
        publicsubs=[]
        privatesubs=[]
        for item in subnet_ids:
            routetable=ec2_client.describe_route_tables(
                Filters=[{
                    'Name':'association.subnet-id',
                    'Values':[item]
                }]
            )
            routes=routetable['RouteTables'][0]['Routes']
            unitresults=[]
            
            for tables in routes:
                key='GatewayId'
                if key in tables:
                    mode=tables['GatewayId']
                    if 'igw' in mode:
                        unitresults.append('public')
                    else:
                        unitresults.append('private')
            
            if 'public' in unitresults:
                publicsubs.append(item)
            else:
                privatesubs.append(item)

        response={'PublicSN':publicsubs,'PrivateSN':privatesubs}

    except ClientError as error:
        print("Error al describir la subred: ",error)
    else:
        return response

#def find_private_staging_subnet(vpcid):
#    """
#        Looks for a private subnet for staging environmet
#    """

#   try:

#    except:
#    else:

def create_security_group(description,groupname,vpc_id):
    """
        Creates a security Group
    """
    try:
        response=ec2_client.create_security_group(
                                                    Description=description,
                                                    GroupName=groupname,
                                                    VpcId=vpc_id,
                                                    TagSpecifications=[
                                                        {
                                                            'ResourceType':'security-group',
                                                            'Tags':[
                                                                {
                                                                    'Key':'Name',
                                                                    'Value': groupname
                                                                },
                                                                {
                                                                    'Key':'Creator',
                                                                    'Value': 'DRSAuto'
                                                                }
                                                            ]
                                                        }
                                                    ]
                                                )
    except ClientError as error:
        print('Error al crear el security group', error)
    else:
        return response

def add_ingress_rule(security_group_id,port,protocol,ipRange):
    """
        Creates a SG ingres rule 
    """
    try:
        response=ec2_client.authorize_security_group_ingress(
                                                                GroupId=security_group_id,
                                                                CidrIp=ipRange,
                                                                FromPort=port,
                                                                ToPort=port,
                                                                IpProtocol=protocol
                                                            )
    except ClientError as error:
        print('Error al crear la regla de ingreso', error)
    else:
        return response
    

def add_egress_rule(security_group_id,port,protocol,ipRange):
    """
        Creates a SG ingres rule 
        CidrIp=ipRange,
                                                                FromPort=port,
                                                                ToPort=port,
                                                                IpProtocol=protocol
    """
    try:
        response=ec2_client.authorize_security_group_egress(
                                                            GroupId=security_group_id,
                                                            IpPermissions=[{
                                                                'FromPort':port,
                                                                'ToPort':port,
                                                                'IpProtocol':protocol,
                                                                'IpRanges':[{
                                                                    'CidrIp':ipRange
                                                                }]
                                                            }]
                                                        )
    except ClientError as error:
        print('Error al crear la regla de ingreso', error)
    else:
        return response

def molith_infra(vpc,port,protocol,trafic_origin):
    monolith_sec_group=create_security_group('SG para un monolito publico','drsautomonolith',vpc)
    add_ingress_rule(monolith_sec_group['GroupId'],port,protocol,trafic_origin)

    #egressrule
    return monolith_sec_group['GroupId']


def front_back_infra(vpc):
    pass

def three_tier_infra(vpc):
    pass

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
        keys=drsusers()
        time.sleep(1)
        print("\nPermisos basicos creados")
        print("\nRecuerda que para desplegar tu DR te recomendamos tener una VPC con subredes publicas y privadas")

        vpc_option = check_input_value("Para el DR quieres usar una vpc especifica o quieres usar la vpc default del script?(ESPECIFICA/DEFAULT): ",('ESPECIFICA','DEFAULT'))

        if vpc_option == "DEFAULT":
            selectedvpc=describe_vpc('NABPVPC')
        elif vpc_option=="ESPECIFICA":
            tag_value=input("Cual es el nombre de la VPC que quieres usar")
            selectedvpc=describe_vpc(tag_value)
        
        public_or_private_connection=check_input_value("Deseas que la coneccion entre tu ambiente y el DR sea por internet o privada mediante VPN? (PUBLIC_IP/PRIVATE_IP): ",('PUBLIC_IP','PRIVATE_IP'))
        if public_or_private_connection=='PRIVATE_IP':
            public_static_ip=input("Cual es la ip publica de tu ambiente para establecer la coneccion VPN?(X.X.X.X): ")
        else:
            print("Se usaran internet publicas para realizar la replicacion.")
        time.sleep(1)
        print("\nComo se ve la arquitectura a la que quieres crearle un DR?\n")
        time.sleep(1)
        print("""
            1)   __________________
                |DMZ               |
                |   ____________   |
                |  |            |  |
                |  | Web Server |  |
                |  | App Server |  |
                |  |  Database  |  |
                |  |____________|  |
                |__________________|
            """)
        time.sleep(1)
        print("""
           2)
             __________________    __________________
            |DMZ               |  |Sebred Privada    |
            |   ____________   |  |   ____________   |    
            |  |            |  |  |  |            |  |
            |  |            |  |  |  | App Server |  |
            |  | Web Server |<======>|            |  |       
            |  |            |  |  |  | Database   |  |
            |  |____________|  |  |  |____________|  |
            |__________________|  |__________________|
        """)
        time.sleep(1)
        print("""
            3)
             __________________    __________________    _________________
            |DMZ               |  |Sebred Privada    |  |Subred Privada 2 |
            |   ____________   |  |   ____________   |  |   ___________   | 
            |  |            |  |  |  |            |  |  |  |           |  |
            |  |            |  |  |  |            |  |  |  |           |  |
            |  | Web Server |<======>| App Server |<======>|  Database |  |
            |  |            |  |  |  |            |  |  |  |           |  | 
            |  |____________|  |  |  |____________|  |  |  |___________|  |
            |__________________|  |__________________|  |_________________|
        """)
        time.sleep(1)
        appstyle= int(check_input_value("Selecciona el tipo que mas se te acomoda (1, 2 o 3): ",('1','2','3')))

        if appstyle==1:
            vpcid=selectedvpc['Vpcs'][0]['VpcId']
            trafic_port=int(input("Cual es el puerto de ingreso de la app: "))
            trafic_protocol=input("Cual es el protocol ip (tcp, udp o icmp): ")
            trafic_origin=input("Cual es el CIDR que deben tener accesso al servidor (X.X.X.X/X, donde 0.0.0.0/0 da acceso a todo origen): ")
            monolithSG=molith_infra(vpcid,trafic_port,trafic_protocol,trafic_origin)  

            if public_or_private_connection == 'PUBLIC_IP':
                subnets=find_staging_subnet(vpcid)
                staging_subnet=subnets['PublicSN'][0]
                create_public=True
            else:
                subnets=find_staging_subnet(vpcid)
                staging_subnet=subnets['PrivateSN'][0]
                create_public=False

            print("\nAhora crearemos el replication settings template")
            "aws drs create-replication-configuration-template --associate-default-security-group --bandwidth-throttling 500  --create-public-ip --data-plane-routing PUBLIC_IP --default-large-staging-disk-type GP2 --ebs-encryption DEFAULT --pit-policy enabled=true,interval=7,retentionDuration=7,ruleID=549816584,units=DAY --replication-server-instance-type t3.small --replication-servers-security-groups-ids sg-05755909db7d7024b  --staging-area-subnet-id subnet-0407a4de5b9ac2b22 --no-use-dedicated-replication-server --staging-area-tags Creator=DRSAuto,Project=DRSAuto"
            
            replicationServersSG=create_security_group('Security group with the required permissions for AWS Elastic Disaster Recovery Replication Servers','AWS Elastic Disaster Recovery default Replication Server Security Group',vpcid)
            replicationSGID=replicationServersSG['GroupId']
            add_ingress_rule(replicationSGID,1500,'tcp','0.0.0.0/0')
            add_egress_rule(replicationSGID,53,'udp','0.0.0.0/0')
            add_egress_rule(replicationSGID,443,'tcp','0.0.0.0/0')
            
            try:
                drs.create_replication_configuration_template(
                    associateDefaultSecurityGroup=False,
                    bandwidthThrottling=500,
                    createPublicIP=create_public,
                    dataPlaneRouting=public_or_private_connection,
                    defaultLargeStagingDiskType='GP3',
                    ebsEncryption='DEFAULT',
                    pitPolicy=[
                        {
                            'enabled':True,
                            'interval':10,
                            'retentionDuration':60,
                            'ruleID':1,
                            'units': 'MINUTE'
                        },
                        {
                            'enabled':True,
                            'interval':1,
                            'retentionDuration':24,
                            'ruleID':2,
                            'units': 'HOUR'
                        },
                        {
                            'enabled':True,
                            'interval':1,
                            'retentionDuration':7,
                            'ruleID':3,
                            'units': 'DAY'
                        }
                    ],
                    replicationServerInstanceType='t3.small',
                    replicationServersSecurityGroupsIDs=[
                        replicationSGID,
                    ],
                    stagingAreaSubnetId=staging_subnet,
                    stagingAreaTags={
                        'Cretor': 'DRSAuto'
                    },
                    useDedicatedReplicationServer=False
                )
            except ClientError as error:
                print('\nError al crear replication template: ',error)
            else:
                print('\nReplication template creado exitosamente')
            
            print('\nEl comando en linux para descargar el cliente es: wget -O ./aws-replication-installer-init.py https://aws-elastic-disaster-recovery-' + sess.region_name + '.s3.amazonaws.com/latest/linux/aws-replication-')
            print('\nEn Windows se puede descargar el agende de esta url: https://aws-elastic-disaster-recovery-' + sess.region_name + '.s3.amazonaws.com/latest/windows/AwsReplicationWindowsInstaller.exe')
            print('\nEs hora de installar el agente el servidores fuente, ingresa los siguientes datos en los prompts:')
            print('\nRegion: us-east-1')
            print('\nAccess key: '+ keys['DRSAgentAccessKey'])
            print('\nSecret key: '+ keys['DRSAgentSecret'])
            print('\nSi quieres replicar todos los discos solo debes presionar Enter, de lo contario debes definir los discos que quieres replicar')
            time.sleep(2)
            print('\nUna vez se complete la instalacion veras el servidor aparecer en source servers en la consola web (https://us-east-1.console.aws.amazon.com/drs/home?region=us-east-1#/sourceServers)')
            time.sleep(1)
            print('\nDejanos saber cuando completes la instalacion y aparesca el servidor')
            time.sleep(1)
            input('\nPresiona Enter cuando estes listo')

            source_server_id=input('\nProporcionanos el id del servidor: ')
            drs.update_launch_configuration(
                sourceServerID=source_server_id,
                targetInstanceTypeRightSizingMethod='BASIC'
            )

            instance_launch_config=drs.get_launch_configuration(sourceServerID=source_server_id)

            ec2_client.create_launch_template_version(
                LaunchTemplateId=instance_launch_config['ec2LaunchTemplateID'],
                LaunchTemplateData={
                    'NetworkInterfaces':[{
                        'AssociatePublicIpAddress': True,
                        'SubnetId':subnets['PublicSN'][1],
                        'Groups': [monolithSG]
                    }],
                }

            )
            print('launch template creado')

            ec2_client.modify_launch_template(
                DefaultVersion='2',
                LaunchTemplateId=instance_launch_config['ec2LaunchTemplateID'],
            )

            print('nueva version default')


        elif appstyle==2:
            front_back_infra()
        elif appstyle==3:
            three_tier_infra()
        time.sleep(1)
    else:
        print("deacuerdo, que tengas un feliz dia")
