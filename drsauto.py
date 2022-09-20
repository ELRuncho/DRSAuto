import time
from typing import Type
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
            f.write('\nsudo python aws-replication-installer-init.py')
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

def create_route(destination_cidr_block,gateway_id, route_table_id):
    """
        Creates a route in a route table
    """
    try:
        response = ec2_client.create_route(
            DestinationCidrBlock=destination_cidr_block,
            GatewayId=gateway_id,
            RouteTableId=route_table_id
        )
    except ClientError as error:
        print('Error al crear la ruta: ',error)
        raise
    else:
        return response

def find_route_tables(vpc_id):
    """
        Describes all route tables in a vpc
    """

    try:
        paginator = ec2_client.get_paginator('describe_route_tables')

        response_iterator = paginator.paginate(
                                Filters=[{
                                    'Name':'vpc-id',
                                    'Values': [vpc_id]
                                }]
                            )
        
        full_result= response_iterator.build_full_result()

        route_tables_list = []

        for page in full_result['RouteTables']:
            route_tables_list.append(page['RouteTableId'])

    except ClientError as error:
        print('Error al listar las tablas: ', error)
    else:
        return route_tables_list

def create_security_group(description,groupname,vpc_id):
    """
        Creates a security Group
    """
    serial=0
    SGs=ec2_client.describe_security_groups(Filters=[{'Name':'vpc-id','Values':[vpc_id]}])
    SGNames=[groups for groups in SGs['SecurityGroups'] if groupname in groups['GroupName']]

    while SGNames:
        serial+=1
        groupname=groupname+str(serial)
        SGNames=[groups for groups in SGs['SecurityGroups'] if groupname in groups['GroupName']]

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

def add_ingress_rule(**kwargs):#security_group_id,port,protocol,ipRange
    """
        Creates a SG ingres rule 
    """

    main_security_group_id=kwargs.get('main_security_group_id',None)
    ipRange=kwargs.get('ipRange',None)
    port=kwargs.get('port',None)
    protocol=kwargs.get('protocol',None)
    source_security_group_id=kwargs.get('source_security_group_id',None)

    if source_security_group_id:
        try:
            response=ec2_client.authorize_security_group_ingress(
                                                                    GroupId=main_security_group_id,
                                                                    IpPermissions=[{
                                                                                    'FromPort':port,
                                                                                    'ToPort':port,
                                                                                    'IpProtocol':protocol,
                                                                                    'UserIdGroupPairs':[
                                                                                        {
                                                                                            'GroupId':source_security_group_id
                                                                                        }
                                                                                    ]
                                                                                }]
                                                                )
        except ClientError as error:
            print('Error al crear la regla de ingreso', error)
        else:
            return response
    else:
        try:
            response=ec2_client.authorize_security_group_ingress(
                                                                    GroupId=main_security_group_id,
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
    monolith_sec_group=create_security_group('SG para un monolito','drsautomonolith',vpc)
    add_ingress_rule(main_source_security_group_id=monolith_sec_group['GroupId'],port=port,protocol=protocol,ipRange=trafic_origin)

    #egressrule
    return monolith_sec_group['GroupId']


def front_back_infra(vpcid):
    trafic_port_server1 = int(input("\nCual es el puerto de ingreso del servidor1: "))
    trafic_protocol_server1 = input("\nCual es el protocol ip del servidor2 (tcp, udp o icmp): ")
    trafic_origin_server1 = input("\nCual es el CIDR que deben tener accesso al servidor1 (X.X.X.X/X, donde 0.0.0.0/0 da acceso a todo origen): ")
    server2toserver1port = input("\nCual es el puerto con el que el servidor2 se comunica con el servidor1: ")
    server2toserver1protocol=input("\nCual es el protocolo con el que el servidor2 se comunica con el servidor1:")

    trafic_port_server2 = int(input("\nCual es el puerto de ingreso del servidor2: "))
    trafic_protocol_server2 = input("\nCual es el protocol ip del servidor2 (tcp, udp o icmp): ")
    trafic_origin_server2 = input("\nCual es el CIDR que deben tener accesso al servidor2 (X.X.X.X/X, donde 0.0.0.0/0 da acceso a todo origen): ")
    server1toserver2port = input("\nCual es el puerto con el que el servidor1 se comunica con el servidor2: ")
    server1toserver2protocol=input("\nCual es el protocolo con el que el servidor1 se comunica con el servidor2:")

    server1_sec_group = create_security_group('SG para server1','drsserver1',vpcid)
    add_ingress_rule(main_security_group_id=server1_sec_group['GroupId'],port=trafic_port_server1,protocol=trafic_protocol_server1,ipRange=trafic_origin_server1)

    server2_sec_group = create_security_group('SG para server2','drsserver2',vpcid)
    add_ingress_rule(main_security_group_id=server2_sec_group['GroupId'],port=trafic_port_server2,protocol=trafic_protocol_server2,ipRange=trafic_origin_server2)

    add_ingress_rule(main_security_group_id=server1_sec_group['GroupId'],port=server2toserver1port,protocol=server2toserver1protocol,source_security_group_id=server2_sec_group['GroupId'])
    add_ingress_rule(main_security_group_id=server2_sec_group['GroupId'],port=server1toserver2port,protocol=server1toserver2protocol,source_security_group_id=server1_sec_group['GroupId'])
    
    usecase_sg=[server1_sec_group['GroupId'],server2_sec_group['GroupId']]
    return usecase_sg

def three_tier_infra(vpcid):
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
            bgpasn=int(input("Cual es el ASN de BGP de tu dispositivo de red en premisas?(default 65000): "))
        else:
            print("Se usaran internet publicas para realizar la replicacion.")
        time.sleep(1)
        print("\nComo se ve la arquitectura a la que quieres crearle un DR?\n")
        time.sleep(1)
        print("""
            1)   __________________
                |DMZ/subred privada|
                |   ____________   |
                |  |            |  |
                |  |            |  |
                |  |  Monolito  |  |
                |  |            |  |
                |  |____________|  |
                |__________________|
            """)
        time.sleep(1)
        print("""
           2)
             __________________    __________________
            |DMZ/Subred privada|  |Sebred Privada    |
            |   ____________   |  |   ____________   |    
            |  |            |  |  |  |            |  |
            |  |            |  |  |  |            |  |
            |  |  Server1   |<======>|  Server2   |  |       
            |  |            |  |  |  |            |  |
            |  |____________|  |  |  |____________|  |
            |__________________|  |__________________|
        """)
        time.sleep(1)
        print("""
            3)
             __________________    __________________    _________________
            |DMZ/Subred privada|  |Sebred Privada    |  |Subred Privada 2 |
            |   ____________   |  |   ____________   |  |   ___________   | 
            |  |            |  |  |  |            |  |  |  |           |  |
            |  |            |  |  |  |            |  |  |  |           |  |
            |  |  Server1   |<======>|  Server2   |<======>|  Server3  |  |
            |  |            |  |  |  |            |  |  |  |           |  | 
            |  |____________|  |  |  |____________|  |  |  |___________|  |
            |__________________|  |__________________|  |_________________|
        """)
        time.sleep(1)
        appstyle= int(check_input_value("Selecciona el tipo que mas se te acomoda (1, 2 o 3): ",('1','2','3')))

        if appstyle==1:
            vpcid=selectedvpc['Vpcs'][0]['VpcId']
            trafic_port=int(input("\nCual es el puerto de ingreso de la app: "))
            trafic_protocol=input("\nCual es el protocol ip (tcp, udp o icmp): ")
            trafic_origin=input("\nCual es el CIDR que deben tener accesso al servidor (X.X.X.X/X, donde 0.0.0.0/0 da acceso a todo origen): ")
            monolithSG=molith_infra(vpcid,trafic_port,trafic_protocol,trafic_origin)  

            if public_or_private_connection == 'PUBLIC_IP':
                subnets=find_staging_subnet(vpcid)
                staging_subnet=subnets['PublicSN'][0]
                create_public=True
            else:
                subnets=find_staging_subnet(vpcid)
                staging_subnet=subnets['PublicSN'][0]
                create_public=False
                customergw = ec2_client.create_customer_gateway(BgpAsn=bgpasn,Type='ipsec.1',DeviceName='DRSAutoCGW',IpAddress=public_static_ip)
                vgw = ec2_client.create_vpn_gateway(Type='ipsec.1')
                ec2_client.attach_vpn_gateway(VpcId=vpcid,VpnGatewayId=vgw['VpnGateway']['VpnGatewayId'])
                cgw_cidr=input('Ingresa el CIDR de tu red en premisas(X.X.X.X/X): ')
                vpn_connection=ec2_client.create_vpn_connection(CustomerGatewayId=customergw['CustomerGateway']['CustomerGatewayId'],Type='ipsec.1',VpnGatewayId=vgw['VpnGateway']['VpnGatewayId'],Options={'StaticRoutesOnly':True,'LocalIpv4NetworkCidr':cgw_cidr,'RemoteIpv4NetworkCidr':selectedvpc['Vpcs'][0]['CidrBlock']})
                ec2_client.create_vpn_connection_route(DestinationCidrBlock=cgw_cidr,VpnConnectionId=vpn_connection['VpnConnection']['VpnConnectionId'])
                ec2_client.create_vpn_connection_route(DestinationCidrBlock=selectedvpc['Vpcs'][0]['CidrBlock'],VpnConnectionId=vpn_connection['VpnConnection']['VpnConnectionId'])
                routetables=find_route_tables(vpcid)

                for table in routetables:
                    ec2_client.enable_vgw_route_propagation(
                        GatewayId=vgw['VpnGateway']['VpnGatewayId'],
                        RouteTableId=table
                    )

            print("\nAhora crearemos el replication settings template")
            
            replicationServersSG=create_security_group('Security group with the required permissions for AWS Elastic Disaster Recovery Replication Servers','AWS Elastic Disaster Recovery default Replication Server Security Group',vpcid)
            replicationSGID=replicationServersSG['GroupId']
            add_ingress_rule(main_security_group_id=replicationSGID,port=1500,protocol='tcp',ipRange='0.0.0.0/0')
            add_egress_rule(main_security_group_id=replicationSGID,port=53,protocol='udp',ipRange='0.0.0.0/0')
            add_egress_rule(main_security_group_id=replicationSGID,port=443,protocol='tcp',ipRange='0.0.0.0/0')
            
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

            tipored=check_input_value('Tu servidor necesita estar en una dmz o en una subred privada (dmz/privada): ',('dmz','privada'))
            destsubnet=''
            if tipored=='dmz':
                destsubnet=subnets['PublicSN'][1]
            else:
                destsubnet=subnets['PrivateSN'][0]

            ec2_client.create_launch_template_version(
                LaunchTemplateId=instance_launch_config['ec2LaunchTemplateID'],
                LaunchTemplateData={
                    'NetworkInterfaces':[{
                        'AssociatePublicIpAddress': True,
                        'DeviceIndex':0,
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
            vpcid=selectedvpc['Vpcs'][0]['VpcId']
            infra=front_back_infra(vpcid)
            if public_or_private_connection == 'PUBLIC_IP':
                subnets=find_staging_subnet(vpcid)
                staging_subnet=subnets['PublicSN'][0]
                create_public=True
            else:
                subnets=find_staging_subnet(vpcid)
                staging_subnet=subnets['PublicSN'][0]
                create_public=False
                customergw = ec2_client.create_customer_gateway(BgpAsn=bgpasn,Type='ipsec.1',DeviceName='DRSAutoCGW',IpAddress=public_static_ip)
                vgw = ec2_client.create_vpn_gateway(Type='ipsec.1')
                ec2_client.attach_vpn_gateway(VpcId=vpcid,VpnGatewayId=vgw['VpnGateway']['VpnGatewayId'])
                cgw_cidr=input('Ingresa el CIDR de tu red en premisas(X.X.X.X/X): ')
                vpn_connection=ec2_client.create_vpn_connection(CustomerGatewayId=customergw['CustomerGateway']['CustomerGatewayId'],Type='ipsec.1',VpnGatewayId=vgw['VpnGateway']['VpnGatewayId'],Options={'StaticRoutesOnly':True,'LocalIpv4NetworkCidr':cgw_cidr,'RemoteIpv4NetworkCidr':selectedvpc['Vpcs'][0]['CidrBlock']})
                ec2_client.create_vpn_connection_route(DestinationCidrBlock=cgw_cidr,VpnConnectionId=vpn_connection['VpnConnection']['VpnConnectionId'])
                ec2_client.create_vpn_connection_route(DestinationCidrBlock=selectedvpc['Vpcs'][0]['CidrBlock'],VpnConnectionId=vpn_connection['VpnConnection']['VpnConnectionId'])
                routetables=find_route_tables(vpcid)

                for table in routetables:
                    ec2_client.enable_vgw_route_propagation(
                        GatewayId=vgw['VpnGateway']['VpnGatewayId'],
                        RouteTableId=table
                    )

            print("\nAhora crearemos el replication settings template")
            
            replicationServersSG=create_security_group('Security group with the required permissions for AWS Elastic Disaster Recovery Replication Servers','AWS Elastic Disaster Recovery default Replication Server Security Group',vpcid)
            replicationSGID=replicationServersSG['GroupId']
            add_ingress_rule(main_security_group_id=replicationSGID,port=1500,protocol='tcp',ipRange='0.0.0.0/0')
            add_egress_rule(main_security_group_id=replicationSGID,port=53,protocol='udp',ipRange='0.0.0.0/0')
            add_egress_rule(main_security_group_id=replicationSGID,port=443,protocol='tcp',ipRange='0.0.0.0/0')

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

            source_server1_id=input('\nProporcionanos el id del servidor1: ')
            drs.update_launch_configuration(
                sourceServerID=source_server1_id,
                targetInstanceTypeRightSizingMethod='BASIC'
            )

            source_server2_id=input('\nProporcionanos el id del servidor2: ')
            drs.update_launch_configuration(
                sourceServerID=source_server2_id,
                targetInstanceTypeRightSizingMethod='BASIC'
            )
            instance_launch_config1=drs.get_launch_configuration(sourceServerID=source_server1_id)
            instance_launch_config2=drs.get_launch_configuration(sourceServerID=source_server1_id)

            tipored=check_input_value('Tu servidor1 necesita estar en una dmz o en una subred privada (dmz/privada): ',('dmz','privada'))
            destsubnet=''

            if tipored=='dmz':
                destsubnet=subnets['PublicSN'][1]
                ec2_client.create_launch_template_version(
                    LaunchTemplateId=instance_launch_config1['ec2LaunchTemplateID'],
                    LaunchTemplateData={
                        'NetworkInterfaces':[{
                            'AssociatePublicIpAddress': True,
                            'DeviceIndex':0,
                            'SubnetId':destsubnet,
                            'Groups': [infra[0]]
                        }],
                    }
                )
                print('launch template creado')
            else:
                destsubnet=subnets['PrivateSN'][0]
                ec2_client.create_launch_template_version(
                    LaunchTemplateId=instance_launch_config1['ec2LaunchTemplateID'],
                    LaunchTemplateData={
                        'NetworkInterfaces':[{
                            'AssociatePublicIpAddress': True,
                            'DeviceIndex':0,
                            'SubnetId':destsubnet,
                            'Groups': [infra[0]]
                        }],
                    }
                )
                print('launch template creado')

            
            ec2_client.create_launch_template_version(
                    LaunchTemplateId=instance_launch_config2['ec2LaunchTemplateID'],
                    LaunchTemplateData={
                        'NetworkInterfaces':[{
                            'AssociatePublicIpAddress': True,
                            'DeviceIndex':0,
                            'SubnetId':subnets['PrivateSN'][1],
                            'Groups': [infra[1]]
                        }],
                    }
                )
            print('launch template creado')

            ec2_client.modify_launch_template(
                DefaultVersion='2',
                LaunchTemplateId=instance_launch_config1['ec2LaunchTemplateID'],
            )

            print('nueva version default launch template servidor1')

            ec2_client.modify_launch_template(
                DefaultVersion='2',
                LaunchTemplateId=instance_launch_config2['ec2LaunchTemplateID'],
            )
            print('nueva version default launch template servidor2')
        elif appstyle==3:
            three_tier_infra()
        time.sleep(1)
    else:
        print("deacuerdo, que tengas un feliz dia")
