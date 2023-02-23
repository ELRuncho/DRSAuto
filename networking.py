#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#// SPDX-License-Identifier: Apache-2.0

import checks
import boto3
from botocore.exceptions import ClientError

sess = boto3.Session(profile_name='default')
ec2_client= sess.client('ec2')
ec2 = sess.resource('ec2')

#call using selectedvpc['Vpcs'][0]['CidrBlock']
def create_vpn(vpc_id,bgpasn,public_static_ip,vpc_cidr):
    #Create vpn customer gateway
    customergw = ec2_client.create_customer_gateway(BgpAsn=bgpasn,Type='ipsec.1',DeviceName='DRSAutoCGW',IpAddress=public_static_ip)
    customergw_id = customergw['CustomerGateway']['CustomerGatewayId']

    #Create vpn gateway
    vgw = ec2_client.create_vpn_gateway(Type='ipsec.1')
    vgw_id = vgw['VpnGateway']['VpnGatewayId']

    #Attaching vgw to vpn
    ec2_client.attach_vpn_gateway(VpcId=vpc_id,VpnGatewayId=vgw_id)

    #Creating vpn Connection
    cgw_cidr = input('Ingresa el CIDR de tu red en premisas(X.X.X.X/X): ')
    vpn_connection = ec2_client.create_vpn_connection(CustomerGatewayId=customergw_id,Type='ipsec.1',VpnGatewayId=vgw_id,Options={'StaticRoutesOnly':True,'LocalIpv4NetworkCidr':cgw_cidr,'RemoteIpv4NetworkCidr':vpc_cidr})
    
    #Adding VPN to routes
    vpn_connection_id = vpn_connection['VpnConnection']['VpnConnectionId']
    ec2_client.create_vpn_connection_route(DestinationCidrBlock=cgw_cidr,VpnConnectionId=vpn_connection_id)
    ec2_client.create_vpn_connection_route(DestinationCidrBlock=vpc_cidr,VpnConnectionId=vpn_connection_id)
    routetables= find_route_tables(vpc_id)

    for table in routetables:
                    ec2_client.enable_vgw_route_propagation(
                        GatewayId=vgw_id,
                        RouteTableId=table
                    )
    
    #Creating cgw configuration file
    deviceid=''
    vpndevicetypes=ec2_client.get_vpn_connection_device_types()
    vendors_disponibles=[]

    for item in vpndevicetypes['VpnConnectionDeviceTypes']:
        v=item.get('Vendor')
        vendors_disponibles.append(v)

    vendors_list=tuple(vendors_disponibles)
    vendor=checks.check_input_value('Cual es el fabricante de tu dispositivo vpn en premisas (cisco,fortinet...etc)',vendors_list)

    for item in vpndevicetypes['VpnConnectionDeviceTypes']:
        vname=item.get('Vendor')
        if vname==vendor:
            deviceid=item.get('VpnConnectionDeviceTypeId')
            break

    vpnconfig=ec2_client.get_vpn_connection_device_sample_configuration(VpnConnectionId=vpn_connection_id,VpnConnectionDeviceTypeId=deviceid)
    try:
        with open('configvpn.txt','w') as f:
            f.write(vpnconfig['VpnConnectionDeviceSampleConfiguration'])
    except FileNotFoundError:
        print('Error')
                
    print('creado el archivo de configuracion configvpn.txt con la info de configuracion de la vpn')
    pass

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


def create_vpc(vpc_name):
    # Create a VPC
    vpc = ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
    vpc_id = vpc['Vpc']['VpcId']

    # Add a name tag to the VPC
    ec2_client.create_tags(Resources=[vpc_id], Tags=[{'Key': 'Name', 'Value': vpc_name}])

    # Create public and private subnets
    azs = ec2_client.describe_availability_zones()['AvailabilityZones']
    public_subnets = []
    private_subnets = []
    for i in range(3):
        # Create a public subnet
        publicsubnet = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=f'10.0.{i}.0/24', AvailabilityZone=azs[i]['ZoneName'])
        public_subnet_id = publicsubnet['Subnet']['SubnetId']
        public_subnets.append(public_subnet_id)

        # Create a private subnet
        privatesubnet = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=f'10.0.{i+3}.0/24', AvailabilityZone=azs[i]['ZoneName'])
        private_subnet_id = privatesubnet['Subnet']['SubnetId']
        private_subnets.append(private_subnet_id)

    # Create an Internet Gateway
    igw = ec2_client.create_internet_gateway()
    internet_gateway_id = igw['InternetGateway']['InternetGatewayId']
    ec2_client.attach_internet_gateway(InternetGatewayId=internet_gateway_id, VpcId=vpc_id)

    # Create a NAT Gateway
    ngw = ec2_client.create_nat_gateway(SubnetId=public_subnets[0], AllocationId=ec2_client.allocate_address(Domain='vpc')['AllocationId'])
    nat_gateway_id = ngw['NatGateway']['NatGatewayId']
    natwaiter = ec2_client.get_waiter('nat_gateway_available')
    natwaiter.wait(
        NatgatewayIds=[nat_gateway_id,],
        WaiterConfig={
            'Delay':30,
            'MaxAttempts':30
        }
    )

    # Create a route table for the public subnets
    public_route_table = ec2_client.create_route_table(VpcId=vpc_id)
    public_route_table_id = public_route_table['RouteTable']['RouteTableId']
    for subnet_id in public_subnets:
        ec2_client.associate_route_table(RouteTableId=public_route_table_id, SubnetId=subnet_id)
    ec2_client.create_route(RouteTableId=public_route_table_id, DestinationCidrBlock='0.0.0.0/0', GatewayId=internet_gateway_id)

    # Create a route table for the private subnets
    private_route_table = ec2_client.create_route_table(VpcId=vpc_id)
    private_route_table_id = private_route_table['RouteTable']['RouteTableId']
    for subnet_id in private_subnets:
        ec2_client.associate_route_table(RouteTableId=private_route_table_id,SubnetId=subnet_id)
    ec2_client.create_route(RouteTableId=private_route_table_id, DestinationCiderBlock='0.0.0.0/0', GatewayId=nat_gateway_id)