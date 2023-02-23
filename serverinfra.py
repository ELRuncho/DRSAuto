#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#// SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.exceptions import ClientError

sess = boto3.Session(profile_name='default')
ec2_client= sess.client('ec2')
ec2 = sess.resource('ec2')

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