<!--#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
-->

## Como instalar DRSAuto

### Prerequisitos

1. Python3 o superior y pip [Python](https://www.python.org/downloads/)
2. AWS CLI [aws-cli](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
    - Al instalar la linea de comandos,usando el comando `aws configure`, usa las llaves obtenidas del usuario admin creado anteriormente. 
        ```
            $ aws configure
            AWS Access Key ID: <Access key del usario>
            AWS Secret Access Key: <Access key del usario>
            Default region name: us-east-1 <us-east-1 es la region por defecto>
        ```
**Importante:**
    En Windows, si python o el AWS cli, una vez instalados no se encuentran desde el command prompt se deben agregar a la variable de ambiente PATH.
    Para encontrar el folder que contiene el awscli o python puede usar el comando `where`:

        
        C:\> where /R c:\ <paquete aws o python/py>

### No tienes un equipo Linux o tu computador tiene controles que te impiden instalar? 
En este caso puedes hacer uso de *AWS CLOUDSHELL* para poder tener un ambiente de consola sin tener que desplegar recursos adicionales.

Para usar CloudShell solo debes buscar el servicio en la consola:
![](./images/cloudshellSearch.png)

Una vez estes en CloudShell puedes configurar aws cli que ya viene instalado, asi como python

![](./images/cloudshell.png)

### Instalacion

1. Descarga nabp desde github ya sea descargando el zip o clonando el repositorio

    `$ git clone https://github.com/ELRuncho/DRSAuto.git`

2. Ingresa al folder:

    `$ cd DRSAuto`

3. Instala nabp usando pip:

    `$ python3 drsauto.py`
