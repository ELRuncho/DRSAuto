#// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#// SPDX-License-Identifier: Apache-2.0

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