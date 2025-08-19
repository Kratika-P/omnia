# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
"""This module contains functions for updating node objects."""
import subprocess
import sys

db_path = sys.argv[3]
oim_admin_ip = sys.argv[4]
sys.path.insert(0, db_path)
import omniadb_connection

node_obj_nm = []
GROUPS_STATIC = "all,bmc_static"
GROUPS_DYNAMIC = "all,bmc_dynamic"
CHAIN_SETUP = "runcmd=bmcsetup"
provision_os_image_x86_64 = sys.argv[1]
provision_os_image_aarch64 = sys.argv[2]
CHAIN_OS_X86_64 = f"osimage={provision_os_image_x86_64}"
CHAIN_OS_AARCH64 = f"osimage={provision_os_image_aarch64}"
DISCOVERY_MECHANISM = "mtms"


def get_node_obj():
    """
	Get a list of node objects present in Omnia Infrastrcuture Management (OIM) node

	Returns:
		A list of node object names
	"""

    command = "/opt/xcat/bin/lsdef"
    node_objs = subprocess.run(command.split(), capture_output=True,check=False)
    temp = str(node_objs.stdout).split('\n')
    for i in range(0, len(temp) - 1):
        node_obj_nm.append(temp[i].split(' ')[0])

    update_node_obj_nm()


def update_node_obj_nm():
    """
	Updates the node objects in the cluster based on the discovery mechanism.

	Parameters:
		- DISCOVERY_MECHANISM (str): The discovery mechanism used to discover nodes.
		- oim_admin_ip (str): The IP address of the OIM admin interface.
		- CHAIN_OS_X86_64 (str): The chain os image for x86_64 architecture.
		- CHAIN_OS_AARCH64 (str): The chain os image for aarch64 architecture.
		- db_path (str): The path to the database.
		- provision_os_image_x86_64 (str): The provision os image for x86_64 architecture.
		- provision_os_image_aarch64 (str): The provision os image for aarch64 architecture.

	Returns:
		None
	"""

    # Establish a connection with omniadb
    conn = omniadb_connection.create_connection()
    cursor = conn.cursor()
    sql = """
        SELECT service_tag
        FROM cluster.nodeinfo
        WHERE DISCOVERY_MECHANISM = %s
        AND (status IS NULL OR status != 'booted')
        """
    cursor.execute(sql, (DISCOVERY_MECHANISM,))
    serial_output = cursor.fetchall()
    for i, _ in enumerate(serial_output):
        if serial_output[i][0] is not None:
            serial_output[i] = str(serial_output[i][0]).lower()
    for i, _ in enumerate(serial_output):
        print(serial_output[i])
        if serial_output[i][0] is not None:
            serial_output[i] = serial_output[i].upper()
            params = (serial_output[i],)
            sql = """SELECT node, admin_ip, bmc_ip, bmc_mode, functional_group, cluster_name, group_name, architecture
                     FROM cluster.nodeinfo
                     WHERE service_tag = %s"""
            cursor.execute(sql, params)
            node_name, admin_ip, bmc_ip, mode, role, cluster_name, group_name, architecture = cursor.fetchone()

            if mode is None:
                print("No device is found!")
            if mode == "static":
                chain_os = f"osimage={CHAIN_OS_X86_64 if architecture == 'x86_64' else CHAIN_OS_AARCH64}"
                command = ["/opt/xcat/bin/chdef", node_name, f"ip={admin_ip}",
                           f"groups={GROUPS_STATIC},{role},{cluster_name},{group_name}",
                           f"chain={chain_os}", f"xcatmaster={oim_admin_ip}"]
                subprocess.run(command, check=False)
            if mode == "dynamic":
                command = ["/opt/xcat/bin/chdef", node_name,
                           f"ip={admin_ip}", f"groups={GROUPS_DYNAMIC}",
                           f"chain={CHAIN_SETUP},{CHAIN_OS_X86_64}",
                           f"bmc={bmc_ip}", f"xcatmaster={oim_admin_ip}"]
                subprocess.run(command,check=False)

    cursor.close()
    conn.close()


get_node_obj()
