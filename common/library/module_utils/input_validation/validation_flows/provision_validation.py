# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# pylint: disable=import-error,too-many-arguments,unused-argument,too-many-locals,too-many-positional-arguments
"""
This module contains functions for validating provision configuration.
"""
import json
import os
import re
from ansible.module_utils.input_validation.common_utils import validation_utils
from ansible.module_utils.input_validation.common_utils import config
from ansible.module_utils.input_validation.common_utils import en_us_validation_msg
from ansible.module_utils.input_validation.validation_flows import common_validation
import csv
import yaml
from io import StringIO

file_names = config.files
create_error_msg = validation_utils.create_error_msg
create_file_path = validation_utils.create_file_path

def load_oim_metadata(metadata_file_path):
    with open(metadata_file_path, 'r') as file:
        metadata = yaml.safe_load(file)
    return metadata

metadata_file_path = '/opt/omnia/.data/oim_metadata.yml'
metadata = load_oim_metadata(metadata_file_path)
oim_timezone = metadata['oim_timezone']

# Expected header columns (case-insensitive)
required_headers = [
    "FUNCTIONAL_GROUP_NAME",
    "GROUP_NAME",
    "SERVICE_TAG",
    "PARENT_SERVICE_TAG",
    "HOSTNAME",
    "ADMIN_MAC",
    "ADMIN_IP",
    "BMC_MAC",
    "BMC_IP"
]

def validate_functional_groups_in_mapping_file(pxe_mapping_file_path):
    """
    Validates the PXE mapping file format.

    Args:
        pxe_mapping_file_path (str): Path to the PXE mapping file.

    Raises:
        ValueError: If the PXE mapping file format is invalid.
    """

    if not pxe_mapping_file_path or not os.path.isfile(pxe_mapping_file_path):
        raise ValueError(f"PXE mapping file not found: {pxe_mapping_file_path}")


    with open(pxe_mapping_file_path, "r", encoding="utf-8") as fh:
        raw_lines = fh.readlines()
    
    # Disallow any comment lines in the PXE mapping file
    comment_lines = [i + 1 for i, ln in enumerate(raw_lines) if ln.lstrip().startswith("#")]
    if comment_lines:
        raise ValueError(
            f"PXE mapping file must not contain comments. Comment lines found at: {', '.join(map(str, comment_lines))}"
        )

    # Remove blank lines only; after the check above there are no comment lines
    non_comment_lines = [ln for ln in raw_lines if ln.strip()]
    if not non_comment_lines:
        raise ValueError(f"PXE mapping file is empty: {pxe_mapping_file_path}")

    # Use csv.DictReader on the filtered lines
    reader = csv.DictReader(non_comment_lines)
    if not reader.fieldnames:
        raise ValueError(f"CSV header not found in PXE mapping file: {pxe_mapping_file_path}")

    # Normalize header names for case-insensitive matching
    fieldname_map = {fn.strip().upper(): fn for fn in reader.fieldnames}

    # Check for required headers
    missing = [h for h in required_headers if h not in fieldname_map]
    if missing:
        raise ValueError(
            f"PXE mapping file missing required columns: {', '.join(missing)} (found: {', '.join(reader.fieldnames)})"
        )

    # Validate functional group names present in rows
    invalid_entries = []
    fg_col = fieldname_map["FUNCTIONAL_GROUP_NAME"]
    # Accept alphanumeric and underscore/hyphen (examples use lowercase+underscores)
    fg_pattern = re.compile(r"^[A-Za-z0-9_\-]+$")

    # Iterate rows and validate FG names
    for row_idx, row in enumerate(reader, start=2):  # start=2 approximates line number of first data row
        raw_fg = row.get(fg_col, "")
        fg = raw_fg.strip() if raw_fg is not None else ""
        if not fg:
            invalid_entries.append(f"empty functional group name at CSV row {row_idx}")
            continue
        if not fg_pattern.match(fg):
            invalid_entries.append(f"invalid functional group name '{fg}' at CSV row {row_idx}")
            continue
        elif fg not in config.FUNCTIONAL_GROUP_LAYER_MAP.keys():
            invalid_entries.append(f"unrecognized functional group name '{fg}' at CSV row {row_idx}")

    if invalid_entries:
        raise ValueError("PXE mapping file functional group name validation errors: " + "; ".join(invalid_entries))

    # No exception => file considered valid for functional group names
    return None

def validate_parent_service_tag_hierarchy(pxe_mapping_file_path):
    """
    Validates the parent service tag hierarchy in the PXE mapping file.
    
    Ensures that:
    - kube_control_plane and kube_node functional groups in slurm nodes have a parent_service_tag
    - Management nodes (login, compiler, control plane) do not have a parent_service_tag
    
    Args:
        pxe_mapping_file_path (str): Path to the PXE mapping file.
    
    Raises:
        ValueError: If the parent service tag hierarchy is invalid.
    """
    if not pxe_mapping_file_path or not os.path.isfile(pxe_mapping_file_path):
        raise ValueError(f"PXE mapping file not found: {pxe_mapping_file_path}")
    
    with open(pxe_mapping_file_path, "r", encoding="utf-8") as fh:
        raw_lines = fh.readlines()
    
    non_comment_lines = [ln for ln in raw_lines if ln.strip()]
    reader = csv.DictReader(non_comment_lines)
    
    fieldname_map = {fn.strip().upper(): fn for fn in reader.fieldnames}
    fg_col = fieldname_map.get("FUNCTIONAL_GROUP_NAME")
    parent_col = fieldname_map.get("PARENT_SERVICE_TAG")
    
    if not fg_col or not parent_col:
        raise ValueError("Required columns FUNCTIONAL_GROUP_NAME or PARENT_SERVICE_TAG not found")
    
    hierarchy_errors = []

    # Read all rows so we can pre-scan for a kube cluster and still iterate below
    rows = list(reader)

    # Detect if any row contains a kube control plane or kube node FG
    kube_cluster_present = any(
        ("kube_control_plane" in (row.get(fg_col) or "").strip().lower())
        or ("kube_node" in (row.get(fg_col) or "").strip().lower())
        for row in rows
    )

    # Replace reader with an iterator over the stored rows so the loop below can consume them
    reader_iter = iter(rows)
    
    for row_idx, row in enumerate(reader_iter, start=2):
        fg = row.get(fg_col, "").strip()
        parent = row.get(parent_col, "").strip() if row.get(parent_col) else ""
        
        # Get the layer for this functional group
        layer = config.FUNCTIONAL_GROUP_LAYER_MAP.get(fg)

        if layer == "management":
            # Management nodes should NOT have a parent
            if parent:
                hierarchy_errors.append(
                    f"Management node with functional group '{fg}' at CSV row {row_idx} "
                    f"should not have parent_service_tag, but found: '{parent}'"
                )
        elif layer == "compute" and kube_cluster_present:
            # Compute nodes (slurm_node) MUST have a parent
            if not parent:
                hierarchy_errors.append(
                    f"Compute node with functional group '{fg}' at CSV row {row_idx} "
                    f"must have a parent_service_tag configured"
                )
    
    if hierarchy_errors:
        raise ValueError("PXE mapping file parent service tag hierarchy validation errors: " + "; ".join(hierarchy_errors))
    
    return None

def validate_provision_config(
    input_file_path, data, logger, module, omnia_base_dir, module_utils_base, project_name
):
    """
    Validates the provision configuration.

    Args:
        input_file_path (str): The path to the input file.
        data (dict): The data to be validated.
        logger (Logger): A logger instance.
        module (Module): A module instance.
        omnia_base_dir (str): The base directory of the Omnia configuration.
        module_utils_base (str): The base directory of the module utils.
        project_name (str): The name of the project.

    Returns:
        list: A list of errors encountered during validation.
    """
    errors = []
    software_config_file_path = create_file_path(input_file_path, file_names["software_config"])
    software_config_json = json.load(open(software_config_file_path, "r"))

    # Call validate_software_config from common_validation
    software_errors = common_validation.validate_software_config(
        software_config_file_path,
        software_config_json,
        logger,
        module,
        omnia_base_dir,
        module_utils_base,
        project_name,
    )
    errors.extend(software_errors)

    # Validate language setting
    language = data.get("language", "")
    if not language:
        errors.append(
            create_error_msg("language", input_file_path, en_us_validation_msg.LANGUAGE_EMPTY_MSG)
        )
    elif "en_US.UTF-8" not in language:
        errors.append(
            create_error_msg("language", input_file_path, en_us_validation_msg.LANGUAGE_FAIL_MSG)
        )

    timezone_file_path = os.path.join(
        module_utils_base, "input_validation", "common_utils", "timezone.txt"
    )
    
    pxe_mapping_file_path = data.get("pxe_mapping_file_path", "")
    if pxe_mapping_file_path and validation_utils.verify_path(pxe_mapping_file_path):
        try:
            validate_functional_groups_in_mapping_file(pxe_mapping_file_path)
            validate_parent_service_tag_hierarchy(pxe_mapping_file_path)
        except ValueError as e:
            errors.append(
                create_error_msg("pxe_mapping_file_path", pxe_mapping_file_path,
                str(e),
                )
            )
    else:
        errors.append(
            create_error_msg(
                "pxe_mapping_file_path",
                pxe_mapping_file_path,
                en_us_validation_msg.PXE_MAPPING_FILE_PATH_FAIL_MSG,
            )
        )

    timezone = data["timezone"]
    if not validation_utils.validate_timezone(timezone, timezone_file_path):
        errors.append(
            create_error_msg("timezone", timezone, en_us_validation_msg.TIMEZONE_FAIL_MSG)
        )

    # Detect system timezone
    input_timezone = timezone

    # Compare both timezones
    if oim_timezone != input_timezone:
        errors.append(
            create_error_msg(
                "timezone_mismatch",
                f"Provided input timezone : {input_timezone}, Detected oim timezone: {oim_timezone}",
                "Timezone mismatch detected. Please ensure both timezone matche,s refer file timezone.txt."
            )
        )

    default_lease_time = data["default_lease_time"]
    if not validation_utils.validate_default_lease_time(default_lease_time):
        errors.append(
            create_error_msg(
                "default_lease_time",
                default_lease_time,
                en_us_validation_msg.DEFAULT_LEASE_TIME_FAIL_MSG,
            )
        )
    return errors

def validate_network_spec(
    input_file_path, data, logger, module, omnia_base_dir, module_utils_base, project_name
):
    """
    Validates the network specification configuration.

    Args:
        input_file_path (str): Path to the input configuration file
        data (dict): The network specification data to validate
        logger (Logger): Logger instance for logging messages
        module (AnsibleModule): Ansible module instance
        omnia_base_dir (str): Base directory path for Omnia
        module_utils_base (str): Base path for module utilities
        project_name (str): Name of the project

    Returns:
        list: List of validation errors, empty if no errors found
    """
    errors = []

    if not data.get("Networks"):
        errors.append(
            create_error_msg("Networks", None, en_us_validation_msg.ADMIN_NETWORK_MISSING_MSG)
        )
        return errors

    for network in data["Networks"]:
        errors.extend(_validate_admin_network(network))

    return errors


def _validate_admin_network(network):
    """
    Validates the admin network configuration.

    Args:
        network (dict): Admin network configuration dictionary containing network settings

    Returns:
        list: List of validation errors for admin network, empty if no errors found

    Validates:
        - Netmask bits
        - Network gateway
        - Dynamic IP ranges
    """
    errors = []
    if "admin_network" not in network:
        return errors

    admin_net = network["admin_network"]
    primary_oim_admin_ip = admin_net.get("primary_oim_admin_ip", "")
    primary_oim_bmc_ip = admin_net.get("primary_oim_bmc_ip", "")
    dynamic_range = admin_net.get("dynamic_range", "")
    oim_nic_name = admin_net.get("oim_nic_name", "")
    netmask_bits = admin_net.get("netmask_bits", "")    

    # Validate netmask_bits
    if "netmask_bits" in admin_net:
        netmask = admin_net["netmask_bits"]
        if not validation_utils.validate_netmask_bits(netmask):
            errors.append(
                create_error_msg(
                    "admin_network.netmask_bits",
                    netmask,
                    en_us_validation_msg.NETMASK_BITS_FAIL_MSG,
                )
            )

    # Validate IP ranges
    if "dynamic_range" in admin_net:
        errors.extend(
            _validate_ip_ranges(
                admin_net["dynamic_range"], "admin_network", netmask
            )
        )

    #  Admin and BMC IP should not be the same
    errors.extend(validate_admin_bmc_ip_not_same(primary_oim_admin_ip, primary_oim_bmc_ip))

    # Both should be valid IPv4 addresses (BMC IP is optional)
    errors.extend(validate_admin_bmc_ip_valid(primary_oim_admin_ip, primary_oim_bmc_ip))

    # Neither should be in the dynamic_range
    errors.extend(validate_admin_bmc_ip_not_in_dynamic_range(primary_oim_admin_ip, primary_oim_bmc_ip, dynamic_range))

    # Ensure primary_oim_admin_ip matches actual NIC IP and netmask
    # Ensure primary_oim_admin_ip matches actual NIC IP and netmask
    if oim_nic_name and primary_oim_admin_ip and netmask_bits:
        nic_ips = validation_utils.get_interface_ips_and_netmasks(oim_nic_name)  # returns list of (ip, netmask_bits)

        # Check if any IP/netmask pair matches
        match_found = any(ip == primary_oim_admin_ip and nm == netmask_bits for ip, nm in nic_ips)

        if not match_found:
            errors.append(
                create_error_msg(
                    "primary_oim_admin_ip",
                    primary_oim_admin_ip,
                    f"{en_us_validation_msg.PRIMARY_ADMIN_IP_INTERFACE_MISMATCH_MSG}: "
                    f"The ip/netmask configured on {oim_nic_name} is {nic_ips}, "
                    f"but in network_spec it is {primary_oim_admin_ip}/{netmask_bits}."
                )
            )

    return errors

def validate_admin_bmc_ip_not_same(primary_oim_admin_ip, primary_oim_bmc_ip):
    """
    Validates that primary_oim_admin_ip and primary_oim_bmc_ip are not the same.
    """
    errors = []
    if primary_oim_admin_ip and primary_oim_bmc_ip and primary_oim_admin_ip == primary_oim_bmc_ip:
        errors.append(
            create_error_msg(
                "primary_oim_admin_ip",
                primary_oim_admin_ip,
                en_us_validation_msg.PRIMARY_ADMIN_BMC_IP_SAME_MSG
            )
        )
    return errors

def validate_admin_bmc_ip_valid(primary_oim_admin_ip, primary_oim_bmc_ip):
    """
    Validates that both primary_oim_admin_ip and primary_oim_bmc_ip are valid IPv4 addresses.
    """
    errors = []
    if primary_oim_admin_ip and not validation_utils.validate_ipv4(primary_oim_admin_ip):
        errors.append(
            create_error_msg(
                "primary_oim_admin_ip",
                primary_oim_admin_ip,
                en_us_validation_msg.PRIMARY_ADMIN_IP_INVALID_MSG
            )
        )
    if primary_oim_bmc_ip and not validation_utils.validate_ipv4(primary_oim_bmc_ip):
        errors.append(
            create_error_msg(
                "primary_oim_bmc_ip",
                primary_oim_bmc_ip,
                en_us_validation_msg.PRIMARY_BMC_IP_INVALID_MSG
            )
        )
    return errors

def validate_admin_bmc_ip_not_in_dynamic_range(primary_oim_admin_ip, primary_oim_bmc_ip, dynamic_range):
    """
    Validates that neither primary_oim_admin_ip nor primary_oim_bmc_ip are within the dynamic_range.
    """
    errors = []
    if dynamic_range:
        if primary_oim_admin_ip and validation_utils.is_ip_within_range(dynamic_range, primary_oim_admin_ip):
            errors.append(
                create_error_msg(
                    "primary_oim_admin_ip",
                    primary_oim_admin_ip,
                    en_us_validation_msg.PRIMARY_ADMIN_IP_IN_DYNAMIC_RANGE_MSG
                )
            )
        if primary_oim_bmc_ip and validation_utils.is_ip_within_range(dynamic_range, primary_oim_bmc_ip):
            errors.append(
                create_error_msg(
                    "primary_oim_bmc_ip",
                    primary_oim_bmc_ip,
                    en_us_validation_msg.PRIMARY_BMC_IP_IN_DYNAMIC_RANGE_MSG
                )
            )
    return errors

def _validate_ip_ranges(dynamic_range, network_type, netmask_bits):
    """
    Validates a dynamic IP range for a given network type and netmask.

    Args:
        dynamic_range (str): IP range for dynamic addresses (format: "start_ip-end_ip")
        network_type (str): Type of network being validated ("admin_network")
        netmask_bits (str): The netmask bits value to validate IP ranges against

    Returns:
        list: List of validation errors for IP ranges, empty if no errors found

    Validates:
        - Dynamic IP range format.
        - Dynamic IP range is within valid netmask boundaries.
    """
    errors = []

    if not validation_utils.validate_ipv4_range(dynamic_range):
        errors.append(
            create_error_msg(
                f"{network_type}.dynamic_range",
                dynamic_range,
                en_us_validation_msg.RANGE_IP_CHECK_FAIL_MSG,
            )
        )

    # Validate that IP ranges are within the netmask boundaries
    if netmask_bits:
        # Check dynamic range
        if validation_utils.validate_ipv4_range(
            dynamic_range
        ) and not validation_utils.is_range_within_netmask(dynamic_range, netmask_bits):
            errors.append(
                create_error_msg(
                    f"{network_type}.dynamic_range",
                    dynamic_range,
                    en_us_validation_msg.RANGE_NETMASK_BOUNDARY_FAIL_MSG,
                )
            )

    return errors
