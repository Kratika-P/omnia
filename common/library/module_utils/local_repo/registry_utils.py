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
# pylint: disable=import-error,no-name-in-module
import requests
from requests.auth import HTTPBasicAuth
from ansible.module_utils.local_repo.common_functions import is_file_exists

def validate_user_registry(user_registry):
    """
    Validates a list of user registry entries with connectivity and credential check.
    Args:
        user_registry (list): List of user registry dictionaries.
    Returns:
        tuple: (bool, str) indicating overall validity and error message if invalid.
    """
    if not isinstance(user_registry, list):
        return False, "user_registry must be a list."

    for idx, item in enumerate(user_registry):
        if not isinstance(item, dict):
            return False, f"Entry at index {idx} must be a dictionary."

        host = item.get('host')
        if not host:
            return False, f"Missing or empty 'host' in entry at index {idx}: {item}"

        requires_auth = item.get('requires_auth', False)

        # Check basic username/password presence
        if requires_auth:
            if not item.get('username') or not item.get('password'):
                return False, (
                    f"'requires_auth' is true but 'username' or 'password' is missing or empty "
                    f"in entry for (host: {host})"
                )

            cert_path = item.get('cert_path')
            key_path = item.get('key_path')

            if bool(cert_path) != bool(key_path):
                return False, (
                    f"If authentication is enabled, both 'cert_path' and 'key_path' must be present "
                    f"or both omitted in entry for (host: {host})"
                )
            try:
                url = f"https://{host}/api/v2.0/users/current"
                response = requests.get(
                    url,
                    auth=HTTPBasicAuth(item['username'], item['password']),
                    verify=True  # Set to True if using valid SSL certs
                )

                if response.status_code == 401:
                    return False, f"Invalid credentials for host: {host}"
                elif response.status_code != 200:
                    return False, f"Unexpected status {response.status_code} while validating host: {host}"

            except requests.exceptions.RequestException as e:
                return False, f"Failed to connect to {host}: {str(e)}"

    return True, ""

def check_reachability(user_registry, timeout):
    """
    Checks the reachability of hosts in the user registry.

    Args:
        user_registry (list): A list of dictionaries representing user registry entries.
        timeout (int): The maximum number of seconds to wait for a response.

    Returns:
        tuple: A tuple containing two lists: reachable hosts and unreachable hosts.
    """
    reachable, unreachable = [], []
    for item in user_registry:
        try:
            resp = requests.get(f"https://{item['host']}", timeout=timeout, verify=True)
            if resp.status_code == 200:
                reachable.append(item['host'])
            else:
                unreachable.append(item['host'])
        except Exception:
            unreachable.append(item['host'])
    return reachable, unreachable

def find_invalid_cert_paths(user_registry):
    """
    Finds invalid certificate/key path configurations in the user registry.

    Rules:
    - If cert_path is provided, key_path must also be provided, and vice versa.
    - If either path is provided, the corresponding file must exist.

    Args:
        user_registry (list): List of dictionaries representing user registry entries.

    Returns:
        list: A list of error strings describing invalid entries.
    """
    invalid_entries = []

    for idx, item in enumerate(user_registry):
        cert_path = item.get('cert_path')
        key_path = item.get('key_path')
        name_or_host = item.get('name') or item.get('host') or f"entry {idx}"

        # If only one of cert or key is provided
        if bool(cert_path) != bool(key_path):
            invalid_entries.append(
                f"{name_or_host}: Both 'cert_path' and 'key_path' must be provided together or not at all."
            )
            continue

        # If both are provided, validate file existence
        if cert_path and not is_file_exists(cert_path):
            invalid_entries.append(f"{name_or_host}: cert_path '{cert_path}' does not exist.")

        if key_path and not is_file_exists(key_path):
            invalid_entries.append(f"{name_or_host}: key_path '{key_path}' does not exist.")

    return invalid_entries
