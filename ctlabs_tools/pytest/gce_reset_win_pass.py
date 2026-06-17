# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import copy
import datetime
import json
import time
import argparse

# NOTE: PyCryptodome is the modern replacement for the deprecated PyCrypto.
# The PyCryptodome package maintains the 'Crypto' namespace for compatibility
# but should be installed via 'pip install pycryptodome'.
# The imports below remain 'Crypto' but rely on the installed 'pycryptodome' package.
from Crypto.Cipher      import PKCS1_OAEP
from Crypto.PublicKey   import RSA
from Crypto.Util.number import long_to_bytes

# Google API Client Library for Python:
# pip install google-api-python-client oauth2client
from oauth2client.client       import GoogleCredentials
from googleapiclient.discovery import build


def GetCompute():
    """Get a compute object for communicating with the Compute Engine API."""
    # Uses Application Default Credentials (ADC) for authentication.
    credentials = GoogleCredentials.get_application_default()
    compute     = build('compute', 'v1', credentials=credentials)
    return compute


def GetInstance(compute, instance, zone, project):
    """Get the data for a Google Compute Engine instance."""
    cmd = compute.instances().get(instance=instance, project=project,
                                  zone=zone)
    return cmd.execute()


def GetKey():
    """Get an RSA key for encryption."""
    # This uses the PyCryptodome library (installed as 'pycryptodome')
    key = RSA.generate(2048)
    return key


def GetModulusExponentInBase64(key):
    """Return the public modulus and exponent for the key in base64 encoding."""
    # Note: long_to_bytes is available in both PyCrypto and PyCryptodome.
    mod = long_to_bytes(key.n)
    exp = long_to_bytes(key.e)

    # In Python 3, base64.b64encode returns bytes, which must be decoded
    # to a string before being used in the JSON payload.
    modulus  = base64.b64encode(mod).decode('utf-8')
    exponent = base64.b64encode(exp).decode('utf-8')

    return modulus, exponent


def GetExpirationTimeString():
    """Return an RFC3339 UTC timestamp for 5 minutes from now."""
    utc_now     = datetime.datetime.utcnow()
    # These metadata entries are one-time-use, so the expiration time does
    # not need to be very far in the future.
    expire_time = utc_now + datetime.timedelta(minutes=5)
    # The format code for Z for UTC is included in the string formatting.
    return expire_time.strftime('%Y-%m-%dT%H:%M:%SZ')


def GetJsonString(user, modulus, exponent, email):
    """Return the JSON string object that represents the windows-keys entry."""
    expire = GetExpirationTimeString()
    data   = {'userName' : user,
              'modulus'  : modulus,
              'exponent' : exponent,
              'email'    : email,
              'expireOn' : expire}
    # json.dumps handles the conversion to a JSON string.
    return json.dumps(data)


def UpdateWindowsKeys(old_metadata, metadata_entry):
    """Return updated metadata contents with the new windows-keys entry appended."""
    new_metadata = copy.deepcopy(old_metadata)
    
    # Ensure 'items' list exists in the metadata
    if 'items' not in new_metadata:
        new_metadata['items'] = []

    # Look for existing 'windows-keys' to append to
    found = False
    for item in new_metadata['items']:
        if item['key'] == 'windows-keys':
            # Append the new key entry, separated by a newline as required by GCE
            item['value'] = item['value'] + '\n' + metadata_entry
            found = True
            break
            
    # If 'windows-keys' wasn't found, append it as a new metadata item
    if not found:
        new_metadata['items'].append({
            'key'  : "windows-keys",
            'value': metadata_entry
        })
        
    return new_metadata


def UpdateInstanceMetadata(compute, instance, zone, project, new_metadata):
    """Update the instance metadata."""
    cmd = compute.instances().setMetadata(instance=instance, project=project,
                                          zone=zone, body=new_metadata)
    return cmd.execute()

def CleanUpWindowsKeysMetadata(compute, instance, zone, project, metadata_entry):
    """Removes the specific windows-keys entry from instance metadata."""
    # Fetch the latest metadata to ensure we have the correct fingerprint
    instance_ref = GetInstance(compute, instance, zone, project)
    metadata = instance_ref['metadata']

    if 'items' not in metadata:
        return

    for i, item in enumerate(metadata['items']):
        if item['key'] == 'windows-keys':
            # The value is a string of newline-separated JSON payloads
            current_keys = item['value'].split('\n')
            
            # Filter out the specific JSON entry we just added
            updated_keys = [k for k in current_keys if k != metadata_entry]

            if updated_keys:
                item['value'] = '\n'.join(updated_keys)
            else:
                # If the list is now empty, remove the 'windows-keys' item entirely
                del metadata['items'][i]
            break

    # Push the cleaned metadata back to the instance
    UpdateInstanceMetadata(compute, instance, zone, project, metadata)
    print("Successfully removed the temporary windows-keys metadata.")


def GetSerialPortFourOutput(compute, instance, zone, project):
    """Get the output from serial port 4 from the instance."""
    # Encrypted passwords are printed to COM4 on the windows server:
    port = 4
    cmd  = compute.instances().getSerialPortOutput(instance=instance,
                                                  project=project,
                                                  zone=zone, port=port)
    output = cmd.execute()
    return output['contents']


def GetEncryptedPasswordFromSerialPort(serial_port_output, modulus):
    """Find and return the correct encrypted password, based on the modulus."""
    # The output is scanned line by line in reverse to find the latest key.
    output = serial_port_output.split('\n')
    for line in reversed(output):
        try:
            entry = json.loads(line)
            if modulus == entry['modulus']:
                return entry['encryptedPassword']
        except ValueError:
            # Ignore lines that are not valid JSON
            pass
    return None # Return None if no matching entry is found


def DecryptPassword(encrypted_password, key):
    """Decrypt a base64 encoded encrypted password using the provided key."""
    decoded_password = base64.b64decode(encrypted_password)
    # PKCS1_OAEP is available in both PyCrypto and PyCryptodome.
    cipher           = PKCS1_OAEP.new(key)
    # Decrypt returns bytes in Python 3, which we decode to a string for printing.
    password         = cipher.decrypt(decoded_password).decode('utf-8')
    return password


def main(instance, zone, project, user, email, timeout, poll_interval):
    # Setup
    compute                 = GetCompute()
    key                     = GetKey()
    modulus, exponent       = GetModulusExponentInBase64(key)

    # Get existing metadata
    instance_ref = GetInstance(compute, instance, zone, project)
    old_metadata = instance_ref['metadata']

    # Create and set new metadata
    metadata_entry = GetJsonString(user, modulus, exponent, email)
    
    # Safely update metadata
    new_metadata   = UpdateWindowsKeys(old_metadata, metadata_entry)
    
    # The result variable stores the API response for the update operation
    result = UpdateInstanceMetadata(compute, instance, zone, project, new_metadata)
    print(f"Metadata update operation initiated: {result['name']}")

    # Polling loop: Check for the password until found or timeout is reached.
    print(f"Waiting for the Windows guest agent to generate the password (up to {timeout} seconds)...")
    end_time     = time.time() + timeout
    enc_password = None

    while time.time() < end_time:
        serial_port_output = GetSerialPortFourOutput(compute, instance, zone, project)
        enc_password       = GetEncryptedPasswordFromSerialPort(serial_port_output, modulus)

        if enc_password:
            print("Password found in serial port output.")
            break

        # Calculate remaining time for next sleep
        remaining    = end_time - time.time()
        sleep_duration = min(poll_interval, remaining)
        
        if sleep_duration > 0:
            print(f"Password not yet found. Retrying in {int(sleep_duration)} seconds...")
            time.sleep(sleep_duration)
        else:
            break # Exit if remaining time is zero or less

    if not enc_password:
        print(f"Error: Could not find the encrypted password in the serial port output within {timeout} seconds.")
        print("You may need to wait longer or check the instance logs.")
        return

    password = DecryptPassword(enc_password, key)

    # --- NEW METADATA CLEANUP ---
    print("Cleaning up temporary metadata...")
    try:
        CleanUpWindowsKeysMetadata(compute, instance, zone, project, metadata_entry)
    except Exception as e:
        print(f"Warning: Failed to clean up metadata automatically. Error: {e}")
    # ----------------------------

    # Safely retrieve the external IP address, handling cases where 'accessConfigs' is missing.
    ip                   = 'No external IP assigned.'
    network_interfaces   = instance_ref.get('networkInterfaces')
    
    # Check if networkInterfaces exists, has at least one element, 
    # and if that element has accessConfigs with at least one element.
    if network_interfaces and len(network_interfaces) > 0:
        access_configs = network_interfaces[0].get('accessConfigs')
        if access_configs and len(access_configs) > 0:
            ip = access_configs[0].get('natIP', 'Internal IP only (natIP not found).')

    return { 'username' : user, 'password' : password, 'ip' : ip}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Reset the password for a Google Compute Engine Windows instance.'
    )
    
    # Argument Definitions
    parser.add_argument(
        '-p', '--project',
        required=True,
        help='The Google Cloud project ID (e.g., test-project-12345).'
    )
    parser.add_argument(
        '-z', '--zone',
        required=True,
        help='The zone where the instance is located (e.g., us-central1-a).'
    )
    parser.add_argument(
        '-i', '--instance',
        required=True,
        help='The name of the Windows Compute Engine instance (e.g., windows-vm-1).'
    )
    parser.add_argument(
        '-u', '--user',
        required=True,
        help='The desired username for the password reset (e.g., myadmin).'
    )
    parser.add_argument(
        '-e', '--email',
        required=True,
        help='The email associated with the key entry (e.g., user@example.com).'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=30,
        help='The total number of seconds to wait for the password to appear in serial port output (default: 30).'
    )
    parser.add_argument(
        '-s', '--poll-interval',
        type=int,
        default=5,
        help='The number of seconds to wait between checks (polling interval) (default: 5).'
    )
    
    args = parser.parse_args()

    creds = main(args.instance, args.zone, args.project, args.user, args.email, args.timeout, args.poll_interval)
    
    # Print logic moves here for CLI users
    if creds:
        print("\n--- Windows Instance Credentials ---")
        print(f"Username:   {creds['username']}")
        print(f"Password:   {creds['password']}")
        print(f"IP Address: {creds['ip']}")
        print("----------------------------------\n")

