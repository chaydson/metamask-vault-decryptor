import json
import re
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Python equivalent of @metamask/browser-passworder
class BrowserPassworder:
    @staticmethod
    def decrypt(password, encrypted_vault_str):
        """
        Decrypt the vault using the provided password.
        
        Args:
            password (str): The password to decrypt the vault
            encrypted_vault_str (str): JSON string of the encrypted vault
            
        Returns:
            list: List of keyring objects with decoded mnemonics
        """
        encrypted_vault = json.loads(encrypted_vault_str)
        
        # Extract components
        data = encrypted_vault.get('data')
        iv = encrypted_vault.get('iv')
        salt = encrypted_vault.get('salt')
        key_metadata = encrypted_vault.get('keyMetadata')
        
        if not all([data, iv, salt]):
            raise ValueError("Invalid vault format")
        
        # Decode base64 components
        data_bytes = base64.b64decode(data)
        iv_bytes = base64.b64decode(iv)
        salt_bytes = base64.b64decode(salt)
        
        # Determine iterations based on keyMetadata if available
        iterations = 10000  # Default to old derivation params
        if key_metadata and isinstance(key_metadata, dict) and 'params' in key_metadata:
            iterations = key_metadata['params'].get('iterations', 10000)
        
        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt_bytes,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        
        try:
            # Decrypt using AES-GCM
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(iv_bytes, data_bytes, None)
            
            # Parse the decrypted JSON
            try:
                # Tenta decodificar e carregar como JSON
                decrypted_str = decrypted_data.decode('utf-8')
                keyrings_with_encoded_mnemonic = json.loads(decrypted_str)
                
                # Handle both single object and list formats
                if not isinstance(keyrings_with_encoded_mnemonic, list):
                    keyrings_with_encoded_mnemonic = [keyrings_with_encoded_mnemonic]
                    
                # Retorna diretamente os dados descriptografados
                return keyrings_with_encoded_mnemonic
            except Exception as e:
                print(f"Debug - Falha ao decodificar/analisar dados: {e}")
                print(f"Debug - Tipo de dados descriptografados: {type(decrypted_data)}")
                print(f"Debug - Primeiros 100 bytes: {decrypted_data[:100] if isinstance(decrypted_data, bytes) else 'Não é bytes'}")
                raise
            
            # Decode mnemonics
            keyrings_with_decoded_mnemonic = []
            for keyring in keyrings_with_encoded_mnemonic:
                if 'data' in keyring and 'mnemonic' in keyring['data']:
                    keyring_copy = keyring.copy()
                    keyring_copy['data'] = keyring['data'].copy()
                    keyring_copy['data']['mnemonic'] = decode_mnemonic(keyring['data']['mnemonic'])
                    keyrings_with_decoded_mnemonic.append(keyring_copy)
                else:
                    keyrings_with_decoded_mnemonic.append(keyring)
                    
            return keyrings_with_decoded_mnemonic
        except Exception as e:
            raise ValueError(f"Incorrect password or invalid data: {str(e)}")


# Deduplicates array with rudimentary non-recursive shallow comparison of keys
def dedupe(arr):
    """
    Deduplicate an array of dictionaries by comparing keys and values.
    
    Args:
        arr (list): List of dictionaries to deduplicate
        
    Returns:
        list: Deduplicated list
    """
    if not arr:
        return []
        
    result = []
    for x in arr:
        found = False
        for y in result:
            if (len(x.keys()) == len(y.keys()) and 
                all(y.get(k) == x.get(k) for k in x.keys())):
                found = True
                break
        if not found:
            result.append(x)
    return result


def decode_mnemonic(mnemonic):
    """
    Decode a mnemonic from string or bytes.
    
    Args:
        mnemonic (str or bytes): The mnemonic to decode
        
    Returns:
        str: The decoded mnemonic as a string
    """
    if isinstance(mnemonic, str):
        return mnemonic
    else:
        return mnemonic.decode('utf-8')


def generate_salt(byte_count=32):
    """
    Generates a random string for use as a salt in key derivation.
    
    Args:
        byte_count (int): The number of bytes to generate
        
    Returns:
        str: A base64 encoded random string
    """
    random_bytes = os.urandom(byte_count)
    # Convert bytes to string using the same method as in JavaScript
    chars = [chr(b) for b in random_bytes]
    return base64.b64encode(''.join(chars).encode('latin1')).decode('utf-8')


def extract_vault_from_file(data):
    """
    Extract vault data from various file formats.
    
    Args:
        data (str): The file content to extract vault from
        
    Returns:
        dict or None: The extracted vault data or None if no vault found
    """
    # attempt 1: raw json
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        # Not valid JSON: continue
        pass
    
    # attempt 2: pre-v3 cleartext
    matches = re.search(r'{"wallet-seed":"([^"}]*)"}', data)
    if matches:
        mnemonic = re.sub(r'\\n*', '', matches.group(1))
        vault_matches = re.search(r'"wallet":("{\[ -~\]*\\"version\\":2}")', data)
        vault = {}
        if vault_matches:
            vault = json.loads(json.loads(vault_matches.group(1)))
        
        return {
            'data': {
                **{'mnemonic': mnemonic},
                **vault
            }
        }
    
    # attempt 3: chromium 000003.log file on linux
    matches = re.search(r'"KeyringController":{"vault":"{[^{}]*}"', data)
    if matches:
        vault_body = matches.group(0)[29:]  # substring from position 29
        return json.loads(json.loads(vault_body))
    
    # attempt 4: chromium 000006.log on MacOS
    matches = re.search(r'KeyringController":(\{"vault":".*?=\\"\}"\})', data)
    if matches:
        try:
            keyring_controller_state_fragment = matches.group(1)
            data_regex = r'\\"data\\":\\"([A-Za-z0-9+\/]*=*)'
            iv_regex = r',\\"iv\\":\\"([A-Za-z0-9+\/]{10,40}=*)'
            salt_regex = r',\\"salt\\":\\"([A-Za-z0-9+\/]{10,100}=*)\\\"'
            key_meta_regex = r',\\"keyMetadata\\":(.*}})'
            
            data_match = re.search(data_regex, keyring_controller_state_fragment)
            iv_match = re.search(iv_regex, keyring_controller_state_fragment)
            salt_match = re.search(salt_regex, keyring_controller_state_fragment)
            key_meta_match = re.search(key_meta_regex, keyring_controller_state_fragment)
            
            if all([data_match, iv_match, salt_match, key_meta_match]):
                return {
                    'data': data_match.group(1),
                    'iv': iv_match.group(1),
                    'salt': salt_match.group(1),
                    'keyMetadata': json.loads(key_meta_match.group(1).replace('\\', ''))
                }
        except Exception:
            # Not valid JSON: continue
            pass
    
    # attempt 5: chromium 0000056.log on MacOS
    matches = re.search(r'"KeyringController":(\{.*?"vault":".*?=\\"\}"\})', data)
    if matches:
        try:
            keyring_controller_state_fragment = matches.group(1)
            data_regex = r'\\"data\\":\\"([A-Za-z0-9+\/]*=*)'
            iv_regex = r',\\"iv\\":\\"([A-Za-z0-9+\/]{10,40}=*)'
            salt_regex = r',\\"salt\\":\\"([A-Za-z0-9+\/]{10,100}=*)\\\"'
            key_meta_regex = r',\\"keyMetadata\\":(.*}})'
            
            data_match = re.search(data_regex, keyring_controller_state_fragment)
            iv_match = re.search(iv_regex, keyring_controller_state_fragment)
            salt_match = re.search(salt_regex, keyring_controller_state_fragment)
            key_meta_match = re.search(key_meta_regex, keyring_controller_state_fragment)
            
            if all([data_match, iv_match, salt_match, key_meta_match]):
                return {
                    'data': data_match.group(1),
                    'iv': iv_match.group(1),
                    'salt': salt_match.group(1),
                    'keyMetadata': json.loads(key_meta_match.group(1).replace('\\', ''))
                }
        except Exception:
            # Not valid JSON: continue
            pass
    
    # attempt 6: chromium 000005.ldb on windows
    match_regex = r'Keyring[0-9][^\}]*(\{[^\{\}]*\\"\})'
    capture_regex = r'Keyring[0-9][^\}]*(\{[^\{\}]*\\"\})'
    iv_regex = r'\\"iv.{1,4}[^A-Za-z0-9+\/]{1,10}([A-Za-z0-9+\/]{10,40}=*)'
    data_regex = r'\\"[^":,is]*\\":\\"([A-Za-z0-9+\/]*=*)'
    salt_regex = r',\\"salt.{1,4}[^A-Za-z0-9+\/]{1,10}([A-Za-z0-9+\/]{10,100}=*)'
    
    matches = re.findall(match_regex, data, re.IGNORECASE)
    if not matches:
        return None
    
    vaults = []
    for match in matches:
        capture_match = re.search(capture_regex, match)
        if not capture_match:
            continue
        
        s = capture_match.group(1)
        d_match = re.search(data_regex, s)
        i_match = re.search(iv_regex, s)
        s_match = re.search(salt_regex, s)
        
        if all([d_match, i_match, s_match]):
            vaults.append({
                'data': d_match.group(1),
                'iv': i_match.group(1),
                'salt': s_match.group(1)
            })
    
    vaults = dedupe(vaults)
    if not vaults:
        return None
    
    if len(vaults) > 1:
        print('Found multiple vaults!', vaults)
    
    return vaults[0]


def is_vault_valid(vault):
    """
    Check if a vault object is valid.
    
    Args:
        vault (dict): The vault object to check
        
    Returns:
        bool: True if the vault is valid, False otherwise
    """
    return (isinstance(vault, dict) and 
            all(isinstance(vault.get(e), str) for e in ['data', 'iv', 'salt']))


def decrypt_vault(password, vault):
    """
    Decrypt the vault using the provided password.
    
    Args:
        password (str): The password to decrypt the vault
        vault (dict): The vault object to decrypt
        
    Returns:
        list: List of decrypted keyring objects
    """
    if isinstance(vault, dict) and vault.get('data') and isinstance(vault['data'], dict) and vault['data'].get('mnemonic'):
        return [vault]
    
    try:
        # Decrypt the vault using BrowserPassworder
        result = BrowserPassworder.decrypt(password, json.dumps(vault))
        
        # Decode mnemonics if present
        for item in result:
            if isinstance(item, dict) and 'data' in item and isinstance(item['data'], dict) and 'mnemonic' in item['data']:
                mnemonic = item['data']['mnemonic']
                
                # Caso 1: Se o mnemonic for uma lista de códigos ASCII, converta para string
                if isinstance(mnemonic, list) and all(isinstance(code, int) for code in mnemonic):
                    item['data']['mnemonic'] = ''.join(chr(code) for code in mnemonic)
                
                # Caso 2: Se o mnemonic estiver codificado como string hexadecimal, decodifique-o
                elif isinstance(mnemonic, str) and mnemonic.startswith('0x'):
                    item['data']['mnemonic'] = decode_mnemonic(mnemonic)
        
        return result
    except Exception as e:
        # Apenas registre o erro, mas não retorne uma lista vazia
        # para evitar a mensagem "Decryption successful!" quando falhar
        raise Exception(f"Error decrypting vault: {e}")


# Export the functions
__all__ = [
    'decrypt_vault',
    'extract_vault_from_file',
    'is_vault_valid',
]
