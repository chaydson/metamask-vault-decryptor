#!/usr/bin/env python3
"""
Script to find and decrypt MetaMask vault files (.log and .ldb) within the vault directory
"""

import os
import sys
import json
import argparse
from decryptor import extract_vault_from_file, is_vault_valid, decrypt_vault

# Coloque a senha aqui
password = ""

# ANSI color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def find_metamask_vault_dir(base_dir):
    """
    Find the MetaMask vault directory which is typically named with the extension ID
    """
    if not os.path.exists(base_dir) or not os.path.isdir(base_dir):
        print(f"Error: Directory {base_dir} does not exist")
        return None
    
    # Look for directories in the base_dir
    for item in os.listdir(base_dir):
        item_path = os.path.join(base_dir, item)
        # MetaMask extension ID is typically a 32-character string
        if os.path.isdir(item_path) and len(item) >= 32:
            return item_path
    
    return None

def find_vault_files(vault_dir):
    """
    Find all .log and .ldb files in the vault directory
    """
    if not vault_dir or not os.path.exists(vault_dir):
        return []
    
    vault_files = []
    for item in os.listdir(vault_dir):
        item_path = os.path.join(vault_dir, item)
        if os.path.isfile(item_path) and (item.endswith('.log') or item.endswith('.ldb')):
            vault_files.append(item_path)
    
    return vault_files

def process_vault_file(file_path, password):
    """
    Process a single vault file and attempt to decrypt it
    """
    print(f"\n{'='*80}")
    print(f"Processing file: {file_path}")
    print(f"{'='*80}")
    
    try:
        # Read the vault file - try binary mode first, then text mode if that fails
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read().decode('utf-8', errors='replace')
        except Exception as binary_error:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    file_content = f.read()
            except Exception as text_error:
                print(f"Failed to read file in both binary and text modes.")
                print(f"Binary mode error: {binary_error}")
                print(f"Text mode error: {text_error}")
                return None
        
        # Extract vault from file
        print("Extracting vault from file...")
        vault = extract_vault_from_file(file_content)
        
        if vault is None:
            print(f"{Colors.RED}No vault found in the file.{Colors.END}")
            return None
        
        print("Vault extracted.")
        
        # Check if vault is valid
        if not is_vault_valid(vault):
            print("The extracted vault is not valid.")
            return None
        
        print("Vault is valid.")
        
        # Decrypt vault with password
        print(f"Attempting to decrypt vault with provided password...")
        try:
            decrypted_data = decrypt_vault(password, vault)
            if decrypted_data and len(decrypted_data) > 0:
                print(f"{Colors.GREEN}Decryption successful!{Colors.END}")
                return decrypted_data
            else:
                print("Decryption completed, but no keyring data was found.")
                return None
        except Exception as e:
            print(f"Failed to decrypt vault: {e}")
            return None
    
    except Exception as e:
        print(f"Error processing file: {e}")
        return None

def main():
    """
    Main function to find and decrypt MetaMask vault files
    """
    parser = argparse.ArgumentParser(description='Decrypt MetaMask vault files')
    parser.add_argument('--vault-dir', default='vault', help='Base directory containing the MetaMask vault')
    parser.add_argument('--password', default=password, help='Password to decrypt the vault')
    parser.add_argument('--output', default='decrypted_vaults.json', help='Output file for decrypted vaults')
    
    args = parser.parse_args()
    
    # Find the MetaMask vault directory
    vault_dir = find_metamask_vault_dir(args.vault_dir)
    if not vault_dir:
        print(f"Error: Could not find MetaMask vault directory in {args.vault_dir}")
        sys.exit(1)
    
    print(f"Found MetaMask vault directory: {vault_dir}")
    
    # Find all vault files
    vault_files = find_vault_files(vault_dir)
    if not vault_files:
        print(f"Error: No .log or .ldb files found in {vault_dir}")
        sys.exit(1)
    
    print(f"Found {len(vault_files)} vault files to process")
    
    # Process each vault file
    successful_decryptions = []
    for file_path in vault_files:
        result = process_vault_file(file_path, args.password)
        if result:
            successful_decryptions.append({
                'file': file_path,
                'data': result
            })
    
    # Save results to output file
    if successful_decryptions:
        print(f"\n{Colors.GREEN}{Colors.BOLD}Successfully decrypted {len(successful_decryptions)} vault files{Colors.END}")
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(successful_decryptions, f, indent=2)
            print(f"{Colors.GREEN}{Colors.BOLD}Decrypted vaults saved to {args.output}{Colors.END}")
        except Exception as e:
            print(f"Error saving decrypted vaults: {e}")
    else:
        print("\nNo vaults were successfully decrypted")

if __name__ == "__main__":
    main()
