#!/usr/bin/env python3
"""
Script to find and decrypt MetaMask vault files (.log and .ldb) within the vault directory
"""

import os
import sys
import json
import argparse
from decryptor import extract_vault_from_file, is_vault_valid, decrypt_vault
from hashcat import generate_hashcat_hashes

# Set your password here (can be overridden by --password argument)
password = "datarde0059"

# ANSI color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    NONE = ''

def print_error(message, use_color=True):
    color = Colors.RED if use_color else Colors.NONE
    end = Colors.END if use_color else Colors.NONE
    print(f"{color}{message}{end}")

def print_success(message, use_color=True):
    color = Colors.GREEN + Colors.BOLD if use_color else Colors.NONE
    end = Colors.END if use_color else Colors.NONE
    print(f"{color}{message}{end}")

def find_metamask_vault_dir(base_dir):
    """
    Find the MetaMask vault directory which is typically named with the extension ID
    """
    if not os.path.exists(base_dir) or not os.path.isdir(base_dir):
        return None
    # Look for directories in the base_dir
    for item in os.listdir(base_dir):
        item_path = os.path.join(base_dir, item)
        # MetaMask extension ID is typically a 32-character string
        if os.path.isdir(item_path) and len(item) >= 32:
            # Optionally, check for expected files inside
            if any(f.endswith(('.log', '.ldb')) for f in os.listdir(item_path)):
                return item_path
    return None

def find_vault_files(vault_dir):
    """
    Find all .log and .ldb files in the vault directory
    """
    if not vault_dir or not os.path.exists(vault_dir):
        return []
    return [
        os.path.join(vault_dir, item)
        for item in os.listdir(vault_dir)
        if os.path.isfile(os.path.join(vault_dir, item)) and (item.endswith('.log') or item.endswith('.ldb'))
    ]

def process_vault_file(file_path, password, extracted_vaults=None, use_color=True):
    """
    Process a single vault file and attempt to decrypt it
    """
    print(f"\n{'='*80}")
    print(f"Processing file: {file_path}")
    print(f"{'='*80}")
    try:
        # Try reading as text first, then as binary if that fails
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                file_content = f.read()
        except Exception as text_error:
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read().decode('utf-8', errors='replace')
            except Exception as binary_error:
                print_error(f"Failed to read file in both text and binary modes.", use_color)
                print_error(f"Text mode error: {text_error}", use_color)
                print_error(f"Binary mode error: {binary_error}", use_color)
                return None
        # Extract vault from file
        print("Extracting vault from file...")
        vault = extract_vault_from_file(file_content)
        if vault is None:
            print_error("No vault found in the file.", use_color)
            return None
        print("Vault extracted.")
        # Log vault to extracted_vaults if provided
        if extracted_vaults is not None:
            extracted_vaults.append({
                'file': file_path,
                'vault': vault
            })
        # Check if vault is valid
        if not is_vault_valid(vault):
            print_error("The extracted vault is not valid.", use_color)
            return None
        print("Vault is valid.")
        # Decrypt vault with password
        print("Attempting to decrypt vault with provided password...")
        try:
            decrypted_data = decrypt_vault(password, vault)
            if decrypted_data and len(decrypted_data) > 0:
                print_success("Decryption successful!", use_color)
                return decrypted_data
            else:
                print_error("Decryption completed, but no keyring data was found.", use_color)
                return None
        except Exception as e:
            print_error(f"Failed to decrypt vault: {e}", use_color)
            return None
    except Exception as e:
        print_error(f"Error processing file: {e}", use_color)
        return None

def main():
    """
    Main function to find and decrypt MetaMask vault files
    """
    parser = argparse.ArgumentParser(description='Decrypt MetaMask vault files')
    parser.add_argument('--vault-dir', default='vault', help='Base directory containing the MetaMask vault')
    parser.add_argument('--password', default=password, help='Password to decrypt the vault')
    parser.add_argument('--output', default='output/decrypted_vaults.json', help='Output file for decrypted vaults')
    parser.add_argument('--no-color', action='store_true', help='Disable ANSI color output')
    args = parser.parse_args()
    use_color = not args.no_color
    # Find the MetaMask vault directory
    vault_dir = find_metamask_vault_dir(args.vault_dir)
    if not vault_dir:
        print_error(f"Could not find MetaMask vault directory in {args.vault_dir}", use_color)
        sys.exit(1)
    print_success(f"Found MetaMask vault directory: {vault_dir}", use_color)
    # Find all vault files
    vault_files = find_vault_files(vault_dir)
    if not vault_files:
        print_error(f"No .log or .ldb files found in {vault_dir}", use_color)
        sys.exit(1)
    print_success(f"Found {len(vault_files)} vault files to process", use_color)
    # Process each vault file
    successful_decryptions = []
    extracted_vaults = []
    for file_path in vault_files:
        result = process_vault_file(file_path, args.password, extracted_vaults=extracted_vaults, use_color=use_color)
        if result:
            successful_decryptions.append({
                'file': file_path,
                'data': result
            })
    # Ensure output directory exists
    output_dir = 'output'
    os.makedirs(output_dir, exist_ok=True)
    # Output file paths
    output_filename = os.path.basename(args.output)
    decrypted_vaults_path = os.path.join(output_dir, output_filename)
    extracted_vaults_path = os.path.join(output_dir, 'extracted_vaults.json')
    hashcat_hash_path = os.path.join(output_dir, 'hashcat.hash')
    # Save extracted vaults to a JSON file
    if extracted_vaults:
        try:
            with open(extracted_vaults_path, 'w', encoding='utf-8') as f:
                json.dump(extracted_vaults, f, indent=2)
            print_success(f"Extracted vaults saved to {extracted_vaults_path}", use_color)
            # Generate hashcat.hash from extracted_vaults.json
            hashes = generate_hashcat_hashes(extracted_vaults_path)
            if hashes:
                with open(hashcat_hash_path, 'w', encoding='utf-8') as f:
                    for h in hashes:
                        f.write(h + '\n')
                print_success(f"Hashcat hashes exported to {hashcat_hash_path}", use_color)
            else:
                print_error(f"No valid hashes found in {extracted_vaults_path}.", use_color)
        except Exception as e:
            print_error(f"Error saving extracted vaults: {e}", use_color)
    else:
        print_error("No vaults were extracted.", use_color)
    # Save results to output file
    if successful_decryptions:
        print_success(f"Successfully decrypted {len(successful_decryptions)} vault files", use_color)
        try:
            with open(decrypted_vaults_path, 'w', encoding='utf-8') as f:
                json.dump(successful_decryptions, f, indent=2)
            print_success(f"Decrypted vaults saved to {decrypted_vaults_path}", use_color)
        except Exception as e:
            print_error(f"Error saving decrypted vaults: {e}", use_color)
    else:
        print_error("No vaults were successfully decrypted", use_color)

if __name__ == "__main__":
    main()
