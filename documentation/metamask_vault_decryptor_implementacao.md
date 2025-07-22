# Documentação do MetaMask Vault Decryptor

## Visão Geral

O MetaMask Vault Decryptor é uma ferramenta especializada para extrair e descriptografar vaults do MetaMask, permitindo a recuperação de chaves privadas e mnemonics de carteiras criptográficas. Esta implementação em Python é um port da versão JavaScript original, mantendo as mesmas funcionalidades mas com a flexibilidade e facilidade de uso da linguagem Python.

## Arquitetura do Sistema

O sistema é composto por dois componentes principais:

1. **Módulo de Descriptografia (decryptor.py)**: Contém todas as funções necessárias para extração, validação e descriptografia de vaults
2. **Script Principal (main.py)**: Interface de linha de comando para buscar e processar arquivos de vault do MetaMask

### Diagrama de Fluxo

```
[Arquivos de Vault] → [Extração] → [Validação] → [Descriptografia] → [Dados Descriptografados]
```

## Componentes Principais

### 1. Módulo de Descriptografia (decryptor.py)

Este módulo implementa as funcionalidades centrais do sistema, incluindo:

#### Classe BrowserPassworder

Uma implementação Python do módulo `@metamask/browser-passworder` usado pelo MetaMask para criptografar e descriptografar dados sensíveis.

```python
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
        
        # Decrypt using AES-GCM
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(iv_bytes, data_bytes, None)
        
        # Parse and return the decrypted data
        # ...
```

#### Funções Principais

##### `extract_vault_from_file(data)`

Esta função é responsável por extrair dados de vault de diferentes formatos de arquivo:

```python
def extract_vault_from_file(data):
    """
    Extract vault data from various file formats.
    
    Args:
        data (str): The file content to extract vault from
        
    Returns:
        dict or None: The extracted vault data or None if no vault found
    """
    # Tenta encontrar um objeto JSON válido no arquivo
    json_pattern = r'(\{[\s\S]*?\})'
    matches = re.findall(json_pattern, data)
    
    for match in matches:
        try:
            # Tenta analisar como JSON
            obj = json.loads(match)
            
            # Verifica se parece um vault do MetaMask
            if isinstance(obj, dict) and 'data' in obj and 'iv' in obj and 'salt' in obj:
                return obj
        except json.JSONDecodeError:
            continue
    
    # Tenta encontrar um vault no formato específico do LevelDB
    leveldb_pattern = r'"data":"([^"]+)","iv":"([^"]+)","salt":"([^"]+)"'
    leveldb_matches = re.findall(leveldb_pattern, data)
    
    for match in leveldb_matches:
        if len(match) == 3:
            data_str, iv_str, salt_str = match
            vault = {
                "data": data_str,
                "iv": iv_str,
                "salt": salt_str
            }
            return vault
    
    # Tenta encontrar um vault no formato específico do LevelDB com keyMetadata
    leveldb_pattern_with_metadata = r'"data":"([^"]+)","iv":"([^"]+)","salt":"([^"]+)","keyMetadata":(\{[^}]+\})'
    leveldb_matches_with_metadata = re.findall(leveldb_pattern_with_metadata, data)
    
    for match in leveldb_matches_with_metadata:
        if len(match) == 4:
            data_str, iv_str, salt_str, key_metadata_str = match
            try:
                key_metadata = json.loads(key_metadata_str)
                vault = {
                    "data": data_str,
                    "iv": iv_str,
                    "salt": salt_str,
                    "keyMetadata": key_metadata
                }
                return vault
            except json.JSONDecodeError:
                continue
    
    return None
```

##### `is_vault_valid(vault)`

Verifica se um objeto de vault é válido:

```python
def is_vault_valid(vault):
    """
    Check if a vault object is valid.
    
    Args:
        vault (dict): The vault object to check
        
    Returns:
        bool: True if the vault is valid, False otherwise
    """
    if not isinstance(vault, dict):
        return False
    
    required_keys = ['data', 'iv', 'salt']
    return all(key in vault for key in required_keys)
```

##### `decrypt_vault(password, vault)`

Descriptografa um vault usando a senha fornecida:

```python
def decrypt_vault(password, vault):
    """
    Decrypt the vault using the provided password.
    
    Args:
        password (str): The password to decrypt the vault
        vault (dict): The vault object to decrypt
        
    Returns:
        list: List of decrypted keyring objects
    """
    if not is_vault_valid(vault):
        raise ValueError("Invalid vault format")
    
    # Convert vault to JSON string
    vault_str = json.dumps(vault)
    
    try:
        # Use BrowserPassworder to decrypt
        decrypted_data = BrowserPassworder.decrypt(password, vault_str)
        return decrypted_data
    except Exception as e:
        # Handle specific error types
        if "Incorrect password" in str(e):
            raise ValueError("Incorrect password")
        elif "Invalid vault format" in str(e):
            raise ValueError("Invalid vault format")
        else:
            raise ValueError(f"Failed to decrypt vault: {str(e)}")
```

##### Funções Auxiliares

- `dedupe(arr)`: Remove duplicatas de uma lista de dicionários
- `decode_mnemonic(mnemonic)`: Decodifica uma mnemonic de string ou bytes
- `generate_salt(byte_count=32)`: Gera uma string aleatória para uso como salt na derivação de chaves

### 2. Script Principal (main.py)

O script principal fornece uma interface de linha de comando para buscar e processar arquivos de vault do MetaMask:

#### Funções Principais

##### `find_metamask_vault_dir(base_dir)`

Localiza o diretório de vault do MetaMask, que geralmente é nomeado com o ID da extensão:

```python
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
```

##### `find_vault_files(vault_dir)`

Encontra todos os arquivos .log e .ldb no diretório de vault:

```python
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
```

##### `process_vault_file(file_path, password)`

Processa um único arquivo de vault e tenta descriptografá-lo:

```python
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
                print(f"{Colors.RED}Decryption failed: Empty result.{Colors.END}")
                return None
        except ValueError as e:
            print(f"{Colors.RED}Decryption failed: {str(e)}{Colors.END}")
            return None
        
    except Exception as e:
        print(f"{Colors.RED}Error processing file: {str(e)}{Colors.END}")
        return None
```

##### `main()`

Função principal que processa os argumentos da linha de comando e coordena o processo de busca e descriptografia:

```python
def main():
    """
    Main function to find and decrypt MetaMask vault files
    """
    parser = argparse.ArgumentParser(description='Find and decrypt MetaMask vault files')
    parser.add_argument('--vault-dir', default='vault', help='Base directory containing MetaMask vault files')
    parser.add_argument('--password', required=True, help='Password to decrypt the vault')
    parser.add_argument('--output', default='decrypted_vaults.json', help='Output file for decrypted vaults')
    
    args = parser.parse_args()
    
    print(f"{Colors.BOLD}MetaMask Vault Decryptor{Colors.END}")
    print(f"Looking for vault files in: {args.vault_dir}")
    
    # Find MetaMask vault directory
    vault_dir = args.vault_dir
    if not os.path.exists(vault_dir):
        print(f"{Colors.RED}Error: Directory {vault_dir} does not exist{Colors.END}")
        return
    
    # Find vault files
    vault_files = find_vault_files(vault_dir)
    if not vault_files:
        print(f"{Colors.RED}No vault files found in {vault_dir}{Colors.END}")
        return
    
    print(f"{Colors.GREEN}Found {len(vault_files)} potential vault files.{Colors.END}")
    
    # Process each vault file
    all_decrypted_data = []
    for file_path in vault_files:
        decrypted_data = process_vault_file(file_path, args.password)
        if decrypted_data:
            all_decrypted_data.extend(decrypted_data)
    
    # Save decrypted data to file
    if all_decrypted_data:
        print(f"\n{Colors.GREEN}Successfully decrypted {len(all_decrypted_data)} vaults.{Colors.END}")
        print(f"Saving decrypted data to {args.output}...")
        
        with open(args.output, 'w') as f:
            json.dump(all_decrypted_data, f, indent=2)
        
        print(f"{Colors.GREEN}Done! Decrypted data saved to {args.output}{Colors.END}")
    else:
        print(f"\n{Colors.RED}No vaults were successfully decrypted.{Colors.END}")
```

## Fluxo de Processamento

O fluxo completo de processamento de um vault do MetaMask segue estas etapas:

1. **Localização de Arquivos**:
   - O script busca arquivos .log e .ldb no diretório especificado
   - Esses arquivos potencialmente contêm dados de vault do MetaMask

2. **Extração de Vault**:
   - Cada arquivo é analisado para extrair dados de vault
   - São suportados múltiplos formatos de armazenamento

3. **Validação de Vault**:
   - Os dados extraídos são validados para garantir que são um vault válido
   - São verificados campos obrigatórios como 'data', 'iv' e 'salt'

4. **Descriptografia**:
   - O vault é descriptografado usando a senha fornecida
   - É utilizado o algoritmo PBKDF2 para derivação de chave e AES-GCM para descriptografia

5. **Processamento de Dados**:
   - Os dados descriptografados são processados e formatados
   - Mnemonics codificadas são decodificadas para formato legível

6. **Armazenamento de Resultados**:
   - Os dados descriptografados são salvos em um arquivo JSON
   - Duplicatas são removidas para evitar redundância

## Segurança e Considerações

O MetaMask Vault Decryptor implementa os mesmos algoritmos de criptografia usados pelo MetaMask:

1. **Derivação de Chave**: PBKDF2 com SHA-256, usando salt e múltiplas iterações
2. **Criptografia**: AES-GCM (Galois/Counter Mode), um modo de operação autenticado
3. **Codificação**: Base64 para armazenamento de dados binários

É importante notar que esta ferramenta deve ser usada apenas para fins legítimos, como recuperação de carteiras próprias. O uso indevido para acessar carteiras de terceiros sem autorização é ilegal e antiético.

## Conclusão

O MetaMask Vault Decryptor é uma ferramenta poderosa para recuperação de chaves privadas e mnemonics de carteiras MetaMask. Sua implementação em Python oferece uma alternativa flexível e fácil de usar à versão JavaScript original, mantendo todas as funcionalidades essenciais.

A ferramenta é especialmente útil em cenários de recuperação de carteiras, análise forense e auditoria de segurança, sempre respeitando os limites éticos e legais de tais atividades.
