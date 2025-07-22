# MetaMask Vault Decryptor - Visão Geral

## Introdução

O MetaMask Vault Decryptor é uma ferramenta especializada em Python para extrair e descriptografar vaults do MetaMask, permitindo a recuperação de chaves privadas e mnemonics de carteiras criptográficas. Esta implementação é um port da versão JavaScript original, mantendo as mesmas funcionalidades com a flexibilidade da linguagem Python.

## Funcionalidades Principais

### 1. Extração de Vaults

- **Suporte a Múltiplos Formatos**: Processamento de arquivos .log e .ldb
- **Parsing Inteligente**: Extração de dados de vault usando expressões regulares
- **Detecção Automática**: Identificação de padrões de vault em diferentes formatos de armazenamento

### 2. Validação de Vaults

- **Verificação de Estrutura**: Confirmação da presença de campos obrigatórios
- **Validação de Formato**: Garantia de que os dados extraídos são um vault válido
- **Tratamento de Erros**: Identificação e relato de problemas de formato

### 3. Descriptografia Segura

- **Compatibilidade com MetaMask**: Implementação do mesmo algoritmo usado pelo MetaMask
- **Derivação de Chave PBKDF2**: Uso de salt e múltiplas iterações para segurança
- **Criptografia AES-GCM**: Modo de operação autenticado para garantir integridade

### 4. Interface de Linha de Comando

- **Busca Automática**: Localização de arquivos de vault em diretórios especificados
- **Processamento em Lote**: Capacidade de processar múltiplos arquivos de vault
- **Saída Formatada**: Armazenamento de resultados em formato JSON estruturado

## Principais Arquivos e Componentes

### 1. `decryptor.py`

Módulo central que implementa as funcionalidades de extração e descriptografia:

#### Classe Principal
```python
class BrowserPassworder:
    @staticmethod
    def decrypt(password, encrypted_vault_str):
        # Implementação da descriptografia compatível com MetaMask
```

#### Funções Principais
- `extract_vault_from_file(data)`: Extrai dados de vault de diferentes formatos de arquivo
- `is_vault_valid(vault)`: Verifica se um objeto de vault é válido
- `decrypt_vault(password, vault)`: Descriptografa um vault usando a senha fornecida

#### Funções Auxiliares
- `dedupe(arr)`: Remove duplicatas de uma lista de dicionários
- `decode_mnemonic(mnemonic)`: Decodifica uma mnemonic de string ou bytes
- `generate_salt(byte_count)`: Gera uma string aleatória para uso como salt

### 2. `main.py`

Script principal que fornece a interface de linha de comando:

#### Funções Principais
- `find_metamask_vault_dir(base_dir)`: Localiza o diretório de vault do MetaMask
- `find_vault_files(vault_dir)`: Encontra arquivos .log e .ldb no diretório
- `process_vault_file(file_path, password)`: Processa um arquivo de vault
- `main()`: Coordena o processo de busca e descriptografia

## Fluxo de Processamento

1. **Localização de Arquivos**
   - Busca por arquivos .log e .ldb no diretório especificado
   - Identifica arquivos que potencialmente contêm dados de vault

2. **Processamento de Arquivos**
   - Leitura do conteúdo do arquivo (modo binário ou texto)
   - Extração de dados de vault usando expressões regulares
   - Validação da estrutura do vault extraído

3. **Descriptografia**
   - Derivação de chave usando PBKDF2 com a senha fornecida
   - Descriptografia dos dados usando AES-GCM
   - Decodificação de mnemonics para formato legível

4. **Armazenamento de Resultados**
   - Remoção de duplicatas nos dados descriptografados
   - Salvamento dos resultados em um arquivo JSON
   - Exibição de resumo do processo

## Uso da Ferramenta

### Linha de Comando

```bash
python main.py --vault-dir caminho/para/diretorio/vault --password sua_senha --output resultado.json
```

### Argumentos
- `--vault-dir`: Diretório contendo os arquivos de vault (padrão: 'vault')
- `--password`: Senha para descriptografar o vault (obrigatório)
- `--output`: Arquivo de saída para os vaults descriptografados (padrão: 'decrypted_vaults.json')

### Uso Programático

```python
from decryptor import extract_vault_from_file, is_vault_valid, decrypt_vault

# Extrair vault de um arquivo
with open('caminho/para/arquivo', 'r', encoding='utf-8', errors='replace') as f:
    file_content = f.read()
vault = extract_vault_from_file(file_content)

# Verificar se o vault é válido
if is_vault_valid(vault):
    # Descriptografar o vault
    decrypted_data = decrypt_vault("sua_senha", vault)
```

## Considerações Técnicas

- **Tratamento de Erros**: Captura e tratamento de exceções em cada etapa do processo
- **Compatibilidade**: Suporte a diferentes versões do formato de vault do MetaMask
- **Segurança**: Implementação dos mesmos algoritmos criptográficos usados pelo MetaMask
- **Flexibilidade**: Capacidade de processar diferentes formatos de armazenamento

## Conclusão

O MetaMask Vault Decryptor é uma ferramenta eficiente para recuperação de chaves privadas e mnemonics de carteiras MetaMask. Sua implementação em Python oferece uma alternativa flexível e fácil de usar à versão JavaScript original, mantendo todas as funcionalidades essenciais para extração e descriptografia de vaults.
