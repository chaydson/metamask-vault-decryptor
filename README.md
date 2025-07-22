# metamask-vault-decryptor

Uma ferramenta para extrair e descriptografar vaults do MetaMask.

## Implementação Python

Esta implementação em Python é um port da versão JavaScript original, fornecendo as mesmas funcionalidades:

- Extração de vaults de diferentes formatos de arquivo (.log e .ldb)
- Validação de vaults
- Descriptografia de vaults usando senha
- Busca automática por arquivos de vault do MetaMask

## Estrutura do Projeto

- `decryptor.py`: Contém as funções principais para extração, validação e descriptografia de vaults
- `main.py`: Script principal para buscar e processar arquivos de vault do MetaMask

## Requisitos

```
pip install -r requirements.txt
```

## Como usar

### Método 1: Usando o script principal

Execute o script `main.py` para buscar e descriptografar automaticamente os vaults do MetaMask:

```bash
python main.py --vault-dir caminho/para/diretorio/vault --password sua_senha --output resultado.json
```

Argumentos:
- `--vault-dir`: Diretório base contendo os arquivos de vault do MetaMask (padrão: 'vault')
- `--password`: Senha para descriptografar o vault
- `--output`: Arquivo de saída para os vaults descriptografados (padrão: 'decrypted_vaults.json')

### Método 2: Importando as funções

Você também pode importar as funções diretamente em seu código:

```python
from decryptor import extract_vault_from_file, is_vault_valid, decrypt_vault
```

#### Extraindo um vault de um arquivo

```python
with open('caminho/para/arquivo', 'r', encoding='utf-8', errors='replace') as f:
    file_content = f.read()

vault = extract_vault_from_file(file_content)
```

#### Verificando se um vault é válido

```python
if is_vault_valid(vault):
    print("Vault válido!")
else:
    print("Vault inválido!")
```

#### Descriptografando um vault

```python
decrypted_data = decrypt_vault("sua_senha", vault)
```

## Exemplos de uso

### Exemplo 1: Busca automática

```bash
# Busca e descriptografa vaults no diretório padrão 'vault'
python main.py --password minhasenha
```

### Exemplo 2: Especificando o diretório de busca

```bash
# Busca e descriptografa vaults em um diretório específico
python main.py --vault-dir ~/.config/google-chrome/Default/Local\ Extension\ Settings --password minhasenha
```

### Exemplo 3: Salvando em um arquivo específico

```bash
# Salva os resultados em um arquivo específico
python main.py --password minhasenha --output meus_vaults.json
```
