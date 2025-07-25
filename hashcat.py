import json

def generate_hashcat_hashes(input_file):
    """
    Lê um arquivo JSON de vaults e retorna uma lista de hashes no formato do Hashcat para Metamask.
    """
    with open(input_file, 'r', encoding='utf-8') as f:
        vaults = json.load(f)

    hashes = []
    for entry in vaults:
        vault = entry.get('vault', {})
        salt = vault.get('salt')
        iv = vault.get('iv')
        data = vault.get('data')
        if salt and iv and data:
            hashcat_hash = f"$metamask${salt}${iv}${data}"
            hashes.append(hashcat_hash)
    return hashes 