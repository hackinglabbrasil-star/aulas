import hashlib

hash_cadastro = None


def criar_hash(frase: str) -> str:
    """Devolve uma hash criptografica a partir de uma palavra recebida

    Args:
        frase str: A senha que a pessoa digitou

    Returns:
        str: Hash calculada
    """
    hash_obj = hashlib.sha256(frase.encode())
    hash_senha = hash_obj.hexdigest()
    print(f"Hash gerada: {hash_senha}")
    return hash_senha


def criar_usuario() -> str:
    """Cria o cadastro simulado do usuário

    Returns:
        str: Hash do usuario cadastrado
    """
    global hash_cadastro
    senha = input("Qual sua senha: ")
    senha = f"{senha}hackinglab"
    hash_cadastro = criar_hash(senha)
    print(hash_cadastro)
    return hash_cadastro


def login(hash_cadastro: str) -> bool:
    """Realiza o login do usuario

    Args:
        hash_cadastro (str): Hash de cadastro do usuario

    Returns:
        bool: Resultado do usuario
    """

    senha = input("Digite sua senha")
    senha = f"{senha}hackinglab"
    hash_senha = criar_hash(senha)
    print(hash_senha)
    if hash_senha == hash_cadastro:
        print("Senha correta")
        return True
    else:
        print("Senha incorreta")
        return False


if __name__ == "__main__":
    """Roda um cadastro simples"""
    cadastro = criar_usuario()
    login(cadastro)
