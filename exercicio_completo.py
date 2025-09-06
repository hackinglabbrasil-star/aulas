import hashlib
import sqlite3


"""""" """
Esse códgio é a resolução do exercício da aula de 06/09/2025 HackingLab
O objetivo desse exercício é compreender o funcionamento de hashes 
e como elas são armazenadas em um banco de dados. 

TENTE CONSTRUIR SEU PRÒPRIO SISTEMA UTILIZE ESSE APENAS COMO EXEMPLO
""" """"""

# Conecta ao banco de dados (ou cria se não existir)
conn = sqlite3.connect("usuarios.db")
cursor = conn.cursor()

# Cria a tabela de usuários se não existir
cursor.execute(
    """
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE NOT NULL,
    senha_hash TEXT NOT NULL
)
"""
)
conn.commit()


def criar_hash(frase: str) -> str:
    """Devolve uma hash criptográfica a partir de uma senha"""
    hash_obj = hashlib.sha256(frase.encode())
    hash_senha = hash_obj.hexdigest()
    print(f"Hash da senha inserida: {hash_senha}")
    return hash_senha


def criar_usuario():
    """Cria o cadastro de um usuário e salva no banco de dados"""
    usuario = input("Digite seu nome de usuário: ").strip()
    senha = input("Digite sua senha: ").strip()
    senha_com_salt = f"{senha}hackinglab"
    hash_senha = criar_hash(senha_com_salt)

    try:
        cursor.execute(
            "INSERT INTO usuarios (usuario, senha_hash) VALUES (?, ?)",
            (usuario, hash_senha),
        )
        conn.commit()
        print(f"Usuário '{usuario}' cadastrado com sucesso!")
    except sqlite3.IntegrityError:
        print("Erro: Usuário já existe!")


def login():
    """Realiza o login do usuário usando o banco de dados"""
    usuario = input("Digite seu nome de usuário: ").strip()
    senha = input("Digite sua senha: ").strip()
    senha_com_salt = f"{senha}hackinglab"
    hash_senha = criar_hash(senha_com_salt)

    cursor.execute("SELECT senha_hash FROM usuarios WHERE usuario = ?", (usuario,))
    resultado = cursor.fetchone()

    if resultado and resultado[0] == hash_senha:
        print("Login bem-sucedido!")
        return True
    else:
        print("Usuário ou senha incorretos.")
        return False


if __name__ == "__main__":
    while True:
        print("\n1 - Criar usuário\n2 - Login\n3 - Sair")
        escolha = input("Escolha uma opção: ").strip()
        if escolha == "1":
            criar_usuario()
        elif escolha == "2":
            login()
        elif escolha == "3":
            break
        else:
            print("Opção inválida!")
