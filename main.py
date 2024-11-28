import os
import subprocess
import hashlib
import random
import string
import json
import time
import platform
import getpass

USER_DATA_FILE = 'user_data.json'
OPERATIONS_LOG_FILE = 'operations_log.txt'

# Configuração da memória (simulação)
MEMORY_SIZE = 1024  # Total de memória disponível
memory_blocks = [{"size": 128, "free": True} for _ in range(MEMORY_SIZE // 128)]  # Dividir em blocos de 128


# Carregar dados de usuários
def load_user_data():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'r') as file:
            return json.load(file)
    else:
        return {"users": {}, "permissions": {}}


# Salvar dados de usuários
def save_user_data(data):
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(data, file)


# Log de operações
def log_operation(operation):
    with open(OPERATIONS_LOG_FILE, 'a') as log_file:
        log_file.write(f"{operation}\n")


def generate_salt():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))


def hash_password(password, salt):
    return hashlib.sha512((password + salt).encode()).hexdigest()


def get_password():
    # Obtém a senha de forma oculta no terminal
    password = getpass.getpass("Digite a senha: ")
    return password


def register_user():
    username = input("Digite o nome de usuário: ")
    password = get_password()
    if password is None or len(password) == 0:
        print("A senha não pode ser vazia!")
        return
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    user_data = load_user_data()
    user_data["users"][username] = {"salt": salt, "password_hash": password_hash}
    save_user_data(user_data)
    log_operation(f"Usuário '{username}' criado com sucesso.")
    print(f"Usuário '{username}' criado com sucesso.")


def authenticate_user():
    user_data = load_user_data()
    username = input("Digite o nome de usuário: ")
    if username not in user_data["users"]:
        print("Usuário não encontrado!")
        return None
    password = get_password()
    salt = user_data["users"][username]["salt"]
    password_hash = hash_password(password, salt)
    if password_hash == user_data["users"][username]["password_hash"]:
        print("Login realizado com sucesso!")
        log_operation(f"Usuário '{username}' fez login com sucesso.")
        return username
    else:
        print("Senha incorreta!")
        return None


# Funções de alocação de memória
def allocate_memory(size, algorithm="first_fit"):
    global memory_blocks
    if algorithm == "first_fit":
        for block in memory_blocks:
            if block["free"] and block["size"] >= size:
                block["free"] = False
                return True
    elif algorithm == "best_fit":
        best_block = None
        for block in memory_blocks:
            if block["free"] and block["size"] >= size:
                if best_block is None or block["size"] < best_block["size"]:
                    best_block = block
        if best_block:
            best_block["free"] = False
            return True
    elif algorithm == "worst_fit":
        worst_block = None
        for block in memory_blocks:
            if block["free"] and block["size"] >= size:
                if worst_block is None or block["size"] > worst_block["size"]:
                    worst_block = block
        if worst_block:
            worst_block["free"] = False
            return True
    return False


def deallocate_memory(size):
    global memory_blocks
    for block in memory_blocks:
        if not block["free"] and block["size"] == size:
            block["free"] = True
            return


# Função para execução de comando em novo processo
def execute_command(command, username, memory_algorithm="first_fit"):
    pid = os.getpid()
    print(f"[PID {pid}] Executando: {command}")
    log_operation(f"[PID {pid}] Executando comando: {command}")

    # Alocar memória para o processo
    if not allocate_memory(128, algorithm=memory_algorithm):
        print("Erro: Falha ao alocar memória para o processo.")
        log_operation(f"Erro: Falha ao alocar memória para o comando: {command}")
        return

    # Simula a execução do comando
    if command.startswith("listar"):
        args = command.split()
        path = args[1] if len(args) > 1 else "."
        list_files(path, username)
    elif command.startswith("criar arquivo"):
        args = command.split()
        path = args[2]
        create_file(path, username)
    elif command.startswith("apagar arquivo"):
        args = command.split()
        path = args[2]
        delete_file(path, username)
    elif command.startswith("criar diretorio"):
        args = command.split()
        path = args[2]
        create_directory(path, username)
    elif command.startswith("apagar diretorio"):
        args = command.split()
        path = args[2]
        force = "--force" in args
        delete_directory(path, username, force)

    # Desaloca a memória após a execução do comando
    deallocate_memory(128)
    print(f"[PID {pid}] Processo concluído.")


def list_files(path, username):
    user_data = load_user_data()
    user_permissions = user_data["permissions"]

    # Verifica se o caminho dado existe, e se não, faz ele ser o diretório atual (.)
    if not os.path.exists(path):
        print(f"Erro: O diretório '{path}' não existe.")
        return
    
    # Lista apenas arquivos e diretórios que o usuário tem permissão para acessar
    files = []
    for file in os.listdir(path):
        full_path = os.path.join(path, file)
        if full_path in user_permissions and user_permissions[full_path] == username:
            files.append(file)

    if files:
        print("Arquivos e diretórios criados por você:")
        for file in files:
            print(file)
    else:
        print("Nenhum arquivo ou diretório criado por você.")


def create_file(path, username):
    directory, filename = os.path.split(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, 'w') as file:
        file.write("Conteúdo aleatório")
    user_data = load_user_data()
    user_data["permissions"][path] = username
    save_user_data(user_data)
    log_operation(f"Arquivo '{path}' criado por {username}")
    print(f"Arquivo '{path}' criado por {username}")


def delete_file(path, username):
    user_data = load_user_data()
    if user_data["permissions"].get(path) != username:
        print("Erro: Você não tem permissão para apagar este arquivo.")
        log_operation(f"Erro: {username} tentou apagar arquivo sem permissão: {path}")
        return
    if os.path.exists(path):
        os.remove(path)
        del user_data["permissions"][path]
        save_user_data(user_data)
        log_operation(f"Arquivo '{path}' apagado por {username}")
        print(f"Arquivo '{path}' apagado.")
    else:
        print("Erro: Arquivo não encontrado.")


def create_directory(path, username):
    os.makedirs(path, exist_ok=True)
    user_data = load_user_data()
    user_data["permissions"][path] = username
    save_user_data(user_data)
    log_operation(f"Diretório '{path}' criado por {username}")
    print(f"Diretório '{path}' criado por {username}")


def delete_directory(path, username, force=False):
    user_data = load_user_data()

    if not os.path.exists(path):
        print(f"Erro: O diretório '{path}' não existe.")
        return

    if user_data["permissions"].get(path) != username:
        print("Erro: Você não tem permissão para apagar este diretório.")
        log_operation(f"Erro: {username} tentou apagar diretório sem permissão: {path}")
        return
    if os.path.exists(path):
        if force:
            if platform.system() == "Windows":
                os.system(f"rmdir /S /Q {path}")
            else:
                os.system(f"rm -rf {path}")
        else:
            try:
                os.rmdir(path)
            except OSError:
                print("Erro: O diretório não está vazio. Use '--force' para apagar.")
                return
        del user_data["permissions"][path]
        save_user_data(user_data)
        log_operation(f"Diretório '{path}' apagado por {username}")
        print(f"Diretório '{path}' apagado.")
    else:
        print("Erro: Diretório não encontrado.")


def main():
    user_data = load_user_data()

    if not user_data["users"]:
        print("Nenhum usuário cadastrado. Crie um novo usuário.\n")
        register_user()

    while True:
        create_new_user = input("Deseja criar um novo usuário? (s/n): ").lower()
        if create_new_user == 's':
            register_user()
            break
        elif create_new_user == 'n':
            break
        else:
            print("Opção inválida, por favor escolha 's' para sim ou 'n' para não.")

    user = None
    while not user:
        user = authenticate_user()

    while True:
        command = input(f"{user}@MiniSO$ ")
        if command.lower() == "sair":
            print("Saindo do MiniSO.")
            break
        execute_command(command, user, memory_algorithm="first_fit")


if __name__ == "__main__":
    main()
