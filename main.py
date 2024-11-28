import os
import hashlib
import random
import string
import getpass
import shutil

USER_DATA_FILE = 'user_data.txt'
PERMISSIONS_FILE = 'permissions.txt'
OPERATIONS_LOG_FILE = 'operations_log.txt'
USERS_DIR = 'users'  # Diretório principal onde os diretórios dos usuários serão criados

# Função para carregar dados de usuários
def load_user_data():
    user_data = {"users": {}}
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("{"):
                    parts = line.split('$')
                    if len(parts) == 4:
                        username = parts[0]
                        algorithm = parts[1]  # O algoritmo será sempre "6" para SHA-512
                        salt = parts[2]
                        password_hash = parts[3]
                        user_data["users"][username] = {"algorithm": algorithm, "salt": salt, "password_hash": password_hash}
    return user_data

# Função para salvar dados de usuários
def save_user_data(user_data):
    with open(USER_DATA_FILE, 'w') as file:
        for username, data in user_data["users"].items():
            file.write(f"{username}${data['algorithm']}${data['salt']}${data['password_hash']}\n")

# Função para carregar permissões
def load_permissions():
    permissions = {}
    if os.path.exists(PERMISSIONS_FILE):
        with open(PERMISSIONS_FILE, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    path, user = line.split(':')
                    permissions[path] = user
    return permissions

# Função para salvar permissões
def save_permissions(permissions):
    with open(PERMISSIONS_FILE, 'w') as file:
        for path, user in permissions.items():
            file.write(f"{path}:{user}\n")

# Função para criar diretório para o usuário
def create_user_directory(username):
    user_dir = os.path.join(USERS_DIR, username)
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    return user_dir

# Função para registrar um novo usuário
def register_user():
    username = input("Digite o nome de usuário: ")
    password = get_password()
    if password is None or len(password) == 0:
        print("A senha não pode ser vazia!")
        return
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    user_data = load_user_data()
    
    # Define o algoritmo como "6" para SHA-512
    user_data["users"][username] = {"algorithm": "6", "salt": salt, "password_hash": password_hash}
    save_user_data(user_data)
    
    # Cria diretório exclusivo para o usuário
    create_user_directory(username)
    
    log_operation(f"Usuário '{username}' criado com sucesso.")
    print(f"Usuário '{username}' criado com sucesso.")

# Função para autenticar o usuário
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

# Função para obter a senha de forma segura
def get_password():
    return getpass.getpass("Digite a senha: ")

# Função para gerar um salt aleatório
def generate_salt():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

# Função para gerar o hash da senha
def hash_password(password, salt):
    return hashlib.sha512((password + salt).encode()).hexdigest()

# Função para criar um diretório dentro do diretório do usuário
def create_directory(path, username):
    user_dir = os.path.join(USERS_DIR, username)
    dir_path = os.path.join(user_dir, path)
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
        permissions = load_permissions()
        permissions[dir_path] = username  # Salva permissão para o diretório
        save_permissions(permissions)
        log_operation(f"Diretório '{dir_path}' criado por {username}")
        print(f"Diretório '{dir_path}' criado por {username}")
    else:
        print(f"Erro: O diretório '{dir_path}' já existe.")

# Função para criar um arquivo dentro do diretório do usuário
def create_file(path, username):
    user_dir = os.path.join(USERS_DIR, username)
    file_path = os.path.join(user_dir, path)
    
    directory, filename = os.path.split(file_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    
    with open(file_path, 'w') as file:
        file.write("Conteúdo aleatório")
    
    permissions = load_permissions()
    # Salvar permissão do arquivo criado para o usuário
    permissions[file_path] = username
    save_permissions(permissions)
    log_operation(f"Arquivo '{file_path}' criado por {username}")
    print(f"Arquivo '{file_path}' criado por {username}")

# Função para deletar um arquivo dentro do diretório do usuário
def delete_file(path, username):
    user_dir = os.path.join(USERS_DIR, username)
    file_path = os.path.join(user_dir, path)
    
    permissions = load_permissions()
    if permissions.get(file_path) != username:
        print("Erro: Você não tem permissão para apagar este arquivo.")
        log_operation(f"Erro: {username} tentou apagar arquivo sem permissão: {file_path}")
        return
    if os.path.exists(file_path):
        os.remove(file_path)
        del permissions[file_path]
        save_permissions(permissions)
        log_operation(f"Arquivo '{file_path}' apagado por {username}")
        print(f"Arquivo '{file_path}' apagado.")
    else:
        print("Erro: Arquivo não encontrado.")

# Função para deletar diretório dentro do diretório do usuário
def delete_directory(path, username, force=False):
    user_dir = os.path.join(USERS_DIR, username)
    dir_path = os.path.join(user_dir, path)
    
    permissions = load_permissions()

    if not os.path.exists(dir_path):
        print(f"Erro: O diretório '{dir_path}' não existe.")
        return

    if permissions.get(dir_path) != username:
        print("Erro: Você não tem permissão para apagar este diretório.")
        log_operation(f"Erro: {username} tentou apagar diretório sem permissão: {dir_path}")
        return

    if os.path.exists(dir_path):
        if force:
            # Força a remoção do diretório e seus arquivos
            shutil.rmtree(dir_path)
            del permissions[dir_path]  # Remove a permissão associada
            save_permissions(permissions)
            log_operation(f"Diretório '{dir_path}' apagado com force por {username}")
            print(f"Diretório '{dir_path}' apagado com force.")
        else:
            try:
                os.rmdir(dir_path)
                del permissions[dir_path]
                save_permissions(permissions)
                log_operation(f"Diretório '{dir_path}' apagado por {username}")
                print(f"Diretório '{dir_path}' apagado.")
            except OSError:
                print("Erro: O diretório não está vazio. Use '--force' para apagar.")
                return
    else:
        print("Erro: Diretório não encontrado.")

# Função para listar arquivos no diretório do usuário
def list_files(path, username):
    user_dir = os.path.join(USERS_DIR, username)
    full_path = os.path.join(user_dir, path)
    
    if os.path.exists(full_path):
        print(f"Conteúdo de {full_path}:")
        for item in os.listdir(full_path):
            item_path = os.path.join(full_path, item)
            if os.path.exists(item_path) and load_permissions().get(item_path) == username:
                print(item)
    else:
        print(f"Erro: Diretório {full_path} não encontrado.")

# Função para logar operações
def log_operation(operation):
    with open(OPERATIONS_LOG_FILE, 'a') as log_file:
        log_file.write(f"{operation}\n")

# Função para executar comandos no sistema
def execute_command(command, username):
    if command.startswith("listar"):
        args = command.split()
        path = args[1] if len(args) > 1 else ''  # Pega o diretório fornecido, ou vazio
        list_files(path, username)
    elif command.startswith("criar arquivo"):
        args = command.split()
        path = args[2]
        create_file(path, username)
    elif command.startswith("criar diretorio"):
        args = command.split()
        path = args[2]
        create_directory(path, username)
    elif command.startswith("apagar arquivo"):
        args = command.split()
        path = args[2]
        delete_file(path, username)
    elif command.startswith("apagar diretorio"):
        args = command.split()
        path = args[2]
        force = "--force" in args
        delete_directory(path, username, force)
    else:
        print("Comando desconhecido.")

# Função principal
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
        execute_command(command, user)

if __name__ == "__main__":
    main()
