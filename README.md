# MiniSO - Sistema Operacional Simulado

Este é um sistema operacional simulado que implementa gerenciamento básico de usuários, alocação de memória e execução de comandos com permissões. O projeto utiliza Python e permite operações como cadastro de usuários, login, alocação de memória, criação e exclusão de arquivos e diretórios.

## Funcionalidades

1. **Gerenciamento de Usuários**:
   - Registro de novos usuários com senha hashada e uso de salt.
   - Autenticação de usuários com verificação de senha.

2. **Alocação e Desalocação de Memória**:
   - Simulação de memória usando blocos de 128 bytes.
   - Implementação de algoritmos de alocação: *First Fit*, *Best Fit* e *Worst Fit*.

3. **Execução de Comandos**:
   - Criação e exclusão de arquivos e diretórios com permissões específicas para cada usuário.
   - Suporte a comandos específicos como `listar`, `criar arquivo`, `criar diretorio`, `apagar arquivo` e `apagar diretorio`.

## Estrutura do Projeto

- `USER_DATA_FILE` (`user_data.json`): Arquivo onde são salvos os dados dos usuários e permissões.
- `memory_blocks`: Lista que simula a memória disponível em blocos de 128 bytes.

### Funções Principais

- **Cadastro e Autenticação de Usuários**:
  - `register_user`: Registra um novo usuário com senha hashada.
  - `authenticate_user`: Autentica um usuário já cadastrado.

- **Gerenciamento de Memória**:
  - `allocate_memory`: Aloca blocos de memória usando o algoritmo especificado (*First Fit*, *Best Fit*, ou *Worst Fit*).
  - `deallocate_memory`: Desaloca um bloco de memória.

- **Gerenciamento de Arquivos e Diretórios**:
  - `create_file`: Cria um arquivo e define a permissão de acesso para o usuário que o criou.
  - `delete_file`: Remove um arquivo caso o usuário tenha permissão.
  - `create_directory`: Cria um diretório e define a permissão de acesso.
  - `delete_directory`: Remove um diretório, com a opção de forçar exclusão caso ele contenha arquivos.

- **Execução de Comandos**:
  - `execute_command`: Executa comandos com base na entrada do usuário, como listar, criar e apagar arquivos/diretórios.

## Como Usar

1. **Instalar Dependências**:
   - Não há dependências externas para este projeto, apenas o Python 3.

2. **Executar o Programa**:
   - Execute o script principal:
     ```bash
     python3 nome_do_arquivo.py
     ```
   - Caso nenhum usuário esteja cadastrado, será solicitado o cadastro de um novo usuário.
   - Após autenticar, o usuário pode digitar comandos conforme listado nas funcionalidades.

3. **Comandos Disponíveis**:
   - `listar`: Lista arquivos do diretório atual.
   - `criar arquivo <caminho>`: Cria um arquivo no caminho especificado.
   - `criar diretorio <caminho>`: Cria um diretório no caminho especificado.
   - `apagar arquivo <caminho>`: Apaga um arquivo caso o usuário tenha permissão.
   - `apagar diretorio <caminho> --force`: Apaga um diretório (vazio por padrão ou com o `--force` para diretórios não vazios).

4. **Sair do Sistema**:
   - Digite `sair` para sair do MiniSO.

## Estrutura de Dados

- **`user_data.json`**: Armazena dados de usuários e permissões de acesso para cada arquivo e diretório criado.

## Observações

- Este sistema simula o gerenciamento de memória e permissões de maneira simplificada.
- **Memória**: A memória é dividida em blocos de 128 bytes, e o sistema gerencia a alocação de memória com três algoritmos diferentes.
- **Permissões**: Apenas o usuário que criou um arquivo ou diretório tem permissão para apagá-lo
