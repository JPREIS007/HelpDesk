# HelpDesk
Projeto da disciplina de APS


# Sistema HelpDesk: Registro e Acompanhamento de Ocorrências/Chamados

## Descrição
Este projeto implementa um sistema especializado para registro, acompanhamento e resolução de chamados técnicos, comerciais e financeiros em provedores de internet. O sistema centraliza o ciclo de vida do chamado, desde o registro pelo cliente até a resolução final, oferecendo ferramentas robustas para equipes de atendimento. Sua arquitetura foi projetada para escalabilidade, segurança e desempenho, com controle de acesso granular, criptografia de dados e logs de auditoria imutáveis.

## Objetivos
- **Geral**: Desenvolver um sistema integrado para otimizar o fluxo de atendimento, priorizar chamados inteligentemente e garantir rastreabilidade completa.
- **Específicos**:
  - Módulo de registro e classificação automática de prioridade.
  - Gestão de filas e atribuição dinâmica de chamados.
  - Ciclo de vida completo do chamado com reabertura garantida.
  - Segurança com RBAC e logs de auditoria imutáveis.
  - Simulação de atendimento concorrente com threads.

## Tecnologias Utilizadas
- **Backend**: Python + Flask
- **Banco de Dados**: SQLite (`helpdesk.db`)
- **Frontend**: HTML/CSS (Templates Jinja2)
- **Gerenciamento de Dependências**: Pipenv
- **Controle de Versão**: Git/GitHub

## Estrutura do Projeto
```
provedor-funcionando/
├── app.py                # Arquivo principal da aplicação Flask
├── helpdesk.db           # Banco de dados SQLite
├── Pipfile               # Gerenciador de dependências Pipenv
├── Pipfile.lock          # Lockfile do Pipenv
├── requirements.txt      # Requisitos do projeto (opcional)
└── templates/            # Templates HTML para as páginas
    ├── base.html
    ├── cadastro.html
    ├── dashboard.html
    ├── gerenciar_usuarios.html
    ├── index.html
    ├── login.html
    ├── logs_auditoria.html
    ├── novo_chamado.html
    ├── recuperar_senha.html
    ├── redefinir_senha.html
    ├── relatorios.html
    ├── simular_atendimento.html
    └── visualizar_chamado.html
```

## Funcionalidades Principais
1. **Autenticação e Perfil**:
   - Login seguro para clientes, atendentes e administradores.
   - Cadastro de usuários com diferentes perfis (cliente, atendente, técnico, administrador).

2. **Gestão de Chamados**:
   - Registro de chamados com título, descrição, tipo de problema e anexos.
   - Classificação automática de prioridade baseada em impacto e urgência.
   - Atribuição manual ou automática de chamados a atendentes/técnicos.
   - Fluxo de status do chamado (Aberto → Em Atendimento → Resolvido → Fechado).

3. **Auditoria e Segurança**:
   - Logs imutáveis de todas as ações realizadas no sistema.
   - Controle de acesso baseado em roles (RBAC).
   - Senhas armazenadas com criptografia forte (bcrypt/argon2).

4. **Relatórios e Dashboards**:
   - Geração de relatórios com métricas de desempenho (tempo médio de resolução, volume de chamados).
   - Visualização de dashboards com indicadores-chave.

5. **Simulação de Atendimento**:
   - Módulo para simular múltiplos atendimentos concorrentes usando threads.

## Como Executar o Projeto
1. **Clone o repositório**:
   ```bash
   git clone https://github.com/seu-usuario/provedor-funcionando.git
   cd provedor-funcionando
   ```

2. **Instale as dependências**:
   ```bash
   pip install pipenv
   pipenv install
   ```

3. **Inicie o servidor**:
   ```bash
   pipenv run python app.py
   ```

4. **Acesse a aplicação**:
   - Abra o navegador e visite `http://localhost:5000`.

## Contribuidores
- Ana Cristina Nunes da Silva
- Carlos Eduardo Carvalho Hermogenes
- João Paulo dos Reis Silva
- Luis Henrique Aquino de Carvalho
- Marcos André da Silva Santos
- Talyson Tawan Germano da Silva
- Wanderson Luiz Duarte dos Santos

## Licença
Trabalho acadêmico apresentado como requisito parcial para obtenção de nota na disciplina LIC.0169 – Análise e Projetos de Sistemas da Informação, pertencente ao 5º semestre do curso de Licenciatura em Ciências da Computação.  
Professor responsável: Filipe Adeodato Garrido.
