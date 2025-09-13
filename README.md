# 🔐 Comunicação Cliente-Servidor com RSA (4096 bits)

Este projeto implementa um sistema de comunicação **TCP Cliente-Servidor** em Python, utilizando o algoritmo **RSA de 4096 bits** para criptografia e decriptação das mensagens trocadas.  

A troca de mensagens é feita de forma segura:  
- O **servidor** gera (ou carrega de arquivo) um par de chaves RSA.  
- O **cliente** também gera (ou carrega de arquivo) suas próprias chaves.  
- Ambos compartilham suas **chaves públicas** entre si.  
- As mensagens enviadas são **cifradas** com a chave pública do destinatário e só podem ser **decifradas** pela chave privada correspondente.  

---

## 👥 Integrantes do Grupo

- **João Antônio de Brito Moraes** – RA: 081210028
- **Lucas Araujo dos Santos** – RA: 081210009  
- **Natthalie Bohm** – RA: 081210001  
- **Renan Cesar de Araujo** – RA: 081210033

---

## 📂 Estrutura dos Arquivos

- `Simple_tcpServer.py` → Código do servidor TCP com RSA.  
- `Simple_tcpClient.py` → Código do cliente TCP com RSA.  
- `server_keys.json` → Arquivo gerado automaticamente para armazenar as chaves do servidor.  
- `client_keys.json` → Arquivo gerado automaticamente para armazenar as chaves do cliente.  

---

## ⚙️ Funcionamento

### 🔸 Servidor (`Simple_tcpServer.py`)
1. Gera ou carrega suas **chaves RSA** (4096 bits).  
2. Aguarda uma conexão do cliente na porta `1300`.  
3. Envia sua **chave pública** para o cliente.  
4. Recebe a **chave pública do cliente**.  
5. Recebe uma **mensagem criptografada** do cliente e a **decifra** usando sua chave privada.  
6. Processa a mensagem (transforma em **maiúsculo**).  
7. Criptografa a resposta com a **chave pública do cliente** e envia de volta.  

### 🔸 Cliente (`Simple_tcpClient.py`)
1. Gera ou carrega suas **chaves RSA** (4096 bits).  
2. Conecta-se ao servidor (IP e porta configuráveis).  
3. Recebe a **chave pública do servidor**.  
4. Envia sua **chave pública** para o servidor.  
5. Solicita uma mensagem ao usuário.  
6. **Criptografa a mensagem** com a chave pública do servidor e envia.  
7. Recebe a resposta **criptografada** do servidor.  
8. **Decifra** a resposta com sua chave privada e exibe no terminal.  

---

## 🔑 Geração de Chaves RSA

As chaves RSA são geradas com **4096 bits** utilizando:  
- **Teste de primalidade Miller-Rabin** (implementado em `is_probable_prime`).  
- Dois primos grandes `p` e `q` → cálculo de `n = p*q` e `φ(n)`.  
- Exponencial pública `e = 65537` (padrão).  
- Cálculo do inverso modular para obter `d` (chave privada).  

Para evitar recomputar chaves a cada execução:  
- O servidor armazena suas chaves em `server_keys.json`.  
- O cliente armazena suas chaves em `client_keys.json`.  

---

## 📡 Fluxo de Comunicação

```mermaid
sequenceDiagram
    participant Cliente
    participant Servidor

    Cliente->>Servidor: Conexão TCP (porta 1300)
    Servidor->>Cliente: Envia chave pública (n, e)
    Cliente->>Servidor: Envia chave pública (n, e)
    Cliente->>Servidor: Mensagem criptografada
    Servidor->>Servidor: Decripta com chave privada
    Servidor->>Servidor: Converte mensagem para MAIÚSCULO
    Servidor->>Cliente: Resposta criptografada
    Cliente->>Cliente: Decripta resposta
