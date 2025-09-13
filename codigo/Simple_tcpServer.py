from socket import *
import json, os, secrets, math, time, random

# ---------------- Funções auxiliares ----------------
def egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Não existe inverso modular")
    return x % m

# ---------------- PrimoHyper (Miller-Rabin rápido) ----------------
def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small:
        return True
    for p in small:
        if n % p == 0:
            return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    def witness(a: int) -> bool:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                return True
        return False

    if n < (1 << 64):
        bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    else:
        k = 12
        bases = [random.randrange(2, n - 2) for _ in range(k)]

    for a in bases:
        a %= n
        if a == 0: continue
        if not witness(a):
            return False
    return True

def gen_prime(bits=4096):
    while True:
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1)) | 1  # força 4096 bits e ímpar
        if is_probable_prime(n):
            return n

# ---------------- RSA ----------------
def generate_keypair(bits=4096, e=65537):
    half = bits // 2

    print("Gerando p...")
    t0 = time.perf_counter()
    p = gen_prime(half)
    print(f"Primo p gerado ({half} bits) em {time.perf_counter()-t0:.2f} segundos")

    print("Gerando q...")
    t1 = time.perf_counter()
    q = gen_prime(half)
    print(f"Primo q gerado ({half} bits) em {time.perf_counter()-t1:.2f} segundos")

    n = p * q
    phi = (p-1)*(q-1)
    d = modinv(e, phi)
    return (n, e, d)

def rsa_encrypt(msg: str, e: int, n: int) -> int:
    m = int.from_bytes(msg.encode(), "big")
    return pow(m, e, n)

def rsa_decrypt(cipher: int, d: int, n: int) -> str:
    m = pow(cipher, d, n)
    return m.to_bytes((m.bit_length()+7)//8, "big").decode()

# ---------------- Servidor ----------------
serverPort = 1300

# Gera ou carrega chaves
if os.path.exists("server_keys.json"):
    with open("server_keys.json") as f:
        data = json.load(f)
        n, e, d = int(data["n"]), int(data["e"]), int(data["d"])
else:
    print("Gerando chaves RSA 4096 bits... (pode demorar vários minutos)")
    n, e, d = generate_keypair(4096)
    with open("server_keys.json","w") as f:
        json.dump({"n":str(n),"e":str(e),"d":str(d)}, f)

serverSocket = socket(AF_INET,SOCK_STREAM)
serverSocket.bind(("",serverPort))
serverSocket.listen(5)
print("Servidor TCP com RSA rodando na porta", serverPort)

connectionSocket, addr = serverSocket.accept()
print("Conexão de:", addr)

# Envia chave pública do servidor
connectionSocket.send(json.dumps({"n":str(n),"e":str(e)}).encode())

# Recebe chave pública do cliente
client_pub = json.loads(connectionSocket.recv(65000).decode())
client_n, client_e = int(client_pub["n"]), int(client_pub["e"])

# Recebe mensagem cifrada
cipher = int(connectionSocket.recv(65000).decode())
msg = rsa_decrypt(cipher, d, n)
print("Mensagem recebida (decriptada):", msg)

# Processa e responde
reply = msg.upper()
cipher_reply = rsa_encrypt(reply, client_e, client_n)
connectionSocket.send(str(cipher_reply).encode())
print("Resposta enviada (cifrada).")

connectionSocket.close()
