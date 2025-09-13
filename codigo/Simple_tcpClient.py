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

# ---------------- PrimoHyper ----------------
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
        n |= (1 << (bits - 1)) | 1
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

# ---------------- Cliente ----------------
serverName = "10.1.70.33"
serverPort = 1300

# Gera ou carrega chaves
if os.path.exists("client_keys.json"):
    with open("client_keys.json") as f:
        data = json.load(f)
        n, e, d = int(data["n"]), int(data["e"]), int(data["d"])
else:
    print("Gerando chaves RSA 4096 bits... (pode demorar vários minutos)")
    n, e, d = generate_keypair(4096)
    with open("client_keys.json","w") as f:
        json.dump({"n":str(n),"e":str(e),"d":str(d)}, f)

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverName,serverPort))

# Recebe chave pública do servidor
server_pub = json.loads(clientSocket.recv(65000).decode())
server_n, server_e = int(server_pub["n"]), int(server_pub["e"])

# Envia chave pública do cliente
clientSocket.send(json.dumps({"n":str(n),"e":str(e)}).encode())

# Envia mensagem
sentence = input("Digite uma mensagem: ")
cipher = rsa_encrypt(sentence, server_e, server_n)
clientSocket.send(str(cipher).encode())

# Recebe resposta cifrada
cipher_reply = int(clientSocket.recv(65000).decode())
reply = rsa_decrypt(cipher_reply, d, n)
print("Resposta do servidor (decriptada):", reply)

clientSocket.close()
