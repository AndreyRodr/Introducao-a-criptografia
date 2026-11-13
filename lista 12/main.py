from secrets import token_bytes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

P, Q, G = 23, 11, 2

def validar(y):
    return type(y) is int and 2 <= y <= P - 2 and pow(y, Q, P) == 1

def acordo_auditado(a, b):
    if type(a) is not int or not 1 <= a < Q:
        raise ValueError("Privada de Alice inválida")
    if type(b) is not int or not 1 <= b < Q:
        raise ValueError("Privada de Bob inválida")
    A, B = pow(G, a, P), pow(G, b, P)
    if not validar(A) or not validar(B):
        raise ValueError("Pública inválida")
    return A, B, pow(B, a, P), pow(A, b, P)

assert acordo_auditado(2, 5) == (4, 9, 12, 12)
assert validar(4) is True
assert validar(5) is False
assert validar(True) is False

# Todos os 100 pares possíveis, com checagem da igualdade e do formato.
for a in range(1, 11):
    for b in range(1, 11):
        A, B, sa, sb = acordo_auditado(a, b)
        assert sa == sb
        assert validar(A) and validar(B)

# Três casos de referência calculados independentemente.
assert acordo_auditado(1, 1) == (2, 2, 2, 2)
assert acordo_auditado(2, 5) == (4, 9, 12, 12)
assert acordo_auditado(4, 3) == (16, 8, 2, 2)
print("100 pares de privadas: igualdade e públicas válidas confirmadas.")
print("Três pares de referência: resultados esperados confirmados.")

for y in (-1, 0, 1, 4, 5, 22, 23, True, 2.0):
    print(f"Pública {str(y):>4}: {'aceita' if validar(y) else 'rejeitada'}")

for invalida in (0, 11, -1, True):
    try:
        acordo_auditado(invalida, 5)
    except ValueError:
        print(f"Privada {str(invalida):>4}: ValueError")
    else:
        raise AssertionError("Entrada inválida aceita")
    try:
        acordo_auditado(5, invalida)
    except ValueError:
        pass
    else:
        raise AssertionError("Entrada inválida de Bob aceita")

# Intermediário: Mallory usa u=1 (U=2) e v=2 (V=4).
a, b, u, v = 2, 5, 1, 2
A, B = pow(G, a, P), pow(G, b, P)
U, V = pow(G, u, P), pow(G, v, P)
assert validar(U) and validar(V)
alice, mallory_com_alice = pow(U, a, P), pow(A, u, P)
bob, mallory_com_bob = pow(V, b, P), pow(B, v, P)
assert (alice, mallory_com_alice, bob, mallory_com_bob) == (4, 4, 12, 12)
print("MITM: Alice/Mallory = 4/4; Bob/Mallory = 12/12.")

# Biblioteca: geração X25519, derivação HKDF e rejeição AES-GCM.
priv_a = X25519PrivateKey.generate()
priv_b = X25519PrivateKey.generate()
pub_a = priv_a.public_key()
pub_b = priv_b.public_key()
sa = priv_a.exchange(pub_b)
sb = priv_b.exchange(pub_a)
assert sa == sb and len(sa) == 32

def publica_bytes(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def campo(valor):
    return len(valor).to_bytes(4, "big") + valor

transcript = b"".join(map(campo, (
    b"versao-1", b"Alice", b"Bob",
    publica_bytes(pub_a), publica_bytes(pub_b)
)))
sal = token_bytes(16)
def derivar(segredo, info):
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=sal, info=info
    ).derive(segredo)

contexto = transcript + campo(b"Alice-para-Bob")
chave_a = derivar(sa, contexto)
chave_b = derivar(sb, contexto)
assert chave_a == chave_b
assert chave_a != derivar(sb, transcript + campo(b"Bob-para-Alice"))

nonce = token_bytes(12)
aad = b"sessao-1"
registro = AESGCM(chave_a).encrypt(nonce, b"nota=8.5", aad)
assert len(registro) == 24
assert AESGCM(chave_b).decrypt(nonce, registro, aad) == b"nota=8.5"

def rejeita(chave, cifra, dados):
    try:
        AESGCM(chave).decrypt(nonce, cifra, dados)
    except InvalidTag:
        return True
    return False

alterada = bytes([registro[0] ^ 1]) + registro[1:]
assert rejeita(chave_b, alterada, aad)
assert rejeita(chave_b, registro, b"sessao-2")
assert rejeita(derivar(sb, contexto + b"-alterado"), registro, aad)
assert AESGCM(chave_b).decrypt(nonce, registro, aad) == b"nota=8.5"
print("AES-GCM: alteração da cifra, AAD e contexto rejeitadas.")
print("Reenvio idêntico: etiqueta válida novamente (replay não detectado).")

# Pública X25519 de bytes zero: acordo rejeitado.
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
try:
    priv_a.exchange(X25519PublicKey.from_public_bytes(bytes(32)))
except ValueError:
    print("X25519: pública de bytes zero rejeitada.")
else:
    raise AssertionError("Pública inválida aceita")

print("Todos os testes passaram.")
