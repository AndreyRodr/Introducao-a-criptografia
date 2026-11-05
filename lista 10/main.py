import secrets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
 
def derivar(segredo, sal, contexto):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=sal, info=contexto).derive(segredo)
 
a = X25519PrivateKey.generate()
b = X25519PrivateKey.generate()
m = X25519PrivateKey.generate()
sa = a.exchange(b.public_key())
sb = b.exchange(a.public_key())
assert len(sa) == len(sb) == 32 and sa == sb
for privada in (a, b, m):
    publica = privada.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    assert len(publica) == 32
print("1. Acordo correto: segredos iguais (32 bytes); públicas de 32 bytes.")
 
sal = secrets.token_bytes(16)
contexto = b"encontro10|arquivo|alice-bob"
ka = derivar(sa, sal, contexto)
kb = derivar(sb, sal, contexto)
assert ka == kb
mensagem = b"nota=8.5"
nonce = secrets.token_bytes(12)
aad = b"atividade11"
pacote = AESGCM(ka).encrypt(nonce, mensagem, aad)
assert AESGCM(kb).decrypt(nonce, pacote, aad) == mensagem
print("2. HKDF igual; AES-GCM recuperou:", mensagem.decode())
 
sa_m = a.exchange(m.public_key())
sm_a = m.exchange(a.public_key())
ka_m = derivar(sa_m, sal, contexto)
km_a = derivar(sm_a, sal, contexto)
assert ka_m == km_a and ka_m != kb
pacote_errado = AESGCM(ka_m).encrypt(nonce, mensagem, aad)
assert AESGCM(km_a).decrypt(nonce, pacote_errado, aad) == mensagem
try:
    AESGCM(kb).decrypt(nonce, pacote_errado, aad)
    raise AssertionError("Bob deveria rejeitar")
except InvalidTag:
    print("3. Pública trocada: Mallory abriu; Bob rejeitou (InvalidTag).")
 
sb_m = b.exchange(m.public_key())
sm_b = m.exchange(b.public_key())
kb_m = derivar(sb_m, sal, contexto)
km_b = derivar(sm_b, sal, contexto)
assert kb_m == km_b and km_b != km_a
recebido = AESGCM(km_a).decrypt(nonce, pacote_errado, aad)
nonce2 = secrets.token_bytes(12)
pacote_para_bob = AESGCM(km_b).encrypt(nonce2, recebido, aad)
assert AESGCM(kb_m).decrypt(nonce2, pacote_para_bob, aad) == mensagem
print("4. Duas conexões: Mallory abriu e recifrou; chaves diferentes.")
 
alterado = bytearray(pacote)
alterado[0] ^= 1
try:
    AESGCM(kb).decrypt(nonce, bytes(alterado), aad)
    raise AssertionError("Alteração deveria falhar")
except InvalidTag:
    print("5. Pacote alterado: InvalidTag.")
 
k_contexto = derivar(sb, sal, b"outro-contexto")
assert k_contexto != ka
try:
    AESGCM(k_contexto).decrypt(nonce, pacote, aad)
    raise AssertionError("Contexto divergente deveria falhar")
except InvalidTag:
    print("5. Contexto HKDF diferente: chaves diferentes; InvalidTag.")
 
print("Todos os testes passaram.")
