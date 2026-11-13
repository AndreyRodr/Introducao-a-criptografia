from math import gcd
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def preparar(p, q, e):
    # Precondição didática: p e q são primos distintos.
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("Expoente não coprimo com o totiente")
    return p * q, pow(e, -1, phi)

def transformar(m, expoente, n):
    if not isinstance(m, int) or not 0 <= m < n:
        raise ValueError("Representante fora do intervalo")
    return pow(m, expoente, n)

n, d = preparar(7, 13, 5)
assert (n, d) == (91, 29)
for m in range(n):
    assert transformar(transformar(m, 5, n), d, n) == m
print("RSA bruto: 91 representantes recuperados, incluindo 0, 7 e 13.")
for invalido in (-1, n):
    try:
        transformar(invalido, 5, n)
        raise AssertionError("Deveria rejeitar")
    except ValueError:
        print("Representante rejeitado:", invalido)

m, r = 9, 2
c = transformar(m, 5, n)
c_alterada = (c * pow(r, 5, n)) % n
recuperada = transformar(c_alterada, d, n)
assert (c, c_alterada, recuperada) == (81, 44, 18)
print("Previsão / resultado: cifra 81 / 81; alterada 44 / 44; mensagem 18 / 18.")

priv_cifra = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_cifra = priv_cifra.public_key()
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
mensagem = b"pedido=7"
c1 = pub_cifra.encrypt(mensagem, oaep)
c2 = pub_cifra.encrypt(mensagem, oaep)
assert len(c1) == len(c2) == 256 and c1 != c2
assert priv_cifra.decrypt(c1, oaep) == mensagem
assert priv_cifra.decrypt(c2, oaep) == mensagem
assert len(pub_cifra.encrypt(b"A" * 190, oaep)) == 256
try:
    pub_cifra.encrypt(b"A" * 191, oaep)
    raise AssertionError("191 bytes deveriam ser rejeitados")
except ValueError:
    pass
print("OAEP: duas cifras diferentes, ambas recuperadas; 190 aceitos e 191 rejeitados.")

priv_assina = rsa.generate_private_key(public_exponent=65537, key_size=2048)
outro_par = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
assinatura = priv_assina.sign(mensagem, pss, hashes.SHA256())
assert priv_assina.public_key().verify(assinatura, mensagem, pss, hashes.SHA256()) is None
for publica, conteudo in [
    (priv_assina.public_key(), b"pedido=8"),
    (outro_par.public_key(), mensagem)
]:
    try:
        publica.verify(assinatura, conteudo, pss, hashes.SHA256())
        raise AssertionError("Assinatura inválida deveria falhar")
    except InvalidSignature:
        pass
print("PSS: assinatura válida aceita; mensagem alterada e pública errada rejeitadas.")
print("Todos os testes passaram.")
