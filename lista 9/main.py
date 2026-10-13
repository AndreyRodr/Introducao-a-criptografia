from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
 
aes = AESGCM(AESGCM.generate_key(bit_length=128))
nonce = (7).to_bytes(4, "big") + (9).to_bytes(8, "big")
aad = bytes([1]) + (17).to_bytes(2, "big") + (9).to_bytes(4, "big")
mensagem = b"nota=8.5"
 
# Uma única cifração; todas as verificações usam cópias.
pacote = aes.encrypt(nonce, mensagem, aad)
recuperada = aes.decrypt(nonce, pacote, aad)
assert len(pacote) == 24
assert recuperada == mensagem
print("Original:", recuperada.decode("ascii"))
print(f"Tamanhos: M={len(mensagem)}, AAD={len(aad)}, "
      f"N={len(nonce)}, C={len(pacote) - 16}, T=16")
print(f"Saida AESGCM={len(pacote)}; "
      f"registro={len(aad) + len(nonce) + len(pacote)} bytes")
print("AAD (hex):", aad.hex(" "))
 
 
def alterar(dados, indice):
    copia = bytearray(dados)
    copia[indice] ^= 1
    return bytes(copia)
 
 
sequencias_aceitas = set()
 
 
def receber(objeto, n, p, a, usuario_esperado, aceitas):
    # Formato ainda não confiável: validar antes de decrypt.
    if len(a) != 7 or len(n) != 12 or len(p) < 16:
        return "REJEITADO: formato", None
    try:
        m = objeto.decrypt(n, p, a)
    except InvalidTag:
        return "REJEITADO: InvalidTag", None
    # Só agora interpretar o cabeçalho autenticado.
    versao = a[0]
    usuario = int.from_bytes(a[1:3], "big")
    sequencia = int.from_bytes(a[3:7], "big")
    if versao != 1 or usuario != usuario_esperado:
        return "REJEITADO: contexto", None
    identificador = (usuario, sequencia)
    if identificador in aceitas:
        return "REJEITADO: repeticao", None
    # Laboratório sequencial: registrar antes de retornar M.
    aceitas.add(identificador)
    return "ACEITO", m
 
 
# Alterações independentes, sempre a partir do original.
casos = [
    ("C primeiro byte", nonce, alterar(pacote, 0), aad),
    ("T ultimo byte", nonce, alterar(pacote, -1), aad),
    ("AAD ultimo byte", nonce, pacote, alterar(aad, -1)),
    ("Nonce ultimo byte", alterar(nonce, -1), pacote, aad),
]
for nome, n, p, a in casos:
    try:
        aes.decrypt(n, p, a)
    except InvalidTag:
        print(f"{nome}: InvalidTag confirmado")
    else:
        raise AssertionError(f"Aceitacao indevida: {nome}")
    antes = sequencias_aceitas.copy()
    status, m = receber(aes, n, p, a, 17, sequencias_aceitas)
    assert status == "REJEITADO: InvalidTag" and m is None
    assert sequencias_aceitas == antes
print("Adulteracoes: estado inalterado; nenhum M usado")
 
# Outra chave de teste, sem exibir a chave original.
aes_errado = AESGCM(bytes(16))
try:
    aes_errado.decrypt(nonce, pacote, aad)
except InvalidTag:
    print("Outra chave: InvalidTag confirmado")
else:
    raise AssertionError("Outra chave aceita indevidamente")
 
abertura1 = aes.decrypt(nonce, pacote, aad)
abertura2 = aes.decrypt(nonce, pacote, aad)
assert abertura1 == abertura2 == mensagem
print("Duas aberturas intactas: validas na biblioteca")
 
antes = sequencias_aceitas.copy()
status, m = receber(aes, nonce, pacote, aad, 18, sequencias_aceitas)
assert status == "REJEITADO: contexto" and m is None
assert sequencias_aceitas == antes
print("Usuario esperado 18:", status)
 
status, m = receber(aes, nonce, pacote, aad, 17, sequencias_aceitas)
assert status == "ACEITO" and m == mensagem
print("Primeira aceitacao:", status, "-", m.decode("ascii"))
status, m = receber(aes, nonce, pacote, aad, 17, sequencias_aceitas)
assert status == "REJEITADO: repeticao" and m is None
print("Segunda aceitacao:", status)
assert sequencias_aceitas == {(17, 9)}
print("Estado final:", sorted(sequencias_aceitas))
 
# Uma falha também deve preservar um conjunto já preenchido.
antes = sequencias_aceitas.copy()
status, m = receber(aes, nonce, alterar(pacote, 0), aad,
                    17, sequencias_aceitas)
assert status == "REJEITADO: InvalidTag" and m is None
assert sequencias_aceitas == antes
print("Falha apos aceitacao: estado preservado")
print("Todos os testes passaram")
