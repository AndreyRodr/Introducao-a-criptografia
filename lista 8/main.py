def e(x, k=3):
    return (x + k) % 16


def d(y, k=3):
    return (y - k) % 16


def cbc(blocos, iv):
    # Validação do IV e dos blocos
    if not isinstance(iv, int) or not 0 <= iv <= 15:
        raise ValueError("IV deve estar entre 0 e 15.")

    if any(not isinstance(b, int) or not 0 <= b <= 15 for b in blocos):
        raise ValueError("Todos os blocos devem estar entre 0 e 15.")

    resultado = []
    anterior = iv

    for bloco in blocos:
        # XOR com a saída anterior e depois aplica e
        entrada = bloco ^ anterior
        cifrado = e(entrada)

        resultado.append(cifrado)
        anterior = cifrado

    return resultado


def dec_cbc(blocos, iv):
    # Validação do IV e dos blocos
    if not isinstance(iv, int) or not 0 <= iv <= 15:
        raise ValueError("IV deve estar entre 0 e 15.")

    if any(not isinstance(b, int) or not 0 <= b <= 15 for b in blocos):
        raise ValueError("Todos os blocos devem estar entre 0 e 15.")

    resultado = []
    anterior = iv

    for cifrado in blocos:
        # Primeiro aplica d e depois XOR com o cifrado anterior
        bloco = d(cifrado) ^ anterior

        resultado.append(bloco)
        anterior = cifrado

    return resultado


def ctr(blocos, nonce, inicio=0):
    # Nonce e contador possuem dois bits: valores de 0 a 3
    if not isinstance(nonce, int) or not 0 <= nonce <= 3:
        raise ValueError("Nonce deve estar entre 0 e 3.")

    if not isinstance(inicio, int) or not 0 <= inicio <= 3:
        raise ValueError("Contador inicial deve estar entre 0 e 3.")

    if any(not isinstance(b, int) or not 0 <= b <= 15 for b in blocos):
        raise ValueError("Todos os blocos devem estar entre 0 e 15.")

    # Contador de dois bits possui somente quatro valores
    if len(blocos) > 4 - inicio:
        raise ValueError("Contador de dois bits esgotado.")

    resultado = []

    for i, bloco in enumerate(blocos):
        contador = inicio + i

        # T = N || j
        entrada = (nonce << 2) | contador

        # O contador é cifrado para gerar o fluxo
        fluxo = e(entrada)

        # CTR usa XOR entre mensagem e fluxo
        resultado.append(bloco ^ fluxo)

    return resultado


# --------------------------------------------------
# TAREFA 3 - Exemplos 2 e 3
# --------------------------------------------------

mensagem = [6, 6, 6]

cbc_exemplo = cbc(mensagem, 5)
cbc_recuperado = dec_cbc(cbc_exemplo, 5)

ctr_exemplo = ctr(mensagem, 2)
ctr_recuperado = ctr(ctr_exemplo, 2)

assert cbc_exemplo == [6, 3, 8]
assert cbc_recuperado == mensagem

assert ctr_exemplo == [13, 10, 11]
assert ctr_recuperado == mensagem

print("=== Exemplos do material ===")
print("Mensagem:", mensagem)
print("CBC IV=5:", cbc_exemplo)
print("CBC recuperado:", cbc_recuperado)

print("CTR nonce=2:", ctr_exemplo)
print("CTR recuperado:", ctr_recuperado)


# Testa d(e(x)) = x para todos os 16 valores
for x in range(16):
    assert d(e(x)) == x

print("\nd(e(x)) = x confirmado para valores de 0 a 15.")


# Mensagem diferente para testar recuperação
mensagem2 = [1, 2, 3, 4]

cbc2 = cbc(mensagem2, 7)
ctr2 = ctr(mensagem2, 1)

assert dec_cbc(cbc2, 7) == mensagem2
assert ctr(ctr2, 1) == mensagem2

print("\n=== Mensagem diferente ===")
print("Entrada:", mensagem2)
print("CBC:", cbc2)
print("CBC recuperado:", dec_cbc(cbc2, 7))
print("CTR:", ctr2)
print("CTR recuperado:", ctr(ctr2, 1))


# --------------------------------------------------
# TAREFA 4 - Alteração do IV e do nonce
# --------------------------------------------------

print("\n=== Alterando somente o IV do CBC ===")

cbc_iv2 = cbc(mensagem, 2)

print("Entrada:", mensagem)
print("IV: 2")
print("Saída:", cbc_iv2)
print("Recuperação:", dec_cbc(cbc_iv2, 2))

assert dec_cbc(cbc_iv2, 2) == mensagem


print("\n=== Alterando somente o nonce do CTR ===")

ctr_nonce1 = ctr(mensagem, 1)

print("Entrada:", mensagem)
print("Nonce: 1")
print("Saída:", ctr_nonce1)
print("Recuperação:", ctr(ctr_nonce1, 1))

assert ctr(ctr_nonce1, 1) == mensagem


# --------------------------------------------------
# TAREFA 5 - Maleabilidade do CTR
# --------------------------------------------------

print("\n=== Alteração de um bit em CTR ===")

original = ctr(mensagem, 2)

alterado = original.copy()

# Altera o bit menos significativo do primeiro bloco
alterado[0] ^= 1

recuperado_original = ctr(original, 2)
recuperado_alterado = ctr(alterado, 2)

print("Texto cifrado original:", original)
print("Texto cifrado alterado:", alterado)
print("Mensagem original:", recuperado_original)
print("Mensagem após alteração:", recuperado_alterado)

assert recuperado_original == [6, 6, 6]
assert recuperado_alterado == [7, 6, 6]


# --------------------------------------------------
# TAREFA 6 - Esgotamento do contador
# --------------------------------------------------

print("\n=== Teste de esgotamento do contador ===")

try:
    ctr([1, 2, 3, 4, 5], 2)
except ValueError as erro:
    print("Pedido rejeitado:", erro)


