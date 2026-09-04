def f(metade, subchave):
    return (metade + subchave) % 256


def rodada(esquerda, direita, subchave):
    nova_esquerda = direita
    nova_direita = esquerda ^ f(direita, subchave)

    return nova_esquerda, nova_direita


def cifrar(bloco, subchaves):
    esquerda = (bloco >> 8) & 0xFF
    direita = bloco & 0xFF

    for subchave in subchaves:
        esquerda, direita = rodada(esquerda, direita, subchave)

    return (esquerda << 8) | direita


def decifrar(bloco, subchaves):
    esquerda = (bloco >> 8) & 0xFF
    direita = bloco & 0xFF

    for subchave in reversed(subchaves):
        esquerda, direita = (
            direita ^ f(esquerda, subchave),
            esquerda
        )

    return (esquerda << 8) | direita


def distancia_hamming(a, b):
    return (a ^ b).bit_count()


def decifrar_ordem_errada(bloco, subchaves):
    esquerda = (bloco >> 8) & 0xFF
    direita = bloco & 0xFF

    for subchave in subchaves:
        esquerda, direita = (
            direita ^ f(esquerda, subchave),
            esquerda
        )

    return (esquerda << 8) | direita


chaves = [3, 17, 91, 201]

# Testes de ida e volta
for bloco in [0x0000, 0x1234, 0xFFFF]:
    cifrado = cifrar(bloco, chaves)
    recuperado = decifrar(cifrado, chaves)

    assert recuperado == bloco
    assert 0 <= cifrado <= 0xFFFF

    print(f"Entrada:    0x{bloco:04X}")
    print(f"Cifrado:    0x{cifrado:04X}")
    print(f"Recuperado: 0x{recuperado:04X}")
    print()


# Teste alterando um bit da entrada
bloco_original = 0x1234
bloco_alterado = bloco_original ^ 0x0001

saida_original = cifrar(bloco_original, chaves)
saida_alterada = cifrar(bloco_alterado, chaves)

distancia = distancia_hamming(saida_original, saida_alterada)

print(f"Entrada original: 0x{bloco_original:04X}")
print(f"Entrada alterada: 0x{bloco_alterado:04X}")
print(f"Saída original:   0x{saida_original:04X}")
print(f"Saída alterada:   0x{saida_alterada:04X}")
print(f"Bits diferentes na saída: {distancia} de 16")


# Verifica que a ordem errada das subchaves não recupera a mensagem
cifrado = cifrar(0x1234, chaves)

assert decifrar_ordem_errada(cifrado, chaves) != 0x1234

print("\nTodos os testes passaram.")
