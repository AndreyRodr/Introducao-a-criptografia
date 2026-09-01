from functools import reduce

def xor_bytes(*valores):
    # Verifica se todas as sequências possuem o mesmo tamanho
    if len({len(v) for v in valores}) != 1:
        raise ValueError("Todas as sequências devem ter o mesmo tamanho.")

    # Aplica XOR em cada coluna
    return bytes(
        reduce(lambda a, b: a ^ b, coluna)
        for coluna in zip(*valores)
    )


m1 = b"pagar=1000"
m2 = b"pagar=9000"

fluxo_reutilizado = bytes.fromhex("00112233445566778899")

# Cifragem das duas mensagens usando o mesmo fluxo
c1 = xor_bytes(m1, fluxo_reutilizado)
c2 = xor_bytes(m2, fluxo_reutilizado)

# Recupera m2 conhecendo m1, c1 e c2
recuperada = xor_bytes(c1, c2, m1)


# Teste 1: a mensagem recuperada deve ser m2
assert recuperada == m2

# Teste 2: demonstra C1 XOR C2 = M1 XOR M2
assert xor_bytes(c1, c2) == xor_bytes(m1, m2)


# Evidências
print("M1:", m1)
print("M2:", m2)

print("C1:", c1.hex())
print("C2:", c2.hex())

print("C1 XOR C2:", xor_bytes(c1, c2).hex())
print("M1 XOR M2:", xor_bytes(m1, m2).hex())

print("Mensagem recuperada:", recuperada)

print("Todos os testes passaram.")
