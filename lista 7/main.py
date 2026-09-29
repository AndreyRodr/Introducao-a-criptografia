def xtime(valor):
  # Guarda se o bit mais alto estava ativo
    bit_alto = valor & 0x80


    # Desloca para a esquerda e mantém somente 8 bits
    valor = (valor << 1) & 0xFF


    # Se o bit mais alto estava ativo, faz a redução
    if bit_alto:
        valor ^= 0x1B


    return valor




def gf_mul(a, b):
    resultado = 0


    # Percorre os 8 bits do multiplicador
    for _ in range(8):
        # Se o bit menos significativo de b for 1,
        # a parcela atual entra na soma por XOR
        if b & 1:
            resultado ^= a


        # Multiplica a por 02 no corpo do AES
        a = xtime(a)


        # Passa para o próximo bit de b
        b >>= 1


    return resultado




# Testes iniciais pedidos
assert xtime(0x57) == 0xAE
assert gf_mul(0x57, 0x13) == 0xFE


print("Teste xtime(57):", f"{xtime(0x57):02X}")
print("Teste 57 * 13:", f"{gf_mul(0x57, 0x13):02X}")




# Tarefa 3
# Parcelas usadas em 57 * 13
print("\nParcelas de 57 * 13:")


valor = 0x57
multiplicador = 0x13
parcelas = []


for _ in range(8):
    if multiplicador & 1:
        parcelas.append(valor)


    valor = xtime(valor)
    multiplicador >>= 1


print("Parcelas:", " XOR ".join(f"{p:02X}" for p in parcelas))


resultado = 0
for parcela in parcelas:
    resultado ^= parcela


print("Resultado:", f"{resultado:02X}")


assert resultado == 0xFE




# Tarefa 4
# Testa todos os bytes de 00 a FF
for byte in range(256):
    assert gf_mul(byte, 0x00) == 0x00
    assert gf_mul(byte, 0x01) == byte
    assert gf_mul(byte, 0x02) == xtime(byte)


print("\nTestes de 00 a FF passaram:")
print("- multiplicar por 00 resulta em 00")
print("- multiplicar por 01 preserva o byte")
print("- multiplicar por 02 coincide com xtime")




# Tarefa 5
# Primeira saída do MixColumns para [D4, BF, 5D, 30]


p1 = gf_mul(0x02, 0xD4)
p2 = gf_mul(0x03, 0xBF)
p3 = gf_mul(0x01, 0x5D)
p4 = gf_mul(0x01, 0x30)


print("\nPrimeira saída do MixColumns:")
print("02 * D4 =", f"{p1:02X}")
print("03 * BF =", f"{p2:02X}")
print("01 * 5D =", f"{p3:02X}")
print("01 * 30 =", f"{p4:02X}")


mix_resultado = p1 ^ p2 ^ p3 ^ p4


print(
    f"{p1:02X} XOR {p2:02X} XOR "
    f"{p3:02X} XOR {p4:02X} = {mix_resultado:02X}"
)


assert mix_resultado == 0x04




# Tarefa 6
# Demonstra as duas formas de redução usando AE


deslocado = 0xAE << 1


# Forma 1: valor de 9 bits XOR 11B
reducao_11b = deslocado ^ 0x11B


# Forma 2: mantém os 8 bits baixos e XOR com 1B
oito_bits = deslocado & 0xFF
reducao_1b = oito_bits ^ 0x1B


print("\nRedução de AE:")
print("AE << 1 =", f"{deslocado:03X}")
print("15C XOR 11B =", f"{reducao_11b:02X}")
print("5C XOR 1B =", f"{reducao_1b:02X}")


assert reducao_11b == reducao_1b
assert reducao_11b == 0x47
