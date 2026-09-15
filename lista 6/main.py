SEGUNDOS_ANO = 365.25 * 24 * 60 * 60


def tempo_medio(bits_seguranca, testes_por_segundo, maquinas=1):
    # Em média, a chave correta aparece na metade do espaço de busca.
    tentativas_medias = 2 ** (bits_seguranca - 1)
    return tentativas_medias / (testes_por_segundo * maquinas)


def em_anos(segundos):
    return segundos / SEGUNDOS_ANO


CENARIOS = [
    ("DES", 56),
    ("3DES (forca estimada)", 112),
    ("AES-128", 128),
]

TAXA = 1e12
MAQUINAS = [1, 10**3, 10**6, 10**9]


# Testes pedidos no material
assert tempo_medio(56, 1e12) == 2 ** 55 / 1e12

# Dobrar a quantidade de maquinas divide o tempo por dois.
assert tempo_medio(56, TAXA, 2) == tempo_medio(56, TAXA, 1) / 2

# Adicionar um bit dobra o tempo medio.
assert tempo_medio(57, TAXA) == 2 * tempo_medio(56, TAXA)

# A razao entre 128 e 56 bits e 2^72.
assert tempo_medio(128, TAXA) / tempo_medio(56, TAXA) == 2 ** 72


print("TEMPO MEDIO COM 1 MAQUINA A 1e12 TESTES/S")
for nome, bits in CENARIOS:
    segundos = tempo_medio(bits, TAXA)
    print(
        f"{nome:24s} | {bits:3d} bits | "
        f"{segundos:.3e} s | {em_anos(segundos):.3e} anos"
    )

horas_des = tempo_medio(56, TAXA) / 3600
print(f"\nDES (56 bits): {horas_des:.2f} horas em media")


print("\nTABELA COM PARALELISMO PERFEITO")
print(
    f"{'Maquinas':>12s} | {'Cenario':24s} | "
    f"{'Segundos':>12s} | {'Anos':>12s}"
)
print("-" * 70)

for maquinas in MAQUINAS:
    for nome, bits in CENARIOS:
        segundos = tempo_medio(bits, TAXA, maquinas)
        print(
            f"{maquinas:12d} | {nome:24s} | "
            f"{segundos:12.3e} | {em_anos(segundos):12.3e}"
        )


print("\nRAZAO ENTRE AES-128 E DES")
razao = tempo_medio(128, TAXA) / tempo_medio(56, TAXA)
print(f"2^72 = {int(razao)} vezes")


print("\nTodos os testes passaram.")
