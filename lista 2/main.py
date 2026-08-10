"""Atividade 11 — Inverso modular, XOR e aleatoriedade.

Código exclusivamente didático. As operações isoladas aqui implementadas não
formam, por si só, um sistema criptográfico seguro.
"""

import secrets


def euclides_estendido(a, b):
    """Devolve (mdc, x, y), de modo que a*x + b*y = mdc."""
    resto_anterior, resto_atual = abs(a), abs(b)
    x_anterior, x_atual = 1, 0
    y_anterior, y_atual = 0, 1

    while resto_atual != 0:
        quociente = resto_anterior // resto_atual

        resto_anterior, resto_atual = (
            resto_atual,
            resto_anterior - quociente * resto_atual,
        )
        x_anterior, x_atual = (
            x_atual,
            x_anterior - quociente * x_atual,
        )
        y_anterior, y_atual = (
            y_atual,
            y_anterior - quociente * y_atual,
        )

    # Corrige os coeficientes caso a ou b seja negativo.
    x = x_anterior if a >= 0 else -x_anterior
    y = y_anterior if b >= 0 else -y_anterior
    return resto_anterior, x, y


def inverso_modular(a, n):
    """Devolve o inverso de a módulo n ou rejeita quando ele não existe."""
    if n <= 1:
        raise ValueError("O módulo deve ser maior que 1.")

    mdc, x, _ = euclides_estendido(a, n)
    if mdc != 1:
        raise ValueError(
            f"{a} não possui inverso módulo {n}, pois mdc({a}, {n}) = {mdc}."
        )

    return x % n


def xor_bytes(a, b):
    """Aplica XOR byte a byte em duas sequências de mesmo tamanho."""
    if len(a) != len(b):
        raise ValueError("As sequências devem ter o mesmo tamanho.")

    return bytes(byte_a ^ byte_b for byte_a, byte_b in zip(a, b))


def testar_rejeicao_do_inverso():
    """Confirma que um número não coprimo ao módulo é rejeitado."""
    try:
        inverso_modular(6, 26)
    except ValueError as erro:
        return str(erro)
    raise AssertionError("inverso_modular(6, 26) deveria gerar ValueError.")


def main():
    # Teste 1: inverso modular.
    inverso = inverso_modular(7, 26)
    assert inverso == 15
    assert (7 * inverso) % 26 == 1

    # Teste 2: XOR.
    resultado_xor = xor_bytes(bytes.fromhex("0f"), bytes.fromhex("f0"))
    assert resultado_xor.hex() == "ff"

    # Teste 3: rejeição do inverso inexistente.
    mensagem_rejeicao = testar_rejeicao_do_inverso()

    # Teste 4: mil nonces aleatórios de 12 bytes.
    quantidade = 1_000
    nonces = [secrets.token_bytes(12) for _ in range(quantidade)]
    quantidade_unicos = len(set(nonces))
    repeticoes = quantidade - quantidade_unicos

    assert all(len(nonce) == 12 for nonce in nonces)

    print("=== Saída dos testes ===")
    print(f"Inverso modular: 7^(-1) mod 26 = {inverso}")
    print(f"Verificação: (7 * {inverso}) mod 26 = {(7 * inverso) % 26}")
    print(f"XOR: 0f XOR f0 = {resultado_xor.hex()}")
    print(f"Rejeição esperada: {mensagem_rejeicao}")
    print(f"Nonces gerados: {quantidade}")
    print(f"Nonces únicos: {quantidade_unicos}")
    print(f"Repetições encontradas: {repeticoes}")
    print("Todos os testes foram concluídos com sucesso.")

if __name__ == "__main__":
    main()
