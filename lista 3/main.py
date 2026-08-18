ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def cesar(texto, chave):
    resultado = ""
    texto = texto.upper()

    for caractere in texto:
        if caractere in ALFABETO:
            posicao = ALFABETO.index(caractere)
            nova_posicao = (posicao + chave) % 26
            resultado += ALFABETO[nova_posicao]
        else:
            resultado += caractere

    return resultado

def decifrar(texto, chave):
    return cesar(texto, -chave)

def pontuacao(texto):
    palavras = texto.split()

    # Palavras mais características recebem maior peso.
    pesos = {
        "A": 2,
        "DE": 3,
        "AO": 3,
        "QUE": 5
    }

    pontos = 0

    for palavra in palavras:
        if palavra in pesos:
            pontos += pesos[palavra]

    return pontos

def candidatas(texto_cifrado):
    resultados = []

    for chave in range(26):
        texto_decifrado = decifrar(texto_cifrado, chave)
        pontos = pontuacao(texto_decifrado)

        resultados.append((pontos, chave, texto_decifrado))

    # Ordena da maior para a menor pontuação.
    return sorted(resultados, key=lambda item: item[0], reverse=True)

msg = "ATAQUE AO AMANHECER"
segredo = cesar(msg, 7)

print("Texto original:", msg)
print("Texto cifrado:", segredo)
print("Texto decifrado:", decifrar(segredo, 7))

assert segredo == "HAHXBL HV HTHUOLJLY"
assert decifrar(segredo, 7) == msg
assert cesar("A B!", 1) == "B C!"

print("\nCandidatas mais prováveis:")

for pontos, chave, texto in candidatas(segredo)[:5]:
    print(f"Pontuação: {pontos} | Chave: {chave} | Texto: {texto}")


texto_curto = cesar("E", 3)

for pontos, chave, texto in candidatas(texto_curto)[:3]:
    print(pontos, chave, texto)
