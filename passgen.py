# ═══════════════════════════════════════════════════════════════
# AUDITORÍA DE SEGURIDAD — Gestoría López & Asociados
# Proyecto FP SMR · passgen.py
# Generador de contraseñas seguras
# Módulo: Seguridad Informática / Programación · FP SMR España
#
# USO EN TERMINAL:
#   python passgen.py
#
# En el navegador este código se ejecuta via Pyodide (passgen.js)
# la función input() se sustituye por el slider de la interfaz.
# ═══════════════════════════════════════════════════════════════

import random

chars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
         'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
         'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
         'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
         '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '"', '#',
         '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':',
         ';', '<', '=', '>', '?', '@', '[',  ']', '^', '_', '`', '{', '|',
         '}', '~']

while True:
    random.shuffle(chars)
    passwd = []
    n = int(input("Cual es la longitud máxima de la contraseña: "))

    for i in range(n):
        char = random.randint(0, len(chars) - 1)
        passwd.append(chars[char])

    passwd_fn = "".join(passwd)
    print(passwd_fn)
