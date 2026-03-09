/* ═══════════════════════════════════════════════════════════════
   AUDITORÍA DE SEGURIDAD — Gestoría López & Asociados
   passgen.js
   Contiene:
     · initPyodide()        — carga Pyodide (Python 3.11 WASM)
     · generatePasswords()  — ejecuta passgen.py en el navegador
     · syncLen()            — sincroniza slider con código visible
     · setQty()             — selecciona cantidad de contraseñas
     · copyPassword()       — copia al portapapeles
     · analyseStrength()    — análisis de fortaleza de contraseña
   Dependencia externa: Pyodide (cdn.jsdelivr.net)
═══════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════
   GENERADOR DE CONTRASEÑAS — PYODIDE
═══════════════════════════════════════════════════════════════ */

let pyodide = null;
let pwQty = 1;

// The exact Python code from passgen.py adapted (input() replaced by a variable)
const PYTHON_CODE = `
import random

chars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
         'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
         'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
         'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
         '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '!', '"', '#',
         '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
         ':', ';', '<', '=', '>', '?', '@', '[', ']', '^', '_',
         '\`', '{', '|', '}', '~']

def generate(n, qty):
    results = []
    for _ in range(qty):
        random.shuffle(chars)
        passwd = []
        for i in range(n):
            char = random.randint(0, len(chars) - 1)
            passwd.append(chars[char])
        results.append("".join(passwd))
    return results

passwords = generate(pw_length, pw_qty)
passwords
`;

async function initPyodide() {
  try {
    pyodide = await loadPyodide();
    document.getElementById('pyDot').classList.add('ready');
    document.getElementById('pyStatusText').textContent = 'Python 3.11 listo (Pyodide WASM)';
    document.getElementById('genBtn').disabled = false;
    document.getElementById('genBtnIcon').textContent = '⚡';
    document.getElementById('genBtnText').textContent = 'GENERAR CONTRASEÑA';
  } catch(e) {
    document.getElementById('pyDot').classList.add('error');
    document.getElementById('pyStatusText').textContent = 'Error al cargar Pyodide: ' + e.message;
  }
}

function syncLen(val) {
  document.getElementById('pwLenDisplay').textContent = val;
  // Update the highlighted number in code display
  document.getElementById('codeN').textContent = val;
}

function setQty(n) {
  pwQty = n;
  document.querySelectorAll('.qty-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('qty' + n).classList.add('active');
}

async function generatePasswords() {
  if (!pyodide) return;

  const btn = document.getElementById('genBtn');
  btn.disabled = true;
  document.getElementById('genBtnIcon').textContent = '⟳';
  document.getElementById('genBtnText').textContent = 'EJECUTANDO…';

  const length = parseInt(document.getElementById('pwLen').value);

  try {
    // Inject variables into Python namespace
    pyodide.globals.set('pw_length', length);
    pyodide.globals.set('pw_qty', pwQty);

    const result = await pyodide.runPythonAsync(PYTHON_CODE);
    const passwords = result.toJs();

    // Hide placeholder, show list
    document.getElementById('outputPlaceholder').style.display = 'none';
    const list = document.getElementById('outputList');
    list.innerHTML = '';

    passwords.forEach((pw, i) => {
      const entry = document.createElement('div');
      entry.className = 'pw-entry';
      entry.style.animationDelay = (i * 0.06) + 's';
      entry.style.opacity = '0';

      const txt = document.createElement('span');
      txt.className = 'pw-text';
      txt.textContent = pw;

      const copyBtn = document.createElement('button');
      copyBtn.className = 'pw-copy';
      copyBtn.textContent = 'COPIAR';
      copyBtn.onclick = () => copyPassword(pw, copyBtn);

      entry.appendChild(txt);
      entry.appendChild(copyBtn);
      list.appendChild(entry);
    });

    // Strength analysis on last password
    analyseStrength(passwords[passwords.length - 1]);

  } catch(e) {
    document.getElementById('outputList').innerHTML =
      `<div style="font-family:var(--font-mono);font-size:11px;color:var(--danger);padding:8px">Error: ${e.message}</div>`;
  }

  btn.disabled = false;
  document.getElementById('genBtnIcon').textContent = '⚡';
  document.getElementById('genBtnText').textContent = 'GENERAR CONTRASEÑA';
}

function copyPassword(pw, btn) {
  navigator.clipboard.writeText(pw).then(() => {
    btn.textContent = '✓ OK';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = 'COPIAR';
      btn.classList.remove('copied');
    }, 1500);
  });
}

function analyseStrength(pw) {
  const section = document.getElementById('strengthSection');
  section.style.display = 'block';

  const len = pw.length;
  const hasLower  = /[a-z]/.test(pw);
  const hasUpper  = /[A-Z]/.test(pw);
  const hasDigit  = /[0-9]/.test(pw);
  const hasSymbol = /[^a-zA-Z0-9]/.test(pw);

  const score = [
    len >= 8, len >= 12, len >= 20, len >= 32,
    hasLower, hasUpper, hasDigit, hasSymbol
  ].filter(Boolean).length;

  const bars = document.getElementById('strengthBars');
  const label = document.getElementById('strengthLabel');
  const total = 8;
  bars.innerHTML = '';

  const colors = ['#ff3860','#ff3860','#ff6400','#ffb800','#ffb800','#00c8ff','#00c8ff','#00ff99','#00ff99'];
  const labels = ['MUY DÉBIL','MUY DÉBIL','MUY DÉBIL','DÉBIL','MODERADA','BUENA','FUERTE','MUY FUERTE','MUY FUERTE'];
  const labelColors = ['#ff3860','#ff3860','#ff3860','#ff6400','#ffb800','#00c8ff','#00c8ff','#00ff99','#00ff99'];

  for (let i = 0; i < total; i++) {
    const bar = document.createElement('div');
    bar.className = 'sbar';
    if (i < score) {
      bar.style.background = colors[score - 1];
      bar.style.boxShadow = `0 0 6px ${colors[score-1]}88`;
    }
    bars.appendChild(bar);
  }

  const lbl = labels[score];
  label.textContent = `SEGURIDAD: ${lbl} · longitud ${len} · ${[hasLower?'min':'',hasUpper?'MAY':'',hasDigit?'núm':'',hasSymbol?'símbolo':''].filter(Boolean).join(', ')}`;
  label.style.color = labelColors[score];
}

// Init on load
setQty(1);
initPyodide();
