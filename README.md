# 🛡️ WpVandaBot

**WpVandaBot** é um scanner e exploit automático para detectar e explorar vulnerabilidades no plugin WordPress **Simple File List <= 4.2.2** (CVE-2020-36847).  
O bot identifica a versão do plugin em sites alvo e, se vulnerável, tenta explorar a falha de upload de arquivos para execução remota de código (RCE).

---

## 🚀 Funcionalidades

- ✅ Verifica se o plugin está instalado e identifica sua versão.
- ✅ Detecta versões vulneráveis automaticamente.
- ✅ Realiza upload de um payload PHP disfarçado de imagem.
- ✅ Renomeia o arquivo para `.php` e tenta executá-lo.
- ✅ Salva os shells ativos encontrados em `shells_found.txt`.
- ✅ Suporte a múltiplos sites via lista.
- ✅ Interface interativa via terminal com banner.

---

## 📌 CVE Referência

- **CVE**: [CVE-2020-36847](https://nvd.nist.gov/vuln/detail/CVE-2020-36847)
- **Vulnerabilidade**: Upload Arbitrário / Remote Code Execution
- **Plugin vulnerável**: `simple-file-list <= 4.2.2`

---

## ⚙️ Requisitos

- Python 3.6+
- Bibliotecas:
  - `requests`
  - `colorama`

Você pode instalar as dependências com:

```bash
pip install -r requirements.txt
