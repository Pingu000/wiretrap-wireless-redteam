# WireTrap — Workflow Git y arranque

## SIEMPRE leer antes de hacer cambios en el código

---

## Rutas

- **Windows (edición):** `C:\Users\tortu\Documents\WireTrap\`
- **Kali (ejecución):** `~/WireTrap-gitlab/`
- **Remote Windows:** `gitlab` → `git push gitlab main`
- **Remote Kali:** `origin` → `git pull origin main`

---

## Cómo hacer cambios en el código (obligatorio seguir este orden)

### 1. Claude edita los archivos directamente en Windows via device_commit_files

Claude usa `device_stage_files` para traer el archivo de Windows, lo edita en `/mnt/user-data/outputs/`, y lo escribe de vuelta con `device_commit_files`.

**IMPORTANTE — verificar antes del commit que los cambios están:**
Pedir a Claude que haga grep en el archivo para confirmar que los cambios están.
Si `device_commit_files` dice "written" pero el archivo no tiene los cambios, re-stagear y volver a editar.

### 2. Commit y push desde PowerShell (Windows)

```powershell
cd C:\Users\tortu\Documents\WireTrap
git add <archivo(s) modificado(s)>
git commit -m "descripcion del cambio"
git push gitlab main
```

**Si git dice "nothing to commit":** el archivo ya está committed. Verificar con:
```powershell
Select-String -Path "core\captive_portal.py" -Pattern "texto_que_debe_estar"
```
Si el texto NO está → el device_commit_files no escribió bien. Repetir desde paso 1.
Si el texto SÍ está → ya estaba commiteado antes, el push ya lo tiene.

### 3. Pull y arranque desde Kali

```bash
cd ~/WireTrap-gitlab
git pull origin main
find . -name "*.pyc" -delete && find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null; true
sudo python3 main.py
```

---

## Resumen rápido

```
Claude edita en Windows → git add + commit + push (PowerShell) → git pull + python3 main.py (Kali)
```
