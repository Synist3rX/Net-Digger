# NetDigger 🔍

> Una herramienta CLI de Python robusta, modular y de alto rendimiento para consultas DNS avanzadas, reconocimiento de red y auditoría de dominios.

---

## Características

- **Soporte Multi-Registro**: Consulta registros DNS estándar (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`) o ejecuta un reconocimiento completo (`ALL`).
- **Nameservers Personalizados**: Enruta de forma fluida las consultas hacia servidores DNS específicos (por ejemplo, Cloudflare `1.1.1.1` o Google `8.8.8.8`).
- **Procesamiento Masivo**: Audita listas de dominios de forma simultánea utilizando archivos TXT planos (`-f`).
- **Exportación a JSON**: Formatea y exporta automáticamente los resultados estructurados de las auditorías para registros o reportes (`-o`).
- **Arquitectura Modular**: Clara separación de responsabilidades con motores centrales dedicados (`resolver`, `exporter`) probados mediante `pytest`.
- **Manejo de Errores Robusto**: Captura con gracia excepciones de red tales como `NXDOMAIN`, `NoAnswer` y `Timeout` sin interrumpir la terminal.

---

## Instalación

1. **Clonar el repositorio**:
   ```bash
   git clone https://github.com/your-username/net-digger.git
   cd net-digger
   ```

2. **Crear y activar un entorno virtual**:
   ```bash
   python -m venv venv
   # En Windows (PowerShell):
   .\venv\Scripts\Activate
   # En Linux/macOS:
   source venv/bin/activate
   ```

3. **Instalar dependencias**:
   ```bash
   pip install -r requirements.txt
   ```

---

## Opciones de la Línea de Comandos

| Bandera / Opción | Descripción | Por defecto |
| :--- | :--- | :--- |
| `-d`, `--domain` | Dominio objetivo individual a consultar (mutuamente exclusivo con `-f`). | `None` |
| `-f`, `--file` | Archivo TXT que contiene una lista de dominios a consultar (uno por línea). | `None` |
| `-t`, `--type` | Tipo de registro DNS (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `ALL`). | `A` |
| `-ns`, `--nameserver` | IP del nameserver personalizado a consultar (ej. `1.1.1.1` u `8.8.8.8`). | DNS del sistema |
| `-to`, `--timeout` | Límite de tiempo de espera en segundos para las consultas DNS. | `5.0` |
| `-o`, `--output` | Ruta para exportar los resultados de la consulta a un archivo JSON estructurado. | `None` |

---

## Ejemplos de Uso

### 1. Consulta Básica de Registro A
Consulta la dirección IPv4 por defecto para un dominio individual usando los resolutores del sistema:
```bash
python digger.py -d example.com
```

### 2. Consulta de Registros de Correo (`MX`)
Verifica los servidores de correo configurados para un dominio:
```bash
python digger.py -d google.com -t MX
```

### 3. Uso de un Nameserver Personalizado y Tipo de Registro Específico
Consulta los registros IPv6 (`AAAA`) para GitHub utilizando el DNS de Cloudflare (`1.1.1.1`):
```bash
python digger.py -d github.com -ns 1.1.1.1 -t AAAA
```

### 4. Reconocimiento Completo (`ALL`)
Realiza una auditoría multi-registro en un dominio objetivo:
```bash
python digger.py -d openai.com -t ALL
```

### 5. Procesamiento Masivo y Exportación a JSON
Lee múltiples dominios desde un archivo `targets.txt`, consulta sus registros MX usando el DNS de Google (`8.8.8.8`) y guarda la salida estructurada en un reporte JSON:
```bash
python digger.py -f targets.txt -ns 8.8.8.8 -t MX -o reports/mx_audit.json
```

---

## Ejecución de Pruebas

Net Digger incluye una suite completa de pruebas unitarias utilizando `pytest` y `unittest.mock` para garantizar la estabilidad sin conexión a internet a través de diferentes plataformas. Ejecuta la suite de pruebas con:

```bash
pytest -v
```

---

## Licencia

Distribuido bajo la **Licencia MIT**. Consulta el archivo `LICENSE` para obtener más información.
