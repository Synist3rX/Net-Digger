# Net Digger 🔍 (`v1.15.0`)

> Una herramienta CLI de Python robusta, modular y de alto rendimiento para reconocimiento de dominios, consultas DNS avanzadas y auditoría de infraestructura de red.

## Características

* **Resumen de Objetivo (`[>] Target`) Siempre Visible**: Muestra automáticamente la resolución de IP, el registro inverso (`PTR`) y el estado HTTP (`HTTP Status`) de cada dominio consultado.

* **Consultas DNS Multi-Registro (`-t` / `--type`)**: Soporta 12 tipos de registros DNS (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `CAA`, `SRV`, `PTR`, `HTTPS`, `SVCB`) o el perfil completo (`ALL`), con desglose de prioridad, TTL y conteo total.

* **Detección Automática de Proveedores**: Identifica el **DNS Provider** (a partir de registros `NS`) y el **Email Provider** (a partir de registros `MX`).

* **Módulos de Inspección Especializados**:

  * **SSL/TLS (`--ssl`)**: Inspección de certificados en el puerto 443 (emisor, vigencia, días restantes, versión TLS, cobertura de dominio, autofirmado y SANs).

  * **WHOIS (`--whois`)**: Consulta directa de registro (registrador, fechas de creación/actualización/expiración, antigüedad, DNSSEC, nameservers y estados EPP).

  * **Seguridad de Correo (`--email`)**: Auditoría de postura de autenticación evaluando **SPF** (con conteo de lookups DNS), **DMARC** (política y reportes) y selectores comunes de **DKIM**.

  * **Blacklist (`--blacklist`)**: Consulta la reputación de la IP y el dominio objetivo frente a listas DNSBL y URIBL mediante la API de DigDNS.

  * **HTTP & Headers (`--headers`)**: Inspecciona código de estado final, cadena de redirecciones (`301`/`302`/etc.), evaluación de cabeceras de seguridad (7 cabeceras clave) y listado completo de cabeceras de respuesta.

  * **Geolocalización y ASN (`--geo` / `--geolocation`)**: Obtiene país, ciudad, zona horaria, coordenadas, número de Sistema Autónomo (`ASN`), organización e ISP asociado a la IP resuelta.

  * **Puntaje de Seguridad (`--score` / `--security-score`)**: Evalúa las cabeceras de seguridad HTTP mediante un sistema ponderado sobre 95 puntos (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` y `Permissions-Policy`) y asigna una calificación (`A`–`F`).

  * **Reputación IP (`--reputation`)**: Consulta el puntaje de abuso (*Abuse Score*), total de reportes, usuarios distintos, ISP, tipo de uso (*Usage Type*), fecha de último reporte y estado de lista blanca (*Whitelisted*) mediante la API de DigDNS.

  * **DNSSEC (`--dnssec`)**: Audita la postura criptográfica del dominio verificando registros `DNSKEY`, `DS` y el indicador `Authenticated Data` (`AD`).

  * **Robots (`--robots`)**: Descarga y analiza `/robots.txt` extrayendo `User-agent`, conteo de reglas `Allow` / `Disallow` y directivas `Sitemap` declaradas.

  * **Sitemap (`--sitemap`)**: Inspecciona índices de sitemaps (`<sitemapindex>`) o conjuntos de URLs (`<urlset>`) descubiertos desde `robots.txt` o rutas estándar (`/sitemap.xml`, `/sitemap_index.xml`).

* **Concurrencia y Resiliencia**: Procesamiento paralelo mediante `ThreadPoolExecutor` con barra de progreso (`tqdm`), soporte de transporte UDP o TCP (`--tcp`) y reintentos automáticos con *exponential backoff* (`-r`).

* **Soporte IDN / Punycode y Validación**: Valida sintaxis de dominios (incluyendo caracteres internacionales como `eñe.es`), direcciones IP de nameservers y tipos de registro solicitados.

* **Exportación a JSON (`-o`)**: Genera reportes estructurados listos para automatización o análisis posterior, creando y utilizando automáticamente la carpeta `output/` cuando no se indica una ruta con directorio.

## Arquitectura del Proyecto

```text
net-digger/
├── digger.py                   # Punto de entrada CLI y orquestación concurrente
├── core/
│   ├── blacklist_inspector.py  # Consulta y normalización de listas negras DNSBL/URIBL (DigDNS API)
│   ├── cli_parser.py           # Definición y parseo de argumentos de línea de comandos
│   ├── detector.py             # Detección de proveedores de DNS y correo
│   ├── dnssec_inspector.py     # Auditoría de DNSSEC (DNSKEY, DS y flag Authenticated Data)
│   ├── email_security.py       # Evaluación de SPF, DMARC y DKIM
│   ├── exporter.py             # Exportación de resultados a JSON y resolución de rutas en output/
│   ├── formatters.py           # Renderizado estructurado de bloques en terminal
│   ├── geo_inspector.py        # Inspección de geolocalización IP, coordenadas, ASN e ISP
│   ├── http_inspector.py       # Inspección HTTP, cadena de redirecciones y cabeceras de seguridad
│   ├── reputation_inspector.py # Consulta de reputación IP y reportes de abuso (DigDNS API)
│   ├── resolver.py             # Motor de consultas DNS (UDP/TCP, timeouts y reintentos)
│   ├── robots_inspector.py     # Descarga y parseo de directivas en robots.txt
│   ├── security_score.py       # Evaluación ponderada y calificación (A–F) de cabeceras de seguridad HTTP
│   ├── sitemap_inspector.py    # Descubrimiento y parseo XML de sitemaps (<sitemapindex> y <urlset>)
│   ├── ssl_inspector.py        # Auditoría de certificados TLS/SSL (puerto 443)
│   ├── target_inspector.py     # Resolución inicial de objetivo (IP, PTR y HTTP Status)
│   ├── validator.py            # Validación de dominios (IDN) e IPs
│   └── whois_inspector.py      # Consultas y parseo de registros WHOIS (puerto 43)
└── tests/                      # Suite de pruebas unitarias con pytest
```

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

## Opciones de la Línea de Comandos

| Bandera / Opción | Descripción | Por defecto |
| :--- | :--- | :--- |
| `DOMAIN` *(posicional)* | Dominio objetivo individual a consultar (ej. `google.com` o `eñe.es`). | `None` |
| `-d`, `--domain` | Dominio objetivo individual (alternativa explícita al argumento posicional; excluyente con `-f`). | `None` |
| `-f`, `--file` | Archivo TXT con una lista de dominios (uno por línea; ignora líneas vacías y `#` comentarios). | `None` |
| `-t`, `--type` | Tipo(s) de registro DNS separados por coma (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `CAA`, `SRV`, `PTR`, `HTTPS`, `SVCB`) o `ALL`. Si se pasa `-t` sin valor, asume `ALL`. | `None` *(solo Target)* |
| `-ns`, `--nameserver` | Dirección IP del servidor DNS personalizado a utilizar (ej. `1.1.1.1` o `8.8.8.8`). | `1.1.1.1` |
| `--tcp` | Fuerza el protocolo de transporte TCP en lugar de UDP para las consultas DNS. | `False` |
| `-to`, `--timeout` | Tiempo máximo de espera en segundos por intento de consulta. | `5.0` |
| `-r`, `--retries` | Número máximo de reintentos automáticos ante fallos de red. | `3` |
| `--ssl` | Inspecciona el certificado TLS/SSL en el puerto 443 del dominio objetivo. | `False` |
| `--whois` | Realiza una consulta WHOIS (puerto 43) para obtener datos de registro del dominio. | `False` |
| `--email` | Audita la configuración de autenticación de correo (`SPF`, `DMARC` y `DKIM`). | `False` |
| `--blacklist` | Verifica la IP y el dominio objetivo en listas negras DNSBL y URIBL mediante la API de DigDNS. | `False` |
| `--headers` | Inspecciona estado HTTP, cadena de redirecciones, cabeceras de seguridad y cabeceras completas. | `False` |
| `--geo`, `--geolocation` | Consulta geolocalización, coordenadas, zona horaria, ASN y organización de la IP objetivo. | `False` |
| `--score`, `--security-score` | Evalúa el puntaje de cabeceras de seguridad HTTP (sobre 95 puntos) y asigna una calificación (`A`–`F`). | `False` |
| `--reputation` | Consulta reputación IP, puntaje de abuso, reportes, ISP, tipo de uso y estado en lista blanca. | `False` |
| `--dnssec` | Inspecciona estado DNSSEC, registros `DNSKEY` y `DS`, y el flag `Authenticated Data` (`AD`). | `False` |
| `--robots` | Descarga y analiza `/robots.txt` (`User-agent`, reglas `Allow`/`Disallow` y directivas `Sitemap`). | `False` |
| `--sitemap` | Inspecciona y extrae las URLs de sitemaps XML (`<sitemapindex>` o `<urlset>`). | `False` |
| `--full` | Muestra valores íntegros sin truncar en tablas, SANs, estados WHOIS, registros SPF/DMARC, cabeceras, `robots.txt` y sitemaps. | `False` |
| `--all` | Activa todos los módulos de inspección y salida completa (`-t ALL`, `--ssl`, `--whois`, `--email`, `--blacklist`, `--headers`, `--geo`, `--score`, `--reputation`, `--dnssec`, `--robots`, `--sitemap` y `--full`). | `False` |
| `-o`, `--output` | Exporta los resultados a JSON. Si se usa `-o` sin nombre guarda en `output/<objetivo>.json`; si se da solo un nombre (`reporte.json`) usa `output/reporte.json`; si se da una ruta con carpeta respeta esa ruta. | `None` *(no exporta si se omite)* |

## Ejemplos de Uso

### 1. Reconocimiento Rápido de Objetivo (`Target`)

Consulta únicamente la metadata básica del dominio (IP resuelta, PTR y código de estado HTTP) sin desplegar tablas DNS:

```bash
python digger.py google.com
```

### 2. Consulta de Registros DNS Específicos o Completos (`-t`)

* **Consultar tipos específicos (separados por coma):**

  ```bash
  python digger.py google.com -t A,MX,TXT
  ```

* **Consultar todos los tipos soportados (`-t` sin valor o `-t ALL`):**

  ```bash
  python digger.py google.com -t
  # Equivalente a:
  python digger.py google.com -t ALL
  ```

### 3. Módulos Especializados (`--ssl`, `--whois`, `--email`, `--blacklist`, `--headers`, `--geo`, `--score`, `--reputation`, `--dnssec`, `--robots`, `--sitemap`)

Puedes ejecutar módulos de auditoría de forma independiente o combinada:

* **Auditar seguridad de correo electrónico:**

  ```bash
  python digger.py github.com --email
  ```

* **Inspeccionar certificado TLS/SSL y datos WHOIS:**

  ```bash
  python digger.py openai.com --ssl --whois
  ```

* **Analizar `robots.txt` y sitemaps XML por separado o juntos:**

  ```bash
  python digger.py google.com --robots --sitemap
  ```

### 4. Auditoría Integral con Salida Completa (`--all`)

Ejecuta simultáneamente la consulta de todos los registros DNS (`ALL`), todos los módulos de auditoría y valores sin truncar (`--full`):

```bash
python digger.py google.com --all
```

**Ejemplo de salida en consola:**

```text
[>] Target: google.com
    Query           : google.com
    Resolves To     : 142.251.215.238 (sea09s35-in-f14.1e100.net)
    HTTP Status     : 200

--------------------------------------------------------------------------------
[>] DNS Records (27 records found)
    TYPE     PRIO   TTL      VALUE
    ------------------------------------------------------------------------
    A        -      99s      142.251.214.110
    AAAA     -      278s     2607:f8b0:4023:c06::64
    MX       10     300s     smtp.google.com
    NS       -      86400s   ns1.google.com
    TXT      -      3600s    v=spf1 include:_spf.google.com ~all
    SOA      -      60s      ns1.google.com
    CAA      -      86400s   0 issue "pki.goog"
    [*] DNS Provider   : Google Cloud DNS (detected via NS)
    [*] Email Provider : Google Workspace (detected via MX)

--------------------------------------------------------------------------------
[>] SSL Certificate
    Status          : 64d left (TLS: TLSv1.3)
    Common Name     : *.google.com
    Issuer          : WE2
    ...

--------------------------------------------------------------------------------
[>] WHOIS
    Domain          : GOOGLE.COM
    Registrar       : MarkMonitor Inc.
    ...

--------------------------------------------------------------------------------
[>] Email Security
    Overall         : Partial
    SPF             : Soft Fail (~all) (1/10 lookups)
    DMARC           : reject (Reports: mailauth-reports@google.com)
    DKIM            : Detected (selector: google)

--------------------------------------------------------------------------------
[>] Blacklist Check
    Overall         : Listed
    Checked IP      : 142.251.45.14
    Summary         : Clean: 11/13 | Listed: 2

--------------------------------------------------------------------------------
[>] HTTP & Headers
    Status          : 200
    Final URL       : http://www.google.com/
    Redirect Chain  : 301 http://google.com -> 200 http://www.google.com/
    Security Headers: 2/7

--------------------------------------------------------------------------------
[>] Geolocation & ASN
    IP Address      : 142.251.34.78
    Location        : Dallas, Texas, US
    Timezone        : America/Chicago
    Coordinates     : 37.751, -97.822
    ASN             : AS15169
    Organization    : Google LLC
    ISP / Org       : AS15169 Google LLC

--------------------------------------------------------------------------------
[>] Security Score
    Grade           : F
    Category        : HTTP Security Headers
    Points          : 15 / 95 points
    ------------------------------------------------------------------------
        [✖] HSTS                   Not set — site accessible over HTTP          0/25
        [✖] CSP                    Not set — no XSS/injection mitigation        0/25
        [✔] X-Frame-Options        SAMEORIGIN                                   15/15
        [✖] X-Content-Type-Options Not set — MIME sniffing allowed              0/10
        [✖] Referrer-Policy        Not set — full URLs sent as Referer          0/10
        [✖] Permissions-Policy     Not set — browser feature access unrestric... 0/10

--------------------------------------------------------------------------------
[>] Reputation
    Abuse Score     : 0% (44 reports from 3 users)
    IP              : 142.251.34.78
    ISP             : Google LLC
    Usage Type      : Content Delivery Network
    Last Report     : 2026-11-25T01:17:20+00:00
    Whitelisted     : Yes

--------------------------------------------------------------------------------
[>] DNSSEC
    DNSSEC          : Not enabled
    Status          : Not configured
    DNSKEY record   : Not found
    DS record       : Not found
    Authenticated Data: No

--------------------------------------------------------------------------------
[>] Robots
    Source URL      : https://google.com/robots.txt
    Lines           : 301
    Rules           : Allow: 48 | Disallow: 220 | Sitemaps: 1
    ------------------------------------------------------------------------
        User-agent: *
        Disallow: /search
        Allow: /search/about
        ...

--------------------------------------------------------------------------------
[>] Sitemap
    Sitemap URL     : https://www.google.com/sitemap.xml
    Type            : sitemapindex
    URLs Found      : 24
    ------------------------------------------------------------------------
        https://www.google.com/gmail/sitemap.xml
        https://www.google.com/forms/sitemaps.xml
        ...
```

### 5. Auditoría Masiva Concurrente, TCP y Exportación a JSON

Procesa una lista de dominios desde un archivo de texto utilizando transporte TCP, un nameserver personalizado y guarda los resultados estructurados en JSON:

```bash
python digger.py -f dominios.txt -ns 8.8.8.8 -t ALL --tcp -r 3 -o reportes/auditoria_dns.json
```

**Estructura generada en el archivo JSON:**

```json
[
    {
        "domain": "google.com",
        "target": {
            "query": "google.com",
            "ip": "142.251.215.238",
            "ptr": "sea09s35-in-f14.1e100.net",
            "resolves_to": "142.251.215.238 (sea09s35-in-f14.1e100.net)",
            "http_status": 200
        },
        "total_records": 27,
        "dns_provider": "Google Cloud DNS",
        "email_provider": "Google Workspace",
        "queries": [
            {
                "status": "SUCCESS",
                "domain": "google.com",
                "punycode": null,
                "type": "MX",
                "records": [
                    {
                        "value": "smtp.google.com",
                        "priority": 10
                    }
                ],
                "ttl": 300
            }
        ],
        "blacklist": {
            "status": "SUCCESS",
            "overall_status": "Listed",
            "checked_ip": "142.251.45.14",
            "listed_count": 2,
            "clean_count": 11
        },
        "http_headers": {
            "status": "SUCCESS",
            "status_code": 200,
            "final_url": "http://www.google.com/",
            "security_headers": {
                "present_count": 2,
                "total_count": 7
            }
        },
        "geolocation": {
            "status": "SUCCESS",
            "ip": "142.251.34.78",
            "location": "Dallas, Texas, US",
            "timezone": "America/Chicago",
            "coordinates": "37.751, -97.822",
            "asn": "AS15169",
            "organization": "Google LLC",
            "isp_org": "AS15169 Google LLC"
        },
        "security_score": {
            "status": "SUCCESS",
            "category": "HTTP Security Headers",
            "score": 15,
            "max_score": 95,
            "grade": "F"
        },
        "reputation": {
            "status": "SUCCESS",
            "ip": "142.251.34.78",
            "abuse_score": 0,
            "total_reports": 44,
            "num_distinct_users": 3,
            "isp": "Google LLC",
            "usage_type": "Content Delivery Network",
            "last_reported_at": "2026-11-25T01:17:20+00:00",
            "whitelisted": true
        },
        "dnssec": {
            "status": "SUCCESS",
            "domain": "google.com",
            "enabled": false,
            "badge": "Not enabled",
            "config_status": "Not configured",
            "dnskey_record": false,
            "ds_record": false,
            "authenticated_data": false
        },
        "robots": {
            "status": "SUCCESS",
            "domain": "google.com",
            "url": "https://google.com/robots.txt",
            "line_count": 301,
            "allow_count": 48,
            "disallow_count": 220,
            "sitemaps": [
                "https://www.google.com/sitemap.xml"
            ]
        },
        "sitemap": {
            "status": "SUCCESS",
            "domain": "google.com",
            "sitemap_url": "https://www.google.com/sitemap.xml",
            "kind": "sitemapindex",
            "url_count": 24,
            "urls": [
                "https://www.google.com/gmail/sitemap.xml"
            ]
        }
    }
]
```

### Exportar a `output/` automáticamente (`-o`)

```bash
python digger.py google.com --all -o
```

Crea la carpeta `output/` (si no existe) y guarda el reporte en `output/google.com.json`. Si consultas una lista con `-f`, genera un archivo con marca de tiempo dentro de `output/` (`output/digger_YYYYMMDD_HHMMSS.json`).

## Ejecución de Pruebas

Net Digger cuenta con una suite de pruebas unitarias construida con `pytest` y `unittest.mock` que valida los módulos de inspección, formateo, validación de argumentos y resolución DNS sin requerir conexión a internet:

```bash
pytest -v
```

## Licencia

Distribuido bajo la **Licencia MIT**. Consulta el archivo `LICENSE` para obtener más información.
