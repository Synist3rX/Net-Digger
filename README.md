# Net-Digger
Herramienta CLI en Python rápida y modular para consultas, reconocimiento y resolución de registros DNS avanzados.

# NetDigger 🔍

Una herramienta CLI modular y robusta en Python para consultas y reconocimiento DNS avanzado.

## Características
- **Soporte multi-registro**: Consulta registros tipo A, AAAA, MX, NS, TXT, CNAME o realiza consultas completas.
- **Nameservers Personalizados**: Redirige las consultas a servidores específicos (ej. Cloudflare `1.1.1.1` o Google `8.8.8.8`).
- **Arquitectura Modular**: Diseñado bajo principios limpios, fácil de extender e integrar con pruebas unitarias (`pytest`).
- **Manejo de Errores Robusto**: Control preciso de excepciones como `NXDOMAIN`, `NoAnswer` y `Timeout`.


## Usage

```
usage: digger.py [-h] [-t TYPE] [-ns NAMESERVER] [-to TIMEOUT] domain

NetDigger: Herramienta CLI de reconocimiento y consulta DNS avanzada.

positional arguments:
  domain                Dominio objetivo a consultar (ej. example.com)

options:
  -h, --help            show this help message and exit
  -t, --type TYPE       Tipo de registro DNS (A, AAAA, MX, NS, TXT, CNAME, SOA, ALL). Por
                        defecto: A
  -ns, --nameserver NAMESERVER
                        Servidor DNS personalizado a consultar (ej. 1.1.1.1 o 8.8.8.8)
  -to, --timeout TIMEOUT
                        Tiempo límite de espera en segundos (por defecto: 5.0)
```
