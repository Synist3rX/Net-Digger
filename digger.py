#!/usr/bin/env python3
import sys
import argparse
from core.resolver import DNSResolverEngine

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="NetDigger: Herramienta CLI de reconocimiento y consulta DNS avanzada."
    )
    parser.add_argument("domain", help="Dominio objetivo a consultar (ej. example.com)")
    parser.add_argument(
        "-t", "--type",
        default="A",
        help="Tipo de registro DNS (A, AAAA, MX, NS, TXT, CNAME, SOA, ALL). Por defecto: A"
    )
    parser.add_argument(
        "-ns", "--nameserver",
        help="Servidor DNS personalizado a consultar (ej. 1.1.1.1 o 8.8.8.8)"
    )
    parser.add_argument(
        "-to", "--timeout",
        type=float,
        default=5.0,
        help="Tiempo límite de espera en segundos (por defecto: 5.0)"
    )
    return parser.parse_args()

def main():
    args = parse_arguments()
    engine = DNSResolverEngine(nameserver=args.nameserver, timeout=args.timeout)
    
    # Manejo de múltiples tipos o tipo único
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"] if args.type.upper() == "ALL" else [args.type]

    print(f"\n[*] Iniciando análisis DNS para: {args.domain}")
    if args.nameserver:
        print(f"[*] Usando Nameserver personalizado: {args.nameserver}")
    print("-" * 50)

    for r_type in record_types:
        result = engine.query_record(args.domain, r_type)
        if result["status"] == "SUCCESS":
            print(f"[+] Registros {result['type']} (TTL: {result['ttl']}s):")
            for item in result["data"]:
                print(f"    -> {item}")
        else:
            print(f"[-] [{result['type']}] {result['message']}")
    print("-" * 50)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operación cancelada por el usuario.")
        sys.exit(0)
