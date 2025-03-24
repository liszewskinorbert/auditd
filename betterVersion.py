#!/usr/bin/env python3
import re
import socket
import time
from datetime import datetime
from sh import tail

# Konfiguracja
UDP_IP = "127.0.0.1"       # zmień na adres serwera docelowego
UDP_PORT = 5555            # zmień na port serwera docelowego
AUDIT_LOG_PATH = "/var/log/audit/audit.log"
OUTPUT_LOG_PATH = "/var/log/audit_commands.log"

# Opóźnienie na start
time.sleep(10)
hostname = socket.gethostname()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def write_log(entry: str) -> None:
    """Zapisuje wpis do pliku OUTPUT_LOG_PATH."""
    try:
        with open(OUTPUT_LOG_PATH, "a") as f:
            f.write(entry)
    except FileNotFoundError:
        pass

def hex_decode(match: re.Match) -> str:
    """Dekoduje ciąg hex po znaku '='."""
    hex_str = match.group(0)[1:]  # usuń znak '='
    try:
        return "=" + bytes.fromhex(hex_str).decode("utf-8")
    except Exception:
        return "=" + hex_str

def format_timestamp(ts_str: str) -> str:
    """Formatuje znacznik czasu, wyodrębniając odpowiedni fragment."""
    try:
        # Oryginalny kod wycinał znaki od 6 do 16
        timestamp_int = int(ts_str[6:16])
        return datetime.fromtimestamp(timestamp_int).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts_str

def process_execve(line: str) -> None:
    """Przetwarza rekord EXECVE i zapisuje log."""
    try:
        # Rozdzielenie linii na część przed i po 'msg='
        _, msg = line.strip().split("msg=", 1)
        aid, exe = msg.split(": ", 1)
        time_part, _ = aid.split(":", 1)
        formatted_time = format_timestamp(time_part)
        # Pobranie części polecenia (pomijamy pierwszy element)
        parts = exe.split(" ", 1)
        if len(parts) > 1:
            exe = parts[1]
        # Zamiana ciągów hex na czytelne znaki
        exe = re.sub(r'=[0-9A-F]{5,}', hex_decode, exe)
        exe = re.sub(r'a[0-9]=', '', exe)
        exe = exe.replace('"', '')
        log_entry = f"timestamp='{formatted_time}' address='{hostname}' comm='{exe}'\n"
        # Jeśli chcesz wysyłać UDP, odkomentuj poniższą linię:
        # sock.sendto(log_entry.encode("utf-8"), (UDP_IP, UDP_PORT))
        write_log(log_entry)
    except Exception:
        # W razie problemów z przetwarzaniem rekordu EXECVE, pomijamy go.
        pass

def process_syscall(line: str) -> None:
    """Przetwarza rekord SYSCALL i zapisuje log."""
    try:
        # Rozdzielenie linii na część przed i po 'msg='
        _, msg = line.strip().split("msg=", 1)
        aid, _ = msg.split(": ", 1)
        time_part, _ = aid.split(":", 1)
        formatted_time = format_timestamp(time_part)
        log_parts = line.split()
        # Pobranie poszczególnych elementów (jeśli dostępne)
        success = log_parts[4] if len(log_parts) > 4 else ""
        comm = log_parts[24] if len(log_parts) > 24 else ""
        auid = log_parts[29] if len(log_parts) > 29 else ""
        euid = log_parts[32] if len(log_parts) > 32 else ""
        log_entry = f"timestamp='{formatted_time}' address='{hostname}' {comm} {success} {auid} {euid}\n"
        # Jeśli chcesz wysyłać UDP, odkomentuj poniższą linię:
        # sock.sendto(log_entry.encode("utf-8"), (UDP_IP, UDP_PORT))
        write_log(log_entry)
    except Exception:
        pass

def main() -> None:
    last_record = False
    for line in tail("-F", AUDIT_LOG_PATH, _iter=True):
        # Jeśli poprzedni rekord został rozpoznany, a bieżący zawiera EXECVE, przetwarzamy EXECVE
        if last_record and "type=EXECVE" in line:
            process_execve(line)
        # Warunek dla rekordu SYSCALL – jeśli linia zawiera "type=SYSCALL" ale nie zawiera "tty=pts", pomijamy ją
        if "type=SYSCALL" in line and "tty=pts" not in line:
            last_record = False
            continue
        # W przeciwnym przypadku traktujemy to jako rekord SYSCALL z "tty=pts"
        last_record = True
        process_syscall(line)

if __name__ == "__main__":
    main()
