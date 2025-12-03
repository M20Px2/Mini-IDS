import sys
import os
import eventlet 


# --- INICIO DEL CÓDIGO DE SUPRESIÓN DE SALIDA (Para ocultar el mensaje "RLock(s) were not greened...") ---
# 1. Guardar la referencia al stderr original
original_stderr = sys.stderr

# 2. Abrir /dev/null y redirigir stderr hacia él
try:
    devnull = open(os.devnull, 'w')
    sys.stderr = devnull
except:
    # Si la redirección falla (por ejemplo, en entornos restringidos), lo ignoramos.
    pass

# 3. Ejecutar monkey_patch() (ESTA ES LA LÍNEA QUE GENERA LA ADVERTENCIA)
eventlet.monkey_patch() 

# 4. Restaurar stderr a su estado original
try:
    sys.stderr = original_stderr
    devnull.close()
except:
    pass
# --- FIN DEL CÓDIGO DE SUPRESIÓN DE SALIDA ---


from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import datetime
import socket

# --- Flask & SocketIO Imports ---
from flask import Flask, render_template
from flask_socketio import SocketIO, emit

# --- Configuración del IDS ---
INTERFACE = "eth0" # ¡ASEGÚRATE DE QUE ESTA ES TU INTERFAZ REAL (ej: eth0)!
ALERT_LOG_FILE = "alerts.log" # Nombre del fichero donde se guardarán las alertas

def get_local_ip(interface_name):
    """Intenta obtener la IP de la máquina en la interfaz."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

LOCAL_IP = get_local_ip(INTERFACE)

# Lista de IPs a ignorar
IP_EXCLUSION_LIST = ['127.0.0.1'] 

# --- Configuración de umbrales y ventanas de tiempo ---
# Ventana deslizante (para tasa de detección)
SYN_FLOOD_THRESHOLD = 50
SYN_WINDOW = 5             # En segundos: 50 SYN en 5 segundos
PORTSCAN_THRESHOLD = 15    
PORTSCAN_WINDOW = 10       # En segundos: 15 puertos en 10 segundos

# Frecuencia de alerta (para prevención de SPAM en el dashboard)
SPAM_WINDOW = 10           # Segundos que debe esperar antes de alertar de nuevo sobre el mismo origen/flujo

# Contadores globales de actividad (almacenan listas de (timestamp, valor))
syn_flood_tracker = defaultdict(list) 
port_scan_tracker = defaultdict(list) 

# Timestamps de alerta (para frecuencia de alerta)
alerted_ips_timestamp = {} 
alerted_flows_timestamp = {} 

# --- Configuración de Flask/SocketIO ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_secret_key_for_hackathon' 
socketio = SocketIO(app, async_mode='eventlet') 

# --- Rutas Web (Frontend) ---
@app.route('/')
def index():
    # Asumo que tienes un archivo index.html para el dashboard web
    return render_template('index.html')


# --- Funciones de utilidad ---
def write_log_header():
    """Escribe la línea de inicio solicitada en el log de alertas."""
    try:
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        header_content = f"----- IDS Alert Log Started: {now} -----" + "\n"
        
        # Comprobar si el archivo ya existe y tiene contenido. Esto evita el salto de línea inicial
        # en la primera ejecución y lo añade en las sucesivas para separar sesiones.
        add_leading_newline = os.path.exists(ALERT_LOG_FILE) and os.path.getsize(ALERT_LOG_FILE) > 0
        
        with open(ALERT_LOG_FILE, 'a') as f: 
            if add_leading_newline:
                f.write("\n") # Añadir una línea de separación solo si ya había contenido
            
            f.write(header_content)
            
        print(f"Log de alertas iniciado (modo 'a'): {ALERT_LOG_FILE}")
    except Exception as e:
        print(f"ERROR: No se pudo escribir la cabecera en {ALERT_LOG_FILE}: {e}")

def clean_old_data(data_tracker, time_window):
    """Implementa la ventana deslizante: elimina los registros más antiguos que time_window."""
    now = datetime.datetime.now()
    cutoff_time = now - datetime.timedelta(seconds=time_window)
    
    for key in list(data_tracker.keys()):
        # Filtrar registros cuya marca de tiempo (índice 0) sea posterior al tiempo de corte
        data_tracker[key] = [item for item in data_tracker[key] if item[0] >= cutoff_time]
        if not data_tracker[key]:
            del data_tracker[key]

def can_alert(key, timestamp_tracker, time_window):
    """Comprueba si el SPAM_WINDOW ha expirado para un key (IP o Flow)."""
    last_alert_time = timestamp_tracker.get(key)
    if last_alert_time is None:
        return True
    
    if datetime.datetime.now() - last_alert_time > datetime.timedelta(seconds=time_window):
        return True
    
    return False


# --- Función de alerta ---
def generate_alert(alert_type, source_ip, details):
    """Genera la alerta en consola, la EMITE al dashboard web y la escribe en el log."""
    
    if alert_type == "SYN Flood":
        emoji = "🔥" 
    elif alert_type == "Port Scan":
        emoji = "🔍" 
    else:
        emoji = "❗" 
        
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. Crear la línea de alerta completa
    alert_line = f"[{now}] {emoji} ALERT: {alert_type} from {source_ip} - {details}"
    
    # 2. Imprimir la alerta en consola
    print(alert_line)
    
    # 3. Escribir la alerta en el fichero alerts.log (Modo 'a' ya usado en write_log_header)
    try:
        with open(ALERT_LOG_FILE, 'a') as f:
            f.write(alert_line + '\n')
    except Exception as e:
        print(f"ERROR: No se pudo escribir la alerta en {ALERT_LOG_FILE}: {e}")
        
    # 4. Emitir la alerta al frontend via SocketIO
    if socketio:
        socketio.emit('new_alert', {
            'time': now,
            'type': alert_type,
            'source_ip': source_ip,
            'details': details
        })


# --- Función de chequeo ---
def check_packet(packet):
    """Función callback de sniff(): Analiza cada paquete en tiempo real."""
    
    if IP not in packet:
        return 
        
    source_ip = packet[IP].src
    
    # Si la IP de origen está en la lista de exclusión, la ignoramos.
    if source_ip in IP_EXCLUSION_LIST:
        return

    current_time = datetime.datetime.now()
    
    if TCP in packet or UDP in packet:
        dest_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        
        # 1. Detección de Port Scan
        port_scan_tracker[source_ip].append((current_time, dest_port))
        
        # Limpiar datos antiguos para aplicar la ventana de 10 segundos
        clean_old_data(port_scan_tracker, PORTSCAN_WINDOW)
        current_ports = set(port for time, port in port_scan_tracker[source_ip])
        
        if len(current_ports) >= PORTSCAN_THRESHOLD:
            
            # Comprobación de SPAM_WINDOW
            if can_alert(source_ip, alerted_ips_timestamp, SPAM_WINDOW):
                
                alerted_ips_timestamp[source_ip] = current_time # Actualizar timestamp de alerta
                
                generate_alert(
                    "Port Scan", 
                    source_ip, 
                    f"Contacted {len(current_ports)} unique ports in {PORTSCAN_WINDOW}s (Threshold: {PORTSCAN_THRESHOLD})"
                )
        
        # 2. Detección de SYN Flood
        if TCP in packet and packet[TCP].flags == 'S': 
            dest_ip = packet[IP].dst
            flow_key = (source_ip, dest_ip)

            syn_flood_tracker[flow_key].append((current_time, 1))
            clean_old_data(syn_flood_tracker, SYN_WINDOW)
            current_syn_count = len(syn_flood_tracker[flow_key])
            
            if current_syn_count >= SYN_FLOOD_THRESHOLD:
                
                # Comprobación de SPAM_WINDOW
                if can_alert(flow_key, alerted_flows_timestamp, SPAM_WINDOW):
                    
                    alerted_flows_timestamp[flow_key] = current_time # Actualizar timestamp de alerta
                    
                    generate_alert(
                        "SYN Flood", 
                        source_ip, 
                        f"Flow {source_ip} -> {dest_ip} sent {current_syn_count} SYN in {SYN_WINDOW}s (Threshold: {SYN_FLOOD_THRESHOLD})"
                    )


# --- Función para iniciar la captura en un hilo separado ---
def start_capture():
    """Ejecuta la captura de paquetes en un hilo de Eventlet."""
    print(f"Starting Scapy capture thread on {INTERFACE}...")
    try:
        # Nota: Asegúrate de ejecutar esto con permisos de root (sudo python3 ids_system.py)
        sniff(iface=INTERFACE, prn=check_packet, store=0) 
    except Exception as e:
        print(f"\nERROR IN SCAPY THREAD: {e}. Check if you have permissions (sudo) or if interface '{INTERFACE}' is correct.")


# --- Función principal de inicio ---
def start_ids():
    """Inicia el servidor Flask, el hilo de captura de Scapy y el log de alertas."""
    
    print("------------- MINI-IDS SYSTEM STATUS -------------")
    print(f"Monitoring Interface: {INTERFACE}")
    print(f"Local IDS IP: {LOCAL_IP}")
    print(f"Alert Log File: {ALERT_LOG_FILE}") 
    print(f"Exclusion List: {IP_EXCLUSION_LIST}") 
    print(f"SYN Flood Threshold: {SYN_FLOOD_THRESHOLD} packets in {SYN_WINDOW} seconds")
    print(f"Port Scan Threshold: {PORTSCAN_THRESHOLD} ports in {PORTSCAN_WINDOW} seconds")
    print(f"Alert Repetition Window (Anti-Spam): {SPAM_WINDOW} seconds")
    print("----------------------------------------------------")
    print(f"Web Dashboard available at: http://{LOCAL_IP}:5000")
    print("Press Ctrl+C to stop the analysis.\n")
    
    # 1. Iniciar el log de alertas
    write_log_header()
    
    # 2. Iniciar la captura de paquetes en un hilo de fondo
    eventlet.spawn(start_capture)
    
    # 3. Iniciar el servidor web (SocketIO/Flask)
    socketio.run(app, host=LOCAL_IP, port=5000)


if __name__ == "__main__":
    try:
        start_ids()
    except Exception as e:
        print(f"\nFATAL ERROR: Could not start IDS or web server. Error: {e}")