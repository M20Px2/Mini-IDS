# \# 🛡️ Mini-IDS System

# 

# Sistema de Detección de Intrusiones (IDS) mínimo y en tiempo real,# 🛡️ Mini-IDS System

# 

# Sistema de Detección de Intrusiones (IDS) mínimo y en tiempo real, desarrollado para la Hackathon CiberArena. Utiliza la librería Scapy para la captura de paquetes y un dashboard web con Flask/SocketIO para la visualización de alertas en vivo.

# 

# ---

# 

# \## ⚙️ Cómo funciona el IDS (Arquitectura)

# 

# El Mini-IDS se compone de varios módulos que trabajan de forma concurrente:

# 

# \* \*\*Captura de paquetes:\*\* Utiliza la librería \*\*Scapy\*\* para realizar sniffing al tráfico de red en la interfaz especificada (`eth0` por defecto).

# \* \*\*Procesamiento asíncrono:\*\* la captura de Scapy se ejecuta en un hilo separado utilizando \*\*Eventlet\*\*, lo que permite que el servidor web de Flask y el motor de detección de amenazas se ejecuten sin bloquearse.

# \* \*\*Detección basada en umbrales:\*\* implementa una técnica de \*\*ventana deslizante\*\* para medir la tasa de tráfico y la actividad de puertos en periodos cortos.

# \* \*\*Sistema anti-spam:\*\* incorpora una ventana de tiempo (`SPAM\_WINDOW`) para evitar que se sature el dashboard con la misma alerta repetidamente.

# \* \*\*Generación de alertas:\*\* las alertas generadas se envían simultáneamente a tres destinos:

# &nbsp;   1.  La consola (terminal).

# &nbsp;   2.  Un fichero de \*log\* local (`alerts.log`).

# &nbsp;   3.  Un \*dashboard\* web en tiempo real mediante \*\*SocketIO\*\*.

# 

# \## 🚨 Patrones de ataque detectados

# 

# El Mini-IDS está configurado para detectar dos patrones de ataque comunes basados en la volumetría del tráfico:

# 

# | Patrón | Detección (Umbral por Defecto) | Ventana de Tiempo | Lógica |

# | :--- | :--- | :--- | :--- |

# | \*\*SYN Flood\*\* | 50 paquetes SYN | 5 segundos | Mide el número de paquetes SYN consecutivos enviados desde una IP de origen a una IP de destino. |

# | \*\*Port Scan\*\* | 15 puertos únicos | 10 segundos | Mide el número de puertos de destino diferentes contactados por una única IP de origen. |

# 

# \## 📋 Requisitos e instalación

# 

# 1\.  \*\*Requisitos del Sistema:\*\*

# &nbsp;   \* Python 3.x

# &nbsp;   \* \*\*Permisos de root:\*\* requiere permisos de \*root\* (`sudo`) para que Scapy pueda capturar paquetes de red.

# 

# 2\.  \*\*Instalar dependencias de Python:\*\*

# &nbsp;   ```bash

# &nbsp;   pip install scapy flask flask-socketio eventlet

# &nbsp;   ```

# 

# 3\.  \*\*Ajustar la interfaz:\*\*

# &nbsp;   Antes de ejecutar, debes editar la línea `INTERFACE = "eth0"` en `mini\_ids.py` y reemplazar `"eth0"` por el nombre de tu interfaz de red real (ej: `wlan0`, `enp3s0`, etc.).

# 

# \## 🚀 Ejemplos de uso y demo

# 

# Sigue estos pasos para poner el IDS en funcionamiento y simular un ataque que lo active:

# 

# 1\.  \*\*Ejecutar el IDS.\*\*

# &nbsp;   Abre una terminal, navega a la carpeta del proyecto y ejecuta el script con `sudo`:

# &nbsp;   ```bash

# &nbsp;   sudo python3 mini\_ids.py

# &nbsp;   ```

# &nbsp;   El IDS se iniciará y te indicará la dirección de su \*dashboard\*: `Web Dashboard available at: http://\[LOCAL\_IP]:5000`.

# 

# 2\.  \*\*Acceder al dashboard.\*\*

# &nbsp;   Abre un navegador web y ve a la dirección indicada (ej: `http://192.168.1.10:5000`).

# 

# 3\.  \*\*Simular un Port Scan (Usando Nmap):\*\*

# &nbsp;   Abre una terminal \*\*diferente\*\* y ejecuta un escaneo rápido contra la IP de tu IDS (o cualquier otra IP de la red que esté siendo monitorizada), \*\*cambiando `TARGET\_IP` por una IP real\*\* (Ej: `192.168.1.5`):

# &nbsp;   ```bash

# &nbsp;   # ATENCIÓN: Ejecutar solo en entornos controlados y con permiso.

# &nbsp;   sudo nmap -sS -p 1-100 TARGET\_IP

# &nbsp;   ```

# &nbsp;   Al superar el umbral de 15 puertos únicos contactados en 10 segundos, el IDS generará una alerta de "Port Scan" en tiempo real.

