# 🛡️ Mini-IDS System

Sistema de Detección de Intrusiones (IDS) mínimo y en tiempo real, desarrollado para la **Hackathon CiberArena**. Utiliza la librería **Scapy** para la captura de paquetes y un dashboard web con **Flask/SocketIO** para la visualización de alertas en vivo.

---

## ⚙️ Cómo funciona el IDS (Arquitectura)

El Mini-IDS se compone de varios módulos que trabajan de forma concurrente:

* **Captura de paquetes:** utiliza la librería **Scapy** para realizar *sniffing* al tráfico de red en la interfaz especificada (`eth0` por defecto).
* **Procesamiento asíncrono:** la captura de Scapy se ejecuta en un hilo separado utilizando **Eventlet**, lo que permite que el servidor web de Flask y el motor de detección de amenazas se ejecuten sin bloquearse.
* **Detección basada en umbrales:** implementa una técnica de **ventana deslizante** para medir la tasa de tráfico y la actividad de puertos en periodos cortos.
* **Sistema anti-spam:** incorpora una ventana de tiempo (`SPAM_WINDOW`) para evitar que se sature el *dashboard* con la misma alerta repetidamente.
* **Generación de alertas:** las alertas generadas se envían simultáneamente a tres destinos:
    1.  La consola (terminal).
    2.  Un fichero de *log* local (`alerts.log`).
    3.  Un *dashboard* web en tiempo real mediante **SocketIO**.

---

## 🚨 Patrones de ataque detectados

El Mini-IDS está configurado para detectar dos patrones de ataque comunes basados en la volumetría del tráfico:

| Patrón | Detección (Umbral por Defecto) | Ventana de Tiempo | Lógica |
| :--- | :--- | :--- | :--- |
| **SYN Flood** | 50 paquetes SYN | 5 segundos | Mide el número de paquetes SYN consecutivos enviados desde una IP de origen a una IP de destino. |
| **Port Scan** | 15 puertos únicos | 10 segundos | Mide el número de puertos de destino diferentes contactados por una única IP de origen. |

---

## 📋 Requisitos e instalación

### 1. Requisitos del sistema

* Python 3.x
* **Permisos de root:** requiere permisos de *root* (`sudo`) para que Scapy pueda capturar paquetes de red.

### 2. Instalar dependencias de Python

Utiliza `pip` para instalar todas las librerías necesarias:

```bash
pip install scapy flask flask-socketio eventlet
```

### 3. Ajustar la interfaz

Antes de ejecutar, debes editar la línea `INTERFACE = "eth0"` en el archivo **`mini_ids.py`** y reemplazar `"eth0"` por el nombre de tu interfaz de red real (ej: `wlan0`, `enp3s0`, etc.).
