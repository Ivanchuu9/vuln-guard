import sys
import time
import logging
import argparse
import signal
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

# ==========================================
# 1. SISTEMA DE VISUALIZACIÓN (Colores y Banner)
# ==========================================

class LogColors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    PURPLE = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[37m"
    BOLD = "\033[1m"

def print_banner():
    banner = r"""
░██    ░██            ░██                 ░██████                                        ░██ 
░██    ░██            ░██                ░██   ░██                                       ░██ 
░██    ░██ ░██    ░██ ░██ ░████████     ░██        ░██    ░██  ░██████   ░██░████  ░████████ 
░██    ░██ ░██    ░██ ░██ ░██    ░██    ░██  █████ ░██    ░██       ░██  ░███     ░██    ░██ 
 ░██  ░██  ░██    ░██ ░██ ░██    ░██    ░██     ██ ░██    ░██  ░███████  ░██      ░██    ░██ 
  ░██░██   ░██   ░███ ░██ ░██    ░██     ░██  ░███ ░██   ░███ ░██   ░██  ░██      ░██   ░███ 
   ░███     ░█████░██ ░██ ░██    ░██      ░█████░█  ░█████░██  ░█████░██ ░██       ░█████░██ 
   """
    print(f"{LogColors.CYAN}{LogColors.BOLD}{banner}{LogColors.RESET}")
    print(f"\t\t{LogColors.GRAY}{LogColors.BOLD}Herramienta de Ciberinteligencia Automatizada{LogColors.RESET}")
    print(f"\t\t{LogColors.YELLOW}{LogColors.BOLD}Autor:{LogColors.RESET} {LogColors.PURPLE}{LogColors.BOLD}ivanchuu9{LogColors.RESET} | {LogColors.YELLOW}{LogColors.BOLD}Version:{LogColors.RESET} {LogColors.BLUE}{LogColors.BOLD}1.0.0{LogColors.RESET}")
    print(f"\t\t{LogColors.GRAY}{LogColors.BOLD}Github:{LogColors.RESET} {LogColors.BLUE}{LogColors.BOLD}https://github.com/ivanchuu9{LogColors.RESET}\n")
    print(f"{LogColors.YELLOW}{LogColors.BOLD}[*]{LogColors.RESET}{LogColors.CYAN}{LogColors.BOLD} Inicializando modulos de deteccion...{LogColors.RESET}\n")

class ColoredFormatter(logging.Formatter):
    """Formateador que inyecta colores ANSI según la gravedad del log."""
    
    _format = "%(asctime)s [%(levelname)s] %(message)s"
    _datefmt = "%H:%M:%S"

    FORMATS = {
        logging.DEBUG:    LogColors.CYAN + _format + LogColors.RESET,
        logging.INFO:     LogColors.GREEN + _format + LogColors.RESET,
        logging.WARNING:  LogColors.YELLOW + LogColors.BOLD + _format + LogColors.RESET,
        logging.ERROR:    LogColors.RED + _format + LogColors.RESET,
        logging.CRITICAL: LogColors.RED + LogColors.BOLD + _format + LogColors.RESET
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt=self._datefmt)
        return formatter.format(record)

# Configuración del Logger Global
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ColoredFormatter())
logger = logging.getLogger("VulnGuard")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# ==========================================
# 2. MODELOS DE DATOS (Dataclasses)
# ==========================================

@dataclass
class Vulnerability:
    """Entidad que representa un hallazgo CVE."""
    id: str
    title: str
    severity: float
    description: str

@dataclass
class AppConfig:
    """Configuración inyectada desde CLI."""
    target_email: str
    min_score: float
    dry_run: bool

# ==========================================
# 3. ARQUITECTURA: PATRÓN STRATEGY
# ==========================================

class NotificationChannel(ABC):
    """
    Interfaz abstracta para canales de notificación.
    Define el contrato que deben cumplir Email, Slack, Teams, etc.
    """
    @abstractmethod
    def send(self, vuln: Vulnerability, recipient: str):
        pass

class EmailChannel(NotificationChannel):
    """Implementación concreta para Email."""
    def send(self, vuln: Vulnerability, recipient: str):
        logger.info(f"[Email] Conectando SMTP... Enviando a {LogColors.BLUE}{LogColors.BOLD}{recipient}{LogColors.RESET}")
        time.sleep(0.3) 
        logger.info(f"[Email] 📧 Enviado: {LogColors.BLUE}{LogColors.BOLD}{vuln.title}{LogColors.RESET}")

class ConsoleChannel(NotificationChannel):
    """Implementación para alertas en consola."""
    def send(self, vuln: Vulnerability, recipient: str):
        if vuln.severity > 9.0:
            logger.critical(f"[Console] 💀 AMENAZA CRITICA: {vuln.title} (Score: {vuln.severity})")
        else:
            logger.warning(f"[Console] ⚠️ Alerta: {vuln.title} (Score: {vuln.severity})")

# ==========================================
# 4. LÓGICA DE NEGOCIO (SERVICIOS)
# ==========================================

class AlertManager:
    """
    Orquestador. Recibe una lista de canales y despacha la alerta.
    Cumple SRP (Single Responsibility Principle).
    """
    def __init__(self, channels: List[NotificationChannel]):
        self.channels = channels

    def dispatch(self, vuln: Vulnerability, config: AppConfig):
        if config.dry_run:
            logger.info(f"[DRY-RUN] Simulacion: Se habria notificado {vuln.id}")
            return

        for channel in self.channels:
            channel.send(vuln, config.target_email)

class VulnerabilityEngine:
    """
    Motor ETL (Extract, Transform, Load).
    Coordina la ingesta, análisis y respuesta.
    """
    def __init__(self, config: AppConfig, alert_manager: AlertManager):
        self.config = config
        self.alert_manager = alert_manager
        # Simulación de persistencia (Cache de duplicados)
        self._seen_ids = {"CVE-2024-0001"} 

    def _fetch_intelligence(self) -> bool:
        logger.info("Conectando con feeds de inteligencia (NVD/Mitre)...")
        time.sleep(0.6) # Simulación de red
        return True

    def _analyze_risk(self, raw_data: dict) -> Vulnerability:
        """Simula el enriquecimiento con IA o reglas CVSS."""
        logger.info(f"Analizando vector de ataque para {LogColors.BLUE}{LogColors.BOLD}{raw_data['id']}{LogColors.RESET}{LogColors.GREEN}...{LogColors.RESET}")
        return Vulnerability(
            id=raw_data["id"],
            title=raw_data["title"],
            severity=raw_data.get("score", 0.0),
            description="Remote Code Execution vulnerability via buffer overflow."
        )

    def run(self):
        logger.info(f"Motor iniciado. Umbral critico: {LogColors.BLUE}{LogColors.BOLD}{self.config.min_score}{LogColors.RESET}")
        
        if not self._fetch_intelligence():
            logger.error("Fallo critico de conexion.")
            return

        # Datos simulados (Mock Data)
        feed = [
            {"id": "CVE-2024-0001", "title": "Old SQL Injection", "score": 9.0},      # Duplicado
            {"id": "CVE-2026-9999", "title": "Zero-Day RCE in Apache", "score": 9.8},  # CRÍTICO
            {"id": "CVE-2026-8888", "title": "Minor XSS in UI", "score": 4.5}         # Bajo riesgo
        ]

        for item in feed:
            # 1. Deduplicación
            if item["id"] in self._seen_ids:
                logger.debug(f"Saltando duplicado: {item['id']}")
                continue

            # 2. Análisis
            vuln = self._analyze_risk(item)

            # 3. Decisión
            if vuln.severity >= self.config.min_score:
                self.alert_manager.dispatch(vuln, self.config)
            else:
                logger.info(f"Riesgo bajo ({vuln.severity}). Archivado.")
            
            self._seen_ids.add(vuln.id)

# ==========================================
# 5. ENTRYPOINT (CLI & Main)
# ==========================================

def signal_handler(sig, frame):
    print(f"\n{LogColors.RED}[!] Interrupcion detectada. Cerrando...{LogColors.RESET}")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    
    # Argumentos CLI
    parser = argparse.ArgumentParser(description="VulnGuard: Automated Threat Detection")
    parser.add_argument("--email", default="admin@corp.com", help="Email para alertas")
    parser.add_argument("--min-score", type=float, default=8.0, help="Score minimo (0-10)")
    parser.add_argument("--dry-run", action="store_true", help="Modo simulacion (sin envío real)")
    
    args = parser.parse_args()
    config = AppConfig(args.email, args.min_score, args.dry_run)

    # Inyección de Dependencias (Wiring)
    # Aquí definimos la estrategia: Enviar por Email Y mostrar en Consola
    active_channels = [EmailChannel(), ConsoleChannel()]
    
    alert_mgr = AlertManager(active_channels)
    engine = VulnerabilityEngine(config, alert_mgr)

    print_banner()
    try:
        engine.run()
        print(f"\n{LogColors.CYAN}{LogColors.BOLD}>> Ciclo de ejecucion finalizado correctamente.{LogColors.RESET}")
    except Exception as e:
        logger.exception("Error inesperado en el motor")
        sys.exit(1)