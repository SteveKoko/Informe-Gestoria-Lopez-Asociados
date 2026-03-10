/* ═══════════════════════════════════════════════════════════════
   AUDITORÍA DE SEGURIDAD — Gestoría López & Asociados
   network.js
   Contiene:
     · NETWORKS{}  — datos completos de ambas redes (before/after)
                     nodos, conexiones, zonas, specs, vulns, fixes
     · renderNetwork() — dibuja el SVG dinámicamente
     · showNet()        — alterna entre red antes/después
     · openModal()      — modal de detalle de cada dispositivo
     · toggleVulns()    — muestra/oculta indicadores de vulnerabilidad
     · Tooltip helpers
═══════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════
   NETWORK DATA
═══════════════════════════════════════════════════════════════ */

const NETWORKS = {

  // ─────────────────────── ANTES ───────────────────────
  before: {
    title: 'RED ANTES DE LA AUDITORÍA — VULNERABLE',
    riskLabel: 'RIESGO CRÍTICO',
    riskClass: 'danger',
    titleClass: 'status-danger',
    statusVulns: '<span class="sv red">23 detectadas</span>',
    statusFirewall: '<span class="sv red">NO CONFIGURADO</span>',
    statusDmz: '<span class="sv red">NO EXISTE</span>',
    statusCompliance: '<span class="sv red">INCUMPLIMIENTO</span>',
    info: '<strong>[ ESTADO ACTUAL ]</strong> Red plana sin segmentación · Sin firewall perimetral · Servidor web expuesto en red interna · DC accesible desde todos los equipos · Impresora con credenciales por defecto · SSH en puerto estándar · Apache sin actualizar (CVE pendientes) · Sin copias de seguridad automatizadas · <strong>Incumplimiento RGPD (Reg. UE 2016/679)</strong>',

    zones: [],

    connections: [
      { from: 'internet', to: 'router', color: '#00c8ff', dash: false },
      { from: 'router',   to: 'switch', color: '#00c8ff', dash: false },
      { from: 'switch',   to: 'dc',      color: '#ff3860', dash: false },
      { from: 'switch',   to: 'web',     color: '#ff3860', dash: false },
      { from: 'switch',   to: 'pcs',     color: '#ffb800', dash: false },
      { from: 'switch',   to: 'printer', color: '#ff3860', dash: false },
    ],

    nodes: {
      internet: {
        x: 600, y: 90,
        icon: '🌐', label: 'INTERNET', sublabel: 'WAN / ISP',
        ip: '83.56.142.19 (WAN)',
        color: '#00c8ff', type: 'internet',
        detail: {
          name: 'Conexión a Internet', type: 'WAN / ISP Telefónica',
          icon: '🌐',
          specs: [
            { k: 'Proveedor ISP', v: 'Telefónica España' },
            { k: 'IP pública (WAN)', v: '83.56.142.19', cls: 'warn' },
            { k: 'Tipo', v: 'Fibra óptica FTTH' },
            { k: 'Ancho de banda', v: '600 Mbps ↓ / 300 Mbps ↑' },
            { k: 'Protocolo', v: 'TCP/IP v4' },
            { k: 'Firewall perimetral', v: 'NO EXISTE', cls: 'bad' },
          ],
          vulns: [
            { sev: 'crit', text: 'Sin firewall perimetral: toda la red interna queda expuesta directamente a internet' },
            { sev: 'crit', text: 'Sin IDS/IPS: ataques externos no son detectados ni bloqueados' },
            { sev: 'high', text: 'IP pública estática sin rotación: facilita reconocimiento pasivo por atacantes' },
          ],
        }
      },
      router: {
        x: 600, y: 210,
        icon: '📡', label: 'ROUTER ISP', sublabel: 'Router de borde',
        ip: 'WAN: 83.56.142.19 / LAN: 192.168.1.1',
        color: '#ffb800', type: 'router',
        detail: {
          name: 'Router ISP', type: 'ROUTER DE BORDE',
          icon: '📡',
          specs: [
            { k: 'IP WAN', v: '83.56.142.19' },
            { k: 'IP LAN (GW)', v: '192.168.1.1' },
            { k: 'Firmware', v: 'v5.13 (2021) — OBSOLETO', cls: 'bad' },
            { k: 'NAT', v: 'Activado' },
            { k: 'DMZ host', v: '192.168.1.20 (¡Web expuesto!)', cls: 'bad' },
            { k: 'Firewall integrado', v: 'Básico / sin reglas', cls: 'warn' },
            { k: 'UPnP', v: 'ACTIVADO', cls: 'bad' },
          ],
          vulns: [
            { sev: 'crit', text: 'DMZ del router apuntando al servidor web: expone puertos 80, 443 y 22 directamente a internet' },
            { sev: 'high', text: 'Firmware v5.13 desactualizado desde 2021: múltiples CVEs conocidos (CVE-2021-35976, CVE-2022-30525)' },
            { sev: 'high', text: 'UPnP activado: los dispositivos de la red pueden abrir puertos arbitrarios' },
            { sev: 'med',  text: 'Sin separación de zonas de red: todo el tráfico LAN/WAN pasa por el mismo router' },
            { sev: 'med',  text: 'Contraseña de administración por defecto no cambiada' },
          ],
        }
      },
      switch: {
        x: 600, y: 330,
        icon: '🔀', label: 'SWITCH', sublabel: 'D-Link DES-1024D',
        ip: 'No gestionable — Sin IP',
        color: '#ffb800', type: 'switch',
        detail: {
          name: 'Switch de red', type: 'SWITCH DE ACCESO',
          icon: '🔀',
          specs: [],
          vulns: [],
        }
      },
      dc: {
        x: 195, y: 480,
        icon: '🖥️', label: 'CONTROLADOR', sublabel: 'Windows Server 2012 R2',
        ip: '192.168.1.10',
        color: '#ff3860', type: 'server', vuln: true,
        detail: {
          name: 'Controlador de Dominio — Windows Server 2012 R2', type: 'SERVIDOR — DOMAIN CONTROLLER (AD DS)',
          icon: '🖥️',
          specs: [
            { k: 'SO', v: 'Windows Server 2012 R2 (Build 9600)' },
            { k: 'IP', v: '192.168.1.10' },
            { k: 'Máscara / GW', v: '255.255.255.0 / 192.168.1.1' },
            { k: 'Rol principal', v: 'AD DS + DNS + DHCP' },
            { k: 'Dominio', v: 'gestoria.local' },
            { k: 'Antivirus', v: 'Windows Defender (desact.)', cls: 'bad' },
            { k: 'RDP', v: 'Puerto 3389 ABIERTO', cls: 'bad' },
            { k: 'SMBv1', v: 'ACTIVADO', cls: 'bad' },
            { k: 'Backup', v: 'SIN CONFIGURAR', cls: 'bad' },
          ],
          vulns: [
            { sev: 'crit', text: 'RDP (puerto 3389) expuesto en red sin autenticación NLA: vulnerable a ataques de fuerza bruta y BlueKeep (CVE-2019-0708)' },
            { sev: 'crit', text: 'SMBv1 activo: vulnerable a EternalBlue/WannaCry (MS17-010). Protocolo obsoleto y sin soporte' },
            { sev: 'high', text: 'Windows Defender desactivado: sin protección contra malware en tiempo real' },
            { sev: 'high', text: 'Política de contraseñas débil: sin longitud mínima, sin complejidad, sin expiración' },
            { sev: 'high', text: 'Sin copias de seguridad configuradas: pérdida total de Active Directory si el servidor falla' },
            { sev: 'med',  text: 'Cuenta de administrador de dominio con nombre por defecto "Administrator"' },
            { sev: 'med',  text: 'Sin auditoría de eventos habilitada: imposible rastrear accesos o cambios' },
          ],
        }
      },
      web: {
        x: 460, y: 480,
        icon: '🌍', label: 'SERVIDOR WEB', sublabel: 'Apache 2.4.41 + SSH',
        ip: '192.168.1.20',
        color: '#ff3860', type: 'server', vuln: true,
        detail: {
          name: 'Servidor Web — Apache + OpenSSH', type: 'SERVIDOR WEB / DEBIAN GNU/LINUX 10',
          icon: '🌍',
          specs: [
            { k: 'SO', v: 'Debian GNU/Linux 10 (Buster)' },
            { k: 'IP', v: '192.168.1.20' },
            { k: 'Máscara / GW', v: '255.255.255.0 / 192.168.1.1' },
            { k: 'Apache', v: '2.4.41 — DESACTUALIZADO', cls: 'bad' },
            { k: 'OpenSSH', v: '7.9p1 — DESACTUALIZADO', cls: 'bad' },
            { k: 'Puerto SSH', v: '22 (por defecto)', cls: 'bad' },
            { k: 'TLS/HTTPS', v: 'NO CONFIGURADO', cls: 'bad' },
            { k: 'Certificado', v: 'Ninguno / HTTP plano', cls: 'bad' },
            { k: 'Actualizaciones', v: 'Sin aplicar (apt pendiente)', cls: 'bad' },
            { k: 'Directory listing', v: 'ACTIVADO', cls: 'bad' },
          ],
          vulns: [
            { sev: 'crit', text: 'Apache 2.4.41: vulnerable a CVE-2021-41773 (path traversal / RCE), CVE-2021-42013 y múltiples CVEs de 2022-2024' },
            { sev: 'crit', text: 'Sin HTTPS: toda la comunicación web en texto plano. Incumplimiento RGPD para datos personales' },
            { sev: 'crit', text: 'SSH en puerto 22 con autenticación por contraseña: expuesto a internet mediante DMZ del router' },
            { sev: 'high', text: 'Directory listing activado: un atacante puede ver todos los archivos del servidor web' },
            { sev: 'high', text: 'OpenSSH 7.9p1 obsoleto: múltiples vulnerabilidades de seguridad conocidas' },
            { sev: 'high', text: 'Servidor en misma red que los puestos de trabajo: si se compromete, el atacante tiene acceso directo a toda la LAN' },
            { sev: 'med',  text: 'Sin WAF (Web Application Firewall): sin protección contra SQL injection, XSS, etc.' },
            { sev: 'med',  text: 'Headers HTTP de seguridad ausentes (X-Frame-Options, CSP, HSTS)' },
          ],
        }
      },
      pcs: {
        x: 730, y: 480,
        icon: '💻', label: '12 EQUIPOS', sublabel: 'Windows 10 (clientes)',
        ip: '192.168.1.100 – .111',
        color: '#ffb800', type: 'clients', vuln: true,
        detail: {
          name: '12 Equipos de trabajo — Windows 10', type: 'PUESTOS DE TRABAJO (12 UNIDADES)',
          icon: '💻',
          specs: [
            { k: 'SO', v: 'Windows 10 Pro 21H1 (mix)' },
            { k: 'Rango IP', v: '192.168.1.100 – .111' },
            { k: 'DHCP', v: 'Servidor DHCP en DC' },
            { k: 'Dominio', v: 'gestoria.local' },
            { k: 'Antivirus', v: 'Sin antivirus centralizado', cls: 'bad' },
            { k: 'Windows Update', v: 'Desactivado en varios', cls: 'bad' },
            { k: 'Puertos USB', v: 'Sin restricción', cls: 'bad' },
            { k: 'Política GPO', v: 'Sin GPOs de seguridad', cls: 'bad' },
          ],
          vulns: [
            { sev: 'crit', text: 'Varios equipos con Windows 10 sin actualizar: vulnerables a Zerologon (CVE-2020-1472), PrintNightmare (CVE-2021-34527)' },
            { sev: 'high', text: 'Sin antivirus centralizado ni EDR: una infección de malware puede propagarse por toda la red' },
            { sev: 'high', text: 'Puertos USB sin restricción: riesgo de extracción de datos o instalación de malware mediante dispositivos externos' },
            { sev: 'high', text: 'Sin políticas GPO de seguridad: usuarios con privilegios de administrador local' },
            { sev: 'med',  text: 'Sin cifrado de disco BitLocker: si un equipo es robado, los datos son accesibles directamente' },
            { sev: 'med',  text: 'Mezcla de versiones Windows 10: dificulta gestión centralizada y parches de seguridad' },
          ],
        }
      },
      printer: {
        x: 995, y: 480,
        icon: '🖨️', label: 'IMPRESORA', sublabel: 'HP LaserJet Pro',
        ip: '192.168.1.200',
        color: '#ff3860', type: 'printer', vuln: true,
        detail: {
          name: 'Impresora — HP LaserJet Pro M404dn', type: 'IMPRESORA DE RED — MUY INSEGURA',
          icon: '🖨️',
          specs: [
            { k: 'Modelo', v: 'HP LaserJet Pro M404dn' },
            { k: 'IP', v: '192.168.1.200 (IP estática)' },
            { k: 'Credenciales web', v: 'admin/admin (por defecto)', cls: 'bad' },
            { k: 'Telnet', v: 'ACTIVADO (puerto 23)', cls: 'bad' },
            { k: 'FTP', v: 'ACTIVADO (puerto 21)', cls: 'bad' },
            { k: 'SNMP', v: 'Community "public"', cls: 'bad' },
            { k: 'Firmware', v: 'Sin actualizar (2019)', cls: 'bad' },
            { k: 'TLS panel web', v: 'HTTP plano', cls: 'bad' },
          ],
          vulns: [
            { sev: 'crit', text: 'Credenciales por defecto (admin/admin): cualquier usuario de la red tiene acceso total de administración' },
            { sev: 'crit', text: 'Telnet activado (puerto 23): protocolo sin cifrado, credenciales viajan en texto plano' },
            { sev: 'high', text: 'FTP activo (puerto 21): permite acceso a los trabajos de impresión almacenados. Datos confidenciales de la gestoría expuestos' },
            { sev: 'high', text: 'SNMP con community "public": un atacante puede obtener información detallada del dispositivo y modificar su configuración' },
            { sev: 'high', text: 'Firmware de 2019 sin actualizar: múltiples CVEs en la serie M404 (CVE-2021-39237, CVE-2021-39238)' },
            { sev: 'med',  text: 'Sin separación de VLAN: la impresora tiene acceso directo a los servidores y equipos de la red' },
            { sev: 'low',  text: 'Sin logging de trabajos de impresión: imposible auditar quién ha impreso qué documentos (incumplimiento RGPD)' },
          ],
        }
      }
    }
  },

  // ─────────────────────── DESPUÉS ───────────────────────
  after: {
    title: 'RED DESPUÉS DE LA AUDITORÍA — SECURIZADA',
    riskLabel: 'RIESGO REDUCIDO',
    riskClass: 'safe',
    titleClass: 'status-safe',
    statusVulns: '<span class="sv green">23 resueltas</span>',
    statusFirewall: '<span class="sv green">Debian 13 + iptables activo</span>',
    statusDmz: '<span class="sv green">DMZ aislada (172.16.1.0/24)</span>',
    statusCompliance: '<span class="sv green">CUMPLIMIENTO RGPD</span>',
    info: '<strong>[ ESTADO TRAS AUDITORÍA ]</strong> Red NAT con salida a internet · Firewall Debian 13 + iptables entre DMZ y LAN · Servidor web en DMZ aislado · DC protegido en red interna · Impresora en red interna · SSH en puerto no estándar + clave pública · Apache actualizado + HTTPS TLS 1.3 · <strong>RGPD cumplido</strong>',

    zones: [
      { id: 'zone-dmz',  x: 200, y: 165,  w: 800, h: 240, color: '#b57bff', label: 'ZONA DMZ — 172.16.1.0/24 (RED NAT)' },
      { id: 'zone-lan',  x: 130, y: 580, w: 940, h: 270, color: '#00ff99', label: 'RED LAN INTERNA — 192.168.0.0/24' },
    ],

    connections: [
      { from: 'internet',  to: 'swdmz',    color: '#00c8ff', dash: false },
      { from: 'swdmz',     to: 'web2',     color: '#b57bff', dash: false },
      { from: 'swdmz',     to: 'fw',       color: '#b57bff', dash: false },
      { from: 'fw',        to: 'swlan',    color: '#00ff99', dash: false },
      { from: 'swlan',     to: 'dc2',      color: '#00ff99', dash: false },
      { from: 'swlan',     to: 'pcs2',     color: '#00ff99', dash: false },
      { from: 'swlan',     to: 'printer2', color: '#00ff99', dash: true  },
      { from: 'swlan',     to: 'admin',    color: '#00ff99', dash: false },
      { from: 'admin',     to: 'dc2',      color: '#ffb800', dash: true  },
      { from: 'admin',     to: 'web2',     color: '#ffb800', dash: true  },
    ],

    nodes: {
      internet: {
        x: 600, y: 75,
        icon: '🌐', label: 'INTERNET', sublabel: 'WAN / ISP (NAT)',
        ip: '83.56.142.19 (WAN · NAT)',
        color: '#00c8ff', type: 'internet',
        detail: {
          name: 'Conexión a Internet (NAT)', type: 'WAN / ISP Telefónica — RED NAT',
          icon: '🌐',
          specs: [
            { k: 'Proveedor ISP', v: 'Telefónica España' },
            { k: 'IP pública (WAN)', v: '83.56.142.19' },
            { k: 'Tipo', v: 'Fibra óptica FTTH' },
            { k: 'Ancho de banda', v: '600 Mbps ↓ / 300 Mbps ↑' },
            { k: 'NAT', v: 'Activo — traducción de direcciones', cls: 'ok' },
            { k: 'Protegido por', v: 'Debian 13 + iptables', cls: 'ok' },
          ],
          fixes: [
            'Red NAT configurada: las direcciones internas no son visibles desde internet',
            'Todo el tráfico externo pasa por la DMZ antes de alcanzar la red interna',
            'Solo los puertos 80 (HTTP→redirect) y 443 (HTTPS) están expuestos al exterior, dirigidos a la DMZ',
            'IDS/IPS Suricata monitoriza el tráfico entrante en tiempo real',
          ],
        }
      },
      swdmz: {
        x: 600, y: 235,
        icon: '🔀', label: 'SW DMZ', sublabel: 'Cisco SG250-08',
        ip: 'Sin IP — Bridge VirtualBox',
        color: '#b57bff', type: 'switch',
        detail: {
          name: 'Switch DMZ', type: 'SWITCH — ZONA DMZ',
          icon: '🔀',
          specs: [],
          fixes: [],
        }
      },
      web2: {
        x: 460, y: 345,
        icon: '🌍', label: 'SERVIDOR WEB', sublabel: 'Apache 2.4.62 + SSH',
        ip: '172.16.1.10',
        color: '#b57bff', type: 'server',
        detail: {
          name: 'Servidor Web — Apache 2.4.62 (DMZ)', type: 'SERVIDOR WEB SECURIZADO — ZONA DMZ',
          icon: '🌍',
          specs: [
            { k: 'SO', v: 'Debian GNU/Linux 12 (Bookworm)', cls: 'ok' },
            { k: 'IP', v: '172.16.1.10 (DMZ)' },
            { k: 'Apache', v: '2.4.62 — ACTUALIZADO', cls: 'ok' },
            { k: 'OpenSSH', v: '9.4p1 — Puerto 2222', cls: 'ok' },
            { k: 'HTTPS/TLS', v: 'TLS 1.3 + cert. Let\'s Encrypt', cls: 'ok' },
            { k: 'WAF', v: 'ModSecurity OWASP CRS 3.3', cls: 'ok' },
            { k: 'Headers HTTP', v: 'HSTS, CSP, X-Frame-Options', cls: 'ok' },
            { k: 'Acceso SSH', v: 'Solo clave pública', cls: 'ok' },
          ],
          fixes: [
            'Servidor movido a DMZ: si es comprometido, no tiene acceso directo a la red interna',
            'Apache 2.4.62 actualizado: todos los CVEs críticos parcheados (jul 2024)',
            'HTTPS obligatorio con TLS 1.3 y certificado Let\'s Encrypt: cumple RGPD para datos en tránsito',
            'SSH en puerto 2222 con autenticación exclusiva por clave pública: elimina riesgo de fuerza bruta',
            'ModSecurity con OWASP CRS: protección contra SQL injection, XSS, CSRF, etc.',
            'Directory listing desactivado, headers de seguridad configurados',
            'Actualizaciones automáticas de seguridad (unattended-upgrades)',
          ],
        }
      },
      fw: {
        x: 740, y: 493,
        icon: '🛡️', label: 'FIREWALL', sublabel: 'Debian 13 + iptables',
        ip: 'DMZ: 172.16.1.1 | LAN: 192.168.0.1',
        color: '#00ff99', type: 'firewall',
        detail: {
          name: 'Firewall — Debian 13 + iptables', type: 'FIREWALL ENTRE DMZ Y LAN',
          icon: '🛡️',
          specs: [
            { k: 'SO', v: 'Debian GNU/Linux 13 (Trixie)', cls: 'ok' },
            { k: 'Firewall', v: 'iptables + iptables-persistent', cls: 'ok' },
            { k: 'IP DMZ (eth0)', v: '172.16.1.1 /24' },
            { k: 'IP LAN (eth1)', v: '192.168.0.1 /24' },
            { k: 'IP Forwarding', v: 'Activo (net.ipv4.ip_forward=1)', cls: 'ok' },
            { k: 'Política por defecto', v: 'DROP en INPUT y FORWARD', cls: 'ok' },
            { k: 'NAT/Masquerade', v: 'MASQUERADE en interfaz DMZ', cls: 'ok' },
            { k: 'IDS/IPS', v: 'Suricata 7.x + iptables NFQUEUE', cls: 'ok' },
            { k: 'VPN', v: 'OpenVPN + iptables tun0', cls: 'ok' },
            { k: 'Logging', v: 'rsyslog → /var/log/iptables.log', cls: 'ok' },
            { k: 'Reglas persistentes', v: 'iptables-save / netfilter-persistent', cls: 'ok' },
          ],
          fixes: [
            'Política por defecto DROP: todo tráfico bloqueado salvo lo explícitamente permitido (iptables -P INPUT DROP / FORWARD DROP)',
            'Separación entre DMZ (172.16.1.0/24) y LAN (192.168.0.0/24) mediante interfaces eth0 y eth1',
            'Reglas FORWARD: DMZ→LAN bloqueado por defecto; LAN puede conectar a DMZ solo puerto 443',
            'NAT con MASQUERADE: la LAN sale a internet a través de la DMZ con traducción de direcciones',
            'Suricata en modo IPS via NFQUEUE: los paquetes pasan por el motor de detección antes de ser aceptados',
            'OpenVPN sobre tun0 con reglas iptables específicas: acceso remoto seguro sin exponer la LAN',
            'Logging de paquetes denegados: iptables -j LOG --log-prefix "DROPPED: " para auditoría RGPD',
            'iptables-persistent: reglas guardadas con iptables-save y restauradas automáticamente al arranque',
          ],
        }
      },
      swlan: {
        x: 600, y: 655,
        icon: '🔀', label: 'SW LAN', sublabel: 'Cisco SG350-28',
        ip: 'Sin IP — Bridge VirtualBox',
        color: '#00ff99', type: 'switch',
        detail: {
          name: 'Switch LAN', type: 'SWITCH — RED INTERNA',
          icon: '🔀',
          specs: [],
          fixes: [],
        }
      },
      dc2: {
        x: 300, y: 790,
        icon: '🖥️', label: 'CONTROLADOR', sublabel: 'Windows Server 2022',
        ip: '192.168.0.10',
        color: '#00ff99', type: 'server',
        detail: {
          name: 'Controlador de Dominio — Windows Server 2022', type: 'SERVIDOR — AD DS + DNS + DHCP (SEGURO)',
          icon: '🖥️',
          specs: [
            { k: 'SO', v: 'Windows Server 2022 (Build 20348)', cls: 'ok' },
            { k: 'IP', v: '192.168.0.10 (LAN interna)' },
            { k: 'Actualizaciones', v: 'Al día (Windows Update)', cls: 'ok' },
            { k: 'Antivirus', v: 'Microsoft Defender + EDR', cls: 'ok' },
            { k: 'SMBv1', v: 'DESACTIVADO', cls: 'ok' },
            { k: 'RDP', v: 'Solo desde IPs admin + NLA', cls: 'ok' },
            { k: 'Backup', v: 'Backup diario configurado', cls: 'ok' },
            { k: 'Auditoría', v: 'GPO completa activada', cls: 'ok' },
          ],
          fixes: [
            'Actualizado a Windows Server 2022: arquitectura más segura y soporte hasta 2031',
            'SMBv1 desactivado: eliminado riesgo de EternalBlue/WannaCry',
            'RDP restringido por IP + NLA obligatorio: solo acceden los administradores desde equipos autorizados',
            'GPOs de seguridad: contraseñas complejas (min. 12 chars), BitLocker, AppLocker',
            'Backup diario automático configurado: RPO de 24h, RTO de 2h',
            'Auditoría completa de eventos habilitada: cumple art. 32 RGPD',
          ],
        }
      },
      pcs2: {
        x: 540, y: 790,
        icon: '💻', label: '12 EQUIPOS', sublabel: 'Windows 11 Pro (dom.)',
        ip: '192.168.0.100 – .111',
        color: '#00ff99', type: 'clients',
        detail: {
          name: '12 Equipos de trabajo — Windows 11 Pro', type: 'PUESTOS DE TRABAJO SECURIZADOS (12 UNIDADES)',
          icon: '💻',
          specs: [
            { k: 'SO', v: 'Windows 11 Pro 23H2', cls: 'ok' },
            { k: 'Rango IP', v: '192.168.0.100 – .111' },
            { k: 'Antivirus', v: 'Defender for Business (EDR)', cls: 'ok' },
            { k: 'Actualizaciones', v: 'Windows Update automático', cls: 'ok' },
            { k: 'BitLocker', v: 'Cifrado de disco activo', cls: 'ok' },
            { k: 'USB', v: 'Restringido por GPO', cls: 'ok' },
            { k: 'Privilegios', v: 'Usuarios estándar (no admin)', cls: 'ok' },
          ],
          fixes: [
            'Actualizados a Windows 11 Pro: soporte hasta 2031, mejoras de seguridad nativas',
            'BitLocker activado por GPO: datos protegidos ante robo de equipos',
            'USB restringido por GPO: solo dispositivos de empresa autorizados',
            'Usuarios sin privilegios de administrador local: contención de malware',
            'AppLocker: solo aplicaciones aprobadas pueden ejecutarse',
          ],
        }
      },
      printer2: {
        x: 760, y: 790,
        icon: '🖨️', label: 'IMPRESORA', sublabel: 'HP LaserJet (segura)',
        ip: '192.168.0.200',
        color: '#00c8ff', type: 'printer',
        detail: {
          name: 'Impresora — HP LaserJet Pro M404dn (segura)', type: 'IMPRESORA DE RED — ASEGURADA',
          icon: '🖨️',
          specs: [
            { k: 'Modelo', v: 'HP LaserJet Pro M404dn' },
            { k: 'IP', v: '192.168.0.200' },
            { k: 'Credenciales', v: 'Contraseña fuerte configurada', cls: 'ok' },
            { k: 'Telnet', v: 'DESACTIVADO', cls: 'ok' },
            { k: 'FTP', v: 'DESACTIVADO', cls: 'ok' },
            { k: 'SNMP', v: 'SNMPv3 + community privada', cls: 'ok' },
            { k: 'Firmware', v: 'Actualizado (v20230524)', cls: 'ok' },
            { k: 'Acceso', v: 'Solo IPs autorizadas', cls: 'ok' },
          ],
          fixes: [
            'Telnet y FTP desactivados: eliminados protocolos inseguros. Solo IPP/HTTPS para gestión',
            'Contraseña de administración cambiada: mínimo 12 caracteres + complejidad',
            'Firmware actualizado a la versión 20230524: todos los CVEs conocidos parcheados',
            'Acceso restringido: la impresora solo puede comunicarse con los PCs autorizados',
            'SNMPv3 con autenticación: reemplaza el antiguo SNMP v1 sin cifrado',
            'Logging de trabajos: registro de quién imprime qué (cumple RGPD trazabilidad)',
          ],
        }
      },
      admin: {
        x: 480, y: 493,
        icon: '👨‍💻', label: 'PC ADMIN', sublabel: 'Administrador de red',
        ip: '192.168.0.50',
        color: '#ffb800', type: 'admin',
        detail: {
          name: 'Equipo Administrador de Red', type: 'PUESTO DE ADMINISTRACIÓN — PRIVILEGIADO',
          icon: '👨‍💻',
          specs: [
            { k: 'SO', v: 'Windows 11 Pro 23H2', cls: 'ok' },
            { k: 'IP', v: '192.168.0.50' },
            { k: 'Máscara / GW', v: '255.255.255.0 / 192.168.0.1' },
            { k: 'Acceso RDP', v: 'Solo a DC (192.168.0.10)', cls: 'ok' },
            { k: 'Acceso SSH', v: 'Solo a Web (172.16.1.10:2222)', cls: 'ok' },
            { k: 'Autenticación', v: 'MFA + clave pública SSH', cls: 'ok' },
            { k: 'BitLocker', v: 'Cifrado completo activo', cls: 'ok' },
            { k: 'Antivirus', v: 'Defender for Business (EDR)', cls: 'ok' },
            { k: 'Acceso a internet', v: 'Restringido por firewall', cls: 'ok' },
            { k: 'Sesión', v: 'Cuenta de dominio con privilegios admin', cls: 'ok' },
          ],
          fixes: [
            'Único equipo autorizado para conectar por RDP al Controlador de Dominio (192.168.0.10:3389) — regla iptables específica: solo esta IP origen puede alcanzar el puerto 3389',
            'Único equipo autorizado para conectar por SSH al servidor web en la DMZ (172.16.1.10 puerto 2222) — regla iptables en la cadena FORWARD que bloquea el resto de IPs',
            'MFA obligatorio: autenticación de dos factores para todas las sesiones administrativas',
            'El acceso privilegiado se controla exclusivamente mediante reglas iptables en el firewall, no por segmentación VLAN',
            'Acceso a internet bloqueado por defecto en el firewall: solo puede acceder a repositorios de actualizaciones',
            'BitLocker activo: si el equipo es robado, las credenciales de administración están protegidas',
            'Todos los accesos administrativos quedan registrados en el SIEM Wazuh (trazabilidad RGPD art. 32)',
          ],
        }
      }
    }
  }
};

/* ═══════════════════════════════════════════════════════════════
   STATE
═══════════════════════════════════════════════════════════════ */
let currentNet = 'before';
let showVulns = false;

/* ═══════════════════════════════════════════════════════════════
   SVG RENDERER
═══════════════════════════════════════════════════════════════ */
const SVG_NS = 'http://www.w3.org/2000/svg';

function makeSvgEl(tag, attrs) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

function renderNetwork(netId) {
  const net = NETWORKS[netId];
  const svg = document.getElementById('netSvg');
  svg.innerHTML = '';

  // Dynamic viewBox per network
  const vbHeight = netId === 'before' ? 620 : 880;
  svg.setAttribute('viewBox', `0 0 1200 ${vbHeight}`);

  // Defs (markers, filters)
  const defs = makeSvgEl('defs', {});

  // Arrow markers
  for (const [id, color] of [['arr-blue','#00c8ff'],['arr-green','#00ff99'],['arr-red','#ff3860'],['arr-purple','#b57bff'],['arr-yellow','#ffb800'],['arr-gold','#ffb800']]) {
    const m = makeSvgEl('marker', { id, markerWidth:'8', markerHeight:'8', refX:'6', refY:'3', orient:'auto' });
    const p = makeSvgEl('path', { d:'M0,0 L0,6 L8,3 z', fill: color, opacity:'0.7' });
    m.appendChild(p); defs.appendChild(m);
  }

  // Glow filter
  const filter = makeSvgEl('filter', { id: 'glow', x: '-50%', y: '-50%', width: '200%', height: '200%' });
  const fe1 = makeSvgEl('feGaussianBlur', { in: 'SourceGraphic', stdDeviation: '3', result: 'blur' });
  const fe2 = makeSvgEl('feMerge', {});
  const feMN1 = makeSvgEl('feMergeNode', { in: 'blur' });
  const feMN2 = makeSvgEl('feMergeNode', { in: 'SourceGraphic' });
  fe2.appendChild(feMN1); fe2.appendChild(feMN2);
  filter.appendChild(fe1); filter.appendChild(fe2);
  defs.appendChild(filter);

  svg.appendChild(defs);

  // Background subtle gradient
  const bgRect = makeSvgEl('rect', { x:'0', y:'0', width:'1200', height: String(vbHeight), fill:'url(#bgGrad)' });
  const bgGrad = makeSvgEl('radialGradient', { id:'bgGrad', cx:'50%', cy:'50%', r:'60%' });
  const bgS1 = makeSvgEl('stop', { offset:'0%', 'stop-color':'#0a1428', 'stop-opacity':'1' });
  const bgS2 = makeSvgEl('stop', { offset:'100%', 'stop-color':'#060a14', 'stop-opacity':'1' });
  bgGrad.appendChild(bgS1); bgGrad.appendChild(bgS2);
  defs.appendChild(bgGrad);
  svg.appendChild(bgRect);

  // Zones
  if (net.zones) {
    for (const z of net.zones) {
      const zg = makeSvgEl('g', {});

      const zRect = makeSvgEl('rect', {
        x: z.x, y: z.y, width: z.w, height: z.h,
        fill: z.color, 'fill-opacity': '0.04',
        stroke: z.color, 'stroke-opacity': '0.3',
        'stroke-width': '1.5',
        'stroke-dasharray': '6,4',
        rx: '4'
      });
      zg.appendChild(zRect);

      const zLabel = makeSvgEl('text', {
        x: z.x + 14, y: z.y + 18,
        fill: z.color, 'fill-opacity': '0.7',
        'font-family': '"Share Tech Mono", monospace',
        'font-size': '11',
        'letter-spacing': '2'
      });
      zLabel.textContent = z.label;
      zg.appendChild(zLabel);
      svg.appendChild(zg);
    }
  }

  // Helper: get node center
  function getCenter(nodeId) {
    const n = net.nodes[nodeId];
    return { x: n.x, y: n.y };
  }

  // Color for connection
  function getMarker(color) {
    if (color === '#00c8ff') return 'arr-blue';
    if (color === '#00ff99') return 'arr-green';
    if (color === '#ff3860') return 'arr-red';
    if (color === '#b57bff') return 'arr-purple';
    return 'arr-yellow';
  }

  // Connections
  let connIdx = 0;
  for (const conn of net.connections) {
    const a = getCenter(conn.from);
    const b = getCenter(conn.to);
    const pathId = `connPath_${connIdx++}`;
    const dur = (2.2 + Math.random() * 2).toFixed(2);

    // Define path in defs for animateMotion reuse
    const pathEl = makeSvgEl('path', {
      id: pathId,
      d: `M${a.x},${a.y} L${b.x},${b.y}`,
      fill: 'none', stroke: 'none'
    });
    defs.appendChild(pathEl);

    // Glow line
    const gline = makeSvgEl('line', {
      x1: a.x, y1: a.y, x2: b.x, y2: b.y,
      stroke: conn.color, 'stroke-width': '4',
      opacity: '0.08',
      'stroke-dasharray': conn.dash ? '8,5' : 'none'
    });
    svg.appendChild(gline);

    // Main line
    const line = makeSvgEl('line', {
      x1: a.x, y1: a.y, x2: b.x, y2: b.y,
      stroke: conn.color, 'stroke-width': '1.5',
      opacity: '0.6',
      'stroke-dasharray': conn.dash ? '8,5' : 'none',
      'marker-end': `url(#${getMarker(conn.color)})`
    });
    svg.appendChild(line);

    // Traffic dot — animateMotion follows the exact path
    const animDot = makeSvgEl('circle', {
      r: '3', fill: conn.color, opacity: '0.85',
      filter: 'url(#glow)'
    });
    const motion = makeSvgEl('animateMotion', {
      dur: `${dur}s`,
      repeatCount: 'indefinite',
      calcMode: 'linear'
    });
    const mpath = makeSvgEl('mpath', {});
    mpath.setAttributeNS('http://www.w3.org/1999/xlink', 'href', `#${pathId}`);
    motion.appendChild(mpath);
    animDot.appendChild(motion);
    svg.appendChild(animDot);
  }

  // Nodes
  let nodeClipIdx = 0;
  for (const [nodeId, node] of Object.entries(net.nodes)) {
    const NW = 128, NH = 82;
    const nx = -NW/2, ny = -NH/2;

    // Per-node clipPath so text never bleeds outside the box
    const clipId = `nodeClip_${nodeClipIdx++}`;
    const clipPath = makeSvgEl('clipPath', { id: clipId });
    const clipRect = makeSvgEl('rect', {
      x: nx + 2, y: ny + 2,
      width: NW - 4, height: NH - 4,
      rx: '3'
    });
    clipPath.appendChild(clipRect);
    defs.appendChild(clipPath);

    const g = makeSvgEl('g', {
      class: 'node-group',
      transform: `translate(${node.x}, ${node.y})`,
      'data-node': nodeId,
      style: 'cursor:pointer'
    });

    // Shadow
    const shadow = makeSvgEl('rect', {
      x: nx+3, y: ny+3, width: NW, height: NH,
      rx: '4', fill: node.color, opacity: '0.08'
    });
    g.appendChild(shadow);

    // Admin node: extra outer ring to make it stand out
    if (node.type === 'admin') {
      const outerRing = makeSvgEl('rect', {
        x: nx-5, y: ny-5, width: NW+10, height: NH+10,
        rx: '7', fill: 'none',
        stroke: '#ffb800', 'stroke-width': '1',
        'stroke-dasharray': '4,3',
        opacity: '0.5'
      });
      const ringAnim = makeSvgEl('animateTransform', {
        attributeName: 'transform', type: 'rotate',
        from: `0 0 0`, to: `360 0 0`,
        dur: '12s', repeatCount: 'indefinite'
      });
      // Pulsing opacity instead of rotation for a rect
      const pulseAnim = makeSvgEl('animate', {
        attributeName: 'opacity',
        values: '0.3;0.7;0.3', dur: '2.5s', repeatCount: 'indefinite'
      });
      outerRing.appendChild(pulseAnim);
      g.appendChild(outerRing);

      const adminLabel = makeSvgEl('text', {
        x: '0', y: ny - 12,
        'text-anchor': 'middle',
        fill: '#ffb800',
        'font-family': '"Share Tech Mono", monospace',
        'font-size': '8',
        'letter-spacing': '2',
        opacity: '0.8'
      });
      adminLabel.textContent = '[ ADMIN ]';
      g.appendChild(adminLabel);
    }

    // Main rect
    const rect = makeSvgEl('rect', {
      x: nx, y: ny, width: NW, height: NH,
      rx: '4',
      fill: '#0b1222',
      stroke: node.color,
      'stroke-width': '1.5',
      opacity: '0.95',
      class: 'node-rect'
    });
    g.appendChild(rect);

    // Color accent top bar
    const topBar = makeSvgEl('rect', {
      x: nx, y: ny, width: NW, height: '3',
      rx: '4', fill: node.color, opacity: '0.6'
    });
    g.appendChild(topBar);

    // Clipped content group — text stays inside box
    const contentG = makeSvgEl('g', { 'clip-path': `url(#${clipId})` });

    // Icon (outside clip is fine — emoji just needs centering)
    const iconEl = makeSvgEl('text', {
      x: '0', y: '-12',
      'text-anchor': 'middle',
      'dominant-baseline': 'middle',
      'font-size': '20',
      style: 'filter: drop-shadow(0 0 4px ' + node.color + '44)'
    });
    iconEl.textContent = node.icon;
    contentG.appendChild(iconEl);

    // Label
    const labelEl = makeSvgEl('text', {
      x: '0', y: '10',
      'text-anchor': 'middle',
      'dominant-baseline': 'middle',
      fill: '#ffffff',
      'font-family': '"Exo 2", sans-serif',
      'font-size': '10.5',
      'font-weight': '700',
      'letter-spacing': '0.4'
    });
    labelEl.textContent = node.label;
    contentG.appendChild(labelEl);

    // Sublabel — truncate to fit inside NW-8 px
    const sublabEl = makeSvgEl('text', {
      x: '0', y: '23',
      'text-anchor': 'middle',
      'dominant-baseline': 'middle',
      fill: node.color,
      'fill-opacity': '0.75',
      'font-family': '"Share Tech Mono", monospace',
      'font-size': '8',
      'letter-spacing': '0.2'
    });
    const sub = node.sublabel;
    sublabEl.textContent = sub.length > 20 ? sub.substring(0, 19) + '…' : sub;
    contentG.appendChild(sublabEl);

    // IP line — hard truncate at 19 chars, font tiny
    const ipEl = makeSvgEl('text', {
      x: '0', y: '35',
      'text-anchor': 'middle',
      'dominant-baseline': 'middle',
      fill: '#ffffff',
      'font-family': '"Share Tech Mono", monospace',
      'font-size': '7',
      'letter-spacing': '0'
    });
    const ipStr = node.ip;
    ipEl.textContent = ipStr.length > 22 ? ipStr.substring(0, 21) + '…' : ipStr;
    contentG.appendChild(ipEl);

    g.appendChild(contentG);

    // Vulnerability indicator
    if (node.vuln && netId === 'before') {
      const vulnG = makeSvgEl('g', { class: 'vuln-indicator', opacity: showVulns ? '1' : '0', style: 'transition:opacity 0.3s' });

      const vCircle = makeSvgEl('circle', {
        cx: NW/2 - 8, cy: -(NH/2) + 8, r: '8',
        fill: '#ff3860'
      });
      vulnG.appendChild(vCircle);

      const vAnim = makeSvgEl('animate', {
        attributeName: 'r', from: '8', to: '12',
        dur: '1.5s', repeatCount: 'indefinite',
        additive: 'sum'
      });
      const vPulse = makeSvgEl('circle', {
        cx: NW/2 - 8, cy: -(NH/2) + 8, r: '8',
        fill: 'none', stroke: '#ff3860', 'stroke-width': '2', opacity: '0.5'
      });
      vPulse.appendChild(vAnim);
      vulnG.appendChild(vPulse);

      const vText = makeSvgEl('text', {
        x: NW/2 - 8, y: -(NH/2) + 12,
        'text-anchor': 'middle',
        fill: '#fff',
        'font-size': '9',
        'font-weight': '700'
      });
      vText.textContent = '!';
      vulnG.appendChild(vText);

      g.appendChild(vulnG);
    }

    // Hover effect
    g.addEventListener('mouseenter', (e) => {
      rect.setAttribute('stroke-width', '2.5');
      rect.setAttribute('fill', '#0f1e35');
      showTooltip(e, node.label + ' — ' + node.ip);
    });
    g.addEventListener('mousemove', (e) => { moveTooltip(e); });
    g.addEventListener('mouseleave', () => {
      rect.setAttribute('stroke-width', '1.5');
      rect.setAttribute('fill', '#0b1222');
      hideTooltip();
    });

    g.addEventListener('click', () => openModal(nodeId));
    svg.appendChild(g);
  }
}

/* ═══════════════════════════════════════════════════════════════
   TOOLTIP
═══════════════════════════════════════════════════════════════ */
const tooltip = document.getElementById('tooltip');

function showTooltip(e, text) {
  tooltip.textContent = text;
  tooltip.style.display = 'block';
  moveTooltip(e);
}
function moveTooltip(e) {
  tooltip.style.left = (e.clientX + 14) + 'px';
  tooltip.style.top  = (e.clientY - 28) + 'px';
}
function hideTooltip() {
  tooltip.style.display = 'none';
}

/* ═══════════════════════════════════════════════════════════════
   MODAL
═══════════════════════════════════════════════════════════════ */
function openModal(nodeId) {
  const net = NETWORKS[currentNet];
  const node = net.nodes[nodeId];
  const d = node.detail;

  document.getElementById('mIcon').textContent = d.icon;
  document.getElementById('mName').textContent = d.name;
  document.getElementById('mType').textContent = d.type;
  document.getElementById('mIp').textContent = '⊕ IP: ' + node.ip;

  let html = '';

  // Specs
  if (d.specs && d.specs.length) {
    html += `<div class="modal-section">
      <div class="section-label">ESPECIFICACIONES TÉCNICAS</div>
      <div class="spec-grid">`;
    for (const s of d.specs) {
      const cls = s.cls ? ` class="spec-val ${s.cls}"` : ' class="spec-val"';
      html += `<div class="spec-cell">
        <div class="spec-key">${s.k}</div>
        <div${cls}>${s.v}</div>
      </div>`;
    }
    html += `</div></div>`;
  }

  // Vulnerabilities (before network) or fixes (after network)
  if (d.vulns && d.vulns.length) {
    const count = d.vulns.length;
    html += `<div class="modal-section">
      <div class="section-label">⚠ VULNERABILIDADES DETECTADAS (${count})</div>`;
    for (const v of d.vulns) {
      html += `<div class="vuln-entry ${v.sev}">
        <span class="sev-badge ${v.sev}">${v.sev.toUpperCase()}</span>
        <span>${v.text}</span>
      </div>`;
    }
    html += `</div>`;
  }

  if (d.fixes && d.fixes.length) {
    html += `<div class="modal-section">
      <div class="section-label">✓ MEDIDAS IMPLEMENTADAS (${d.fixes.length})</div>`;
    for (const f of d.fixes) {
      html += `<div class="fix-entry">
        <span class="fix-check">✔</span>
        <span>${f}</span>
      </div>`;
    }
    html += `</div>`;
  }



  document.getElementById('mBody').innerHTML = html;
  document.getElementById('modalOverlay').classList.add('open');
}

function closeModal(e) {
  if (!e || e.target === document.getElementById('modalOverlay')) {
    document.getElementById('modalOverlay').classList.remove('open');
  }
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
});

/* ═══════════════════════════════════════════════════════════════
   NETWORK SWITCH
═══════════════════════════════════════════════════════════════ */
function showNet(netId) {
  currentNet = netId;
  const net = NETWORKS[netId];

  // Update toggle buttons
  document.getElementById('btnBefore').className = netId === 'before' ? 'active-before' : '';
  document.getElementById('btnAfter').className  = netId === 'after'  ? 'active-after'  : '';

  // Update header
  const diagTitle = document.getElementById('diagTitle');
  diagTitle.className = net.titleClass;
  diagTitle.textContent = net.title;

  const riskBadge = document.getElementById('riskBadge');
  riskBadge.className = `risk-badge ${net.riskClass}`;
  riskBadge.textContent = net.riskLabel;

  // Status footer
  document.getElementById('sfVulns').innerHTML      = 'VULNERABILIDADES: ' + net.statusVulns;
  document.getElementById('sfFirewall').innerHTML   = 'FIREWALL: ' + net.statusFirewall;
  document.getElementById('sfDmz').innerHTML        = 'DMZ: ' + net.statusDmz;
  document.getElementById('sfCompliance').innerHTML = 'RGPD/ENS: ' + net.statusCompliance;

  // Info strip
  document.getElementById('infoStrip').innerHTML = net.info;

  // Re-render
  renderNetwork(netId);
  applyVulnState();
}

/* ═══════════════════════════════════════════════════════════════
   VULNERABILITY TOGGLE
═══════════════════════════════════════════════════════════════ */
function toggleVulns() {
  showVulns = document.getElementById('vulnToggle').checked;
  applyVulnState();
}

function applyVulnState() {
  const indicators = document.querySelectorAll('.vuln-indicator');
  indicators.forEach(el => {
    el.style.opacity = showVulns ? '1' : '0';
  });
}

/* ═══════════════════════════════════════════════════════════════
   INIT
═══════════════════════════════════════════════════════════════ */
window.addEventListener('load', () => {
  showNet('before');
});

window.addEventListener('resize', () => {
  renderNetwork(currentNet);
  applyVulnState();
});
