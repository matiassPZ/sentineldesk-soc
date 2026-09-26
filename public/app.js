let authToken = localStorage.getItem('sentinel_token') || null;
let currentUser = JSON.parse(localStorage.getItem('sentinel_user') || 'null');
let chartPriorityInstance = null;
let chartStatusInstance = null;
let allIncidents = [];
let currentFilteredIncidents = [];
let currentAuditLogs = [];
let currentFilter = 'ALL';
let currentSearch = '';

const authSection = document.getElementById('auth-section');
const dashboardSection = document.getElementById('dashboard-section');
const loginForm = document.getElementById('login-form');
const authError = document.getElementById('auth-error');
const incidentsList = document.getElementById('incidents-list');

// Selectores para Búsqueda y Filtros Rápidos
const incidentSearch = document.getElementById('incident-search');
const btnClearSearch = document.getElementById('btn-clear-search');
const filterPills = document.querySelectorAll('.filter-pill');
const incidentsCounter = document.getElementById('incidents-counter');

// Selectores para Exportación de Reportes Forenses en CSV
const btnExportCSV = document.getElementById('btn-export-csv');
const btnExportAuditCSV = document.getElementById('btn-export-audit-csv');

const modalIncident = document.getElementById('modal-incident');
const btnOpenModal = document.getElementById('btn-open-modal');
const btnCloseModal = document.getElementById('btn-close-modal');
const createIncidentForm = document.getElementById('create-incident-form');

// Selectores para la Consola Forense SIEM (Auditoría ADMIN)
const btnOpenAudit = document.getElementById('btn-open-audit');
const modalAudit = document.getElementById('modal-audit');
const btnCloseAudit = document.getElementById('btn-close-audit');
const btnCloseAuditFooter = document.getElementById('btn-close-audit-footer');
const btnRefreshAudit = document.getElementById('btn-refresh-audit');
const auditLogsContainer = document.getElementById('audit-logs-container');
const auditLogsCount = document.getElementById('audit-logs-count');

// Función de seguridad anti-XSS (Sanitización de caracteres peligrosos)
function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Inicializar sesión si ya existe token
if (authToken && currentUser) {
  showDashboard();
}

// 1. Manejo del Login
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  authError.textContent = '';

  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Fallo de autenticación');

    authToken = data.token;
    currentUser = data.user;
    localStorage.setItem('sentinel_token', authToken);
    localStorage.setItem('sentinel_user', JSON.stringify(currentUser));

    showDashboard();
  } catch (err) {
    authError.textContent = err.message;
  }
});

// 2. Mostrar Dashboard
function showDashboard() {
  authSection.classList.add('hidden');
  dashboardSection.classList.remove('hidden');

  document.getElementById('user-name').textContent = currentUser.name;
  document.getElementById('user-badge').textContent = currentUser.role;

  // Acceso exclusivo a la Consola Forense SIEM para el rol ADMIN
  if (btnOpenAudit) {
    if (currentUser && currentUser.role === 'ADMIN') {
      btnOpenAudit.classList.remove('hidden');
    } else {
      btnOpenAudit.classList.add('hidden');
    }
  }

  loadIncidents();
}

// 3. Cargar Incidentes según Rol (RBAC) con protección XSS
async function loadIncidents() {
  incidentsList.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 2rem;">Cargando telemetría de incidentes...</td></tr>';
  if (incidentsCounter) incidentsCounter.textContent = 'Sincronizando...';

  try {
    const res = await fetch('/api/incidents', {
      headers: { 'Authorization': `Bearer ${authToken}` },
    });

    if (res.status === 401 || res.status === 403) {
      logout();
      return;
    }

    const incidents = await res.json();
    allIncidents = Array.isArray(incidents) ? incidents : [];

    applyFiltersAndRender();
  } catch (err) {
    console.error(err);
    incidentsList.innerHTML = '<tr><td colspan="6" style="color:var(--danger); text-align:center; padding: 2rem;">Error al cargar datos.</td></tr>';
    if (incidentsCounter) incidentsCounter.textContent = 'Error de conexión';
  }
}

// 3.1 Aplicar Filtros Reactivos (Búsqueda textual + Filtros rápidos)
function applyFiltersAndRender() {
  const query = (currentSearch || '').trim().toLowerCase();

  const filtered = allIncidents.filter((inc) => {
    // 1. Filtrado rápido por Estado / Prioridad
    if (currentFilter === 'CRITICAL' && inc.priority !== 'CRITICAL') {
      return false;
    }
    if (currentFilter === 'IN_PROGRESS' && inc.status !== 'IN_PROGRESS') {
      return false;
    }
    if (currentFilter === 'RESOLVED' && inc.status !== 'RESOLVED') {
      return false;
    }

    // 2. Filtrado de búsqueda en texto
    if (query) {
      const title = (inc.title || '').toLowerCase();
      const desc = (inc.description || '').toLowerCase();
      const priority = (inc.priority || '').toLowerCase();
      const status = (inc.status || '').toLowerCase();
      const authorName = (inc.author?.name || '').toLowerCase();
      const authorEmail = (inc.author?.email || '').toLowerCase();

      const matches =
        title.includes(query) ||
        desc.includes(query) ||
        priority.includes(query) ||
        status.includes(query) ||
        authorName.includes(query) ||
        authorEmail.includes(query);

      if (!matches) return false;
    }

    return true;
  });

  // Guardar copia filtrada para la exportación ejecutiva
  currentFilteredIncidents = filtered;

  // Renderizar la tabla con los incidentes filtrados
  renderIncidentsTable(filtered);

  // Actualizar contador en la barra superior de la tabla
  if (incidentsCounter) {
    if (allIncidents.length === 0) {
      incidentsCounter.textContent = '0 incidentes registrados en el sistema';
    } else if (filtered.length === allIncidents.length) {
      incidentsCounter.textContent = `Mostrando todos los ${allIncidents.length} incidentes`;
    } else {
      incidentsCounter.textContent = `Mostrando ${filtered.length} de ${allIncidents.length} incidentes filtrados`;
    }
  }

  // Reflejar la telemetría filtrada en las tarjetas KPI y gráficos Chart.js
  updateKPIs(filtered);
  renderCharts(filtered);
}

// 3.2 Renderizado seguro de la tabla de incidentes
function renderIncidentsTable(incidents) {
  incidentsList.innerHTML = '';

  if (!Array.isArray(incidents) || incidents.length === 0) {
    incidentsList.innerHTML = `
      <tr>
        <td colspan="6" style="text-align:center; padding: 2.5rem; color: var(--text-muted);">
          🔍 No se encontraron incidentes que coincidan con los criterios de búsqueda o filtro.
        </td>
      </tr>
    `;
    return;
  }

  incidents.forEach((inc) => {
    const tr = document.createElement('tr');
    const canEdit = currentUser.role === 'ADMIN' || currentUser.role === 'TECH';

    // Sanitizamos título y descripción para que ningún script se ejecute (Anti-XSS)
    const safeTitle = escapeHtml(inc.title);
    const safeDescription = escapeHtml(inc.description);
    const safeAuthor = inc.author ? escapeHtml(inc.author.name) : 'Sistema';

    tr.innerHTML = `
      <td>
        <strong>${safeTitle}</strong>
        <p style="font-size:0.85rem; color:var(--text-muted); margin-top:0.25rem;">${safeDescription}</p>
      </td>
      <td class="priority-${inc.priority}">${inc.priority}</td>
      <td><span class="status-badge status-${inc.status}">${inc.status}</span></td>
      <td>${safeAuthor}</td>
      <td style="font-size:0.85rem; color:var(--text-muted);">${new Date(inc.createdAt).toLocaleString()}</td>
      <td>
        ${canEdit ? `
          <select onchange="updateStatus('${inc.id}', this.value)" style="padding: 0.3rem; background:#1f2937; color:#fff; border:1px solid #374151; border-radius:4px;">
            <option value="OPEN" ${inc.status === 'OPEN' ? 'selected' : ''}>OPEN</option>
            <option value="IN_PROGRESS" ${inc.status === 'IN_PROGRESS' ? 'selected' : ''}>IN_PROGRESS</option>
            <option value="RESOLVED" ${inc.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option>
          </select>
        ` : '<span style="font-size:0.8rem; color:var(--text-muted);">Solo Lectura</span>'}
      </td>
    `;
    incidentsList.appendChild(tr);
  });
}

// Función auxiliar para actualizar los números de las tarjetas KPI
function updateKPIs(incidents) {
  const critical = incidents.filter(i => i.priority === 'CRITICAL' && i.status !== 'RESOLVED').length;
  const inProgress = incidents.filter(i => i.status === 'IN_PROGRESS').length;
  const resolved = incidents.filter(i => i.status === 'RESOLVED').length;
  const total = incidents.length;

  const elCrit = document.getElementById('kpi-critical');
  const elProg = document.getElementById('kpi-in-progress');
  const elRes = document.getElementById('kpi-resolved');
  const elTot = document.getElementById('kpi-total');

  if (elCrit) elCrit.textContent = critical;
  if (elProg) elProg.textContent = inProgress;
  if (elRes) elRes.textContent = resolved;
  if (elTot) elTot.textContent = total;
}

// =========================================
// Analítica Visual Interactiva con Chart.js
// =========================================
function renderCharts(incidents) {
  if (typeof Chart === 'undefined') {
    console.warn('[SentinelDesk] Chart.js no se encuentra disponible.');
    return;
  }

  const canvasPriority = document.getElementById('chart-priority');
  const canvasStatus = document.getElementById('chart-status');

  if (!canvasPriority || !canvasStatus) return;

  // 1. Destrucción de instancias previas para evitar "Canvas is already in use"
  if (chartPriorityInstance) {
    chartPriorityInstance.destroy();
    chartPriorityInstance = null;
  }
  if (chartStatusInstance) {
    chartStatusInstance.destroy();
    chartStatusInstance = null;
  }

  // 2. Agregación de datos de incidentes
  const priorityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const statusCounts = { OPEN: 0, IN_PROGRESS: 0, RESOLVED: 0 };

  const safeIncidents = Array.isArray(incidents) ? incidents : [];
  safeIncidents.forEach((inc) => {
    if (Object.prototype.hasOwnProperty.call(priorityCounts, inc.priority)) {
      priorityCounts[inc.priority]++;
    }
    if (Object.prototype.hasOwnProperty.call(statusCounts, inc.status)) {
      statusCounts[inc.status]++;
    }
  });

  // Configuración de Tooltips para SOC Dark Theme
  const darkTooltipConfig = {
    backgroundColor: '#111827',
    borderColor: '#374151',
    borderWidth: 1,
    titleColor: '#f9fafb',
    titleFont: { family: "'Inter', sans-serif", weight: '600', size: 12 },
    bodyColor: '#d1d5db',
    bodyFont: { family: "'Inter', sans-serif", size: 12 },
    padding: 10,
    cornerRadius: 8,
    boxPadding: 4,
    usePointStyle: true,
  };

  // 3. Gráfico de Dona: Distribución de Severidad
  const ctxPriority = canvasPriority.getContext('2d');
  chartPriorityInstance = new Chart(ctxPriority, {
    type: 'doughnut',
    data: {
      labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
      datasets: [
        {
          data: [
            priorityCounts.CRITICAL,
            priorityCounts.HIGH,
            priorityCounts.MEDIUM,
            priorityCounts.LOW,
          ],
          backgroundColor: [
            '#ef4444', // Rojo crítico
            '#f59e0b', // Naranja alto
            '#3b82f6', // Azul medio
            '#9ca3af', // Gris bajo
          ],
          borderColor: '#111827',
          borderWidth: 2,
          hoverOffset: 6,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#9ca3af',
            font: {
              family: "'Inter', sans-serif",
              size: 12,
              weight: '500',
            },
            padding: 14,
            usePointStyle: true,
            pointStyle: 'circle',
          },
        },
        tooltip: {
          ...darkTooltipConfig,
          callbacks: {
            label: function (context) {
              const label = context.label || '';
              const value = Number(context.raw) || 0;
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : '0.0';
              return ` ${label}: ${value} (${percentage}%)`;
            },
          },
        },
      },
    },
  });

  // 4. Gráfico de Barras: Estado Operativo de Mitigación
  const ctxStatus = canvasStatus.getContext('2d');
  chartStatusInstance = new Chart(ctxStatus, {
    type: 'bar',
    data: {
      labels: ['OPEN', 'IN_PROGRESS', 'RESOLVED'],
      datasets: [
        {
          label: 'Incidentes',
          data: [
            statusCounts.OPEN,
            statusCounts.IN_PROGRESS,
            statusCounts.RESOLVED,
          ],
          backgroundColor: [
            '#4b5563', // Gris azulado
            '#d97706', // Ámbar
            '#10b981', // Esmeralda
          ],
          borderRadius: 6,
          borderSkipped: false,
          maxBarThickness: 52,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false,
        },
        tooltip: {
          ...darkTooltipConfig,
          callbacks: {
            label: function (context) {
              return ` Tickets: ${context.raw}`;
            },
          },
        },
      },
      scales: {
        x: {
          grid: {
            display: false,
          },
          ticks: {
            color: '#9ca3af',
            font: {
              family: "'JetBrains Mono', monospace",
              size: 11,
              weight: '600',
            },
          },
          border: {
            color: '#374151',
          },
        },
        y: {
          beginAtZero: true,
          grid: {
            color: '#1f2937',
          },
          ticks: {
            color: '#9ca3af',
            stepSize: 1,
            precision: 0,
            font: {
              family: "'JetBrains Mono', monospace",
              size: 11,
            },
          },
          border: {
            display: false,
          },
        },
      },
    },
  });
}

// 4. Cambiar Estado (Solo ADMIN o TECH)
window.updateStatus = async (id, status) => {
  try {
    const res = await fetch(`/api/incidents/${id}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`,
      },
      body: JSON.stringify({ status }),
    });

    if (res.ok) {
      loadIncidents();
    } else {
      console.warn('Permisos insuficientes para cambiar el estado.');
    }
  } catch (err) {
    console.error('Error al actualizar estado:', err);
  }
};

// 5. Crear Incidente
createIncidentForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const title = document.getElementById('inc-title').value;
  const priority = document.getElementById('inc-priority').value;
  const description = document.getElementById('inc-desc').value;

  try {
    const res = await fetch('/api/incidents', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`,
      },
      body: JSON.stringify({ title, priority, description }),
    });

    if (res.ok) {
      createIncidentForm.reset();
      modalIncident.classList.add('hidden');
      loadIncidents();
    }
  } catch (err) {
    console.error('Error al registrar ticket:', err);
  }
});

// =========================================
// Consola de Auditoría Forense / SIEM (ADMIN)
// =========================================
async function loadAuditLogs() {
  if (!auditLogsContainer) return;

  auditLogsContainer.innerHTML = `
    <div style="padding: 2.5rem; text-align: center; color: #8b949e;">
      <span>⏳ Extrayendo telemetría inmutable de auditoría forense...</span>
    </div>
  `;
  if (auditLogsCount) auditLogsCount.textContent = 'Consultando buffer...';

  try {
    const res = await fetch('/api/audit-logs', {
      headers: {
        'Authorization': `Bearer ${authToken}`,
      },
    });

    if (res.status === 401 || res.status === 403) {
      auditLogsContainer.innerHTML = `
        <div style="padding: 2.5rem; text-align: center; color: #ff7b72;">
          <span>⛔ Acceso denegado: Privilegios insuficientes. Se requiere rol ADMIN.</span>
        </div>
      `;
      if (auditLogsCount) auditLogsCount.textContent = 'Acceso Denegado (403)';
      return;
    }

    if (!res.ok) {
      throw new Error(`Fallo de respuesta del servidor: ${res.status}`);
    }

    const logs = await res.json();
    currentAuditLogs = Array.isArray(logs) ? logs : [];
    auditLogsContainer.innerHTML = '';

    if (!Array.isArray(logs) || logs.length === 0) {
      auditLogsContainer.innerHTML = `
        <div style="padding: 2.5rem; text-align: center; color: #8b949e;">
          <span>No se encontraron eventos en la tabla de auditoría.</span>
        </div>
      `;
      if (auditLogsCount) auditLogsCount.textContent = '0 eventos registrados';
      return;
    }

    if (auditLogsCount) {
      auditLogsCount.textContent = `${logs.length} eventos recuperados (Últimos 50)`;
    }

    logs.forEach((log) => {
      const entry = document.createElement('div');
      entry.className = 'audit-entry';

      // Determinación contextual del badge de seguridad
      const actionUpper = String(log.action || '').toUpperCase();
      let badgeClass = 'audit-badge-neutral';

      if (
        actionUpper.includes('FAIL') ||
        actionUpper.includes('DENIED') ||
        actionUpper.includes('BLOCKED') ||
        actionUpper.includes('ATTACK') ||
        actionUpper.includes('CRITICAL') ||
        actionUpper.includes('DELETE') ||
        actionUpper.includes('FATIGUE')
      ) {
        badgeClass = 'audit-badge-danger';
      } else if (
        actionUpper.includes('SUCCESS') ||
        actionUpper.includes('RESOLVED') ||
        actionUpper.includes('REMEDIATED') ||
        actionUpper.includes('CREATED')
      ) {
        badgeClass = 'audit-badge-success';
      } else if (
        actionUpper.includes('STATUS') ||
        actionUpper.includes('UPDATE') ||
        actionUpper.includes('ASSIGN') ||
        actionUpper.includes('ROLE')
      ) {
        badgeClass = 'audit-badge-info';
      } else if (
        actionUpper.includes('WARN') ||
        actionUpper.includes('SUSPICIOUS') ||
        actionUpper.includes('INVESTIGATE')
      ) {
        badgeClass = 'audit-badge-warning';
      }

      // Sanitización estricta contra inyección XSS
      const safeAction = escapeHtml(log.action);
      const safeIp = escapeHtml(log.ipAddress || '0.0.0.0');
      const safeDetails = escapeHtml(log.details || 'Sin detalles adicionales');
      const safeUser = log.user 
        ? `${escapeHtml(log.user.name)} [${escapeHtml(log.user.role)}]` 
        : (log.userId ? escapeHtml(log.userId) : 'Sistema / EDR');

      const formattedDate = new Date(log.createdAt).toLocaleString('es-ES', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });

      entry.innerHTML = `
        <span class="col-time">${formattedDate}</span>
        <span class="col-ip">🖥️ ${safeIp}</span>
        <span class="col-action"><span class="audit-badge ${badgeClass}">${safeAction}</span></span>
        <span class="col-user" title="${safeUser}">👤 ${safeUser}</span>
        <span class="col-details">${safeDetails}</span>
      `;

      auditLogsContainer.appendChild(entry);
    });
  } catch (err) {
    console.error('Error al cargar logs de auditoría forense:', err);
    auditLogsContainer.innerHTML = `
      <div style="padding: 2.5rem; text-align: center; color: #ff7b72;">
        <span>⚠️ Error de comunicación con la API SIEM: ${escapeHtml(err.message)}</span>
      </div>
    `;
    if (auditLogsCount) auditLogsCount.textContent = 'Error de conexión';
  }
}

// Controles de Búsqueda y Filtros Rápidos
if (incidentSearch) {
  incidentSearch.addEventListener('input', (e) => {
    currentSearch = e.target.value;
    if (btnClearSearch) {
      if (currentSearch.length > 0) {
        btnClearSearch.classList.remove('hidden');
      } else {
        btnClearSearch.classList.add('hidden');
      }
    }
    applyFiltersAndRender();
  });
}

if (btnClearSearch) {
  btnClearSearch.addEventListener('click', () => {
    if (incidentSearch) {
      incidentSearch.value = '';
      incidentSearch.focus();
    }
    currentSearch = '';
    btnClearSearch.classList.add('hidden');
    applyFiltersAndRender();
  });
}

filterPills.forEach((pill) => {
  pill.addEventListener('click', () => {
    filterPills.forEach((p) => p.classList.remove('active'));
    pill.classList.add('active');
    currentFilter = pill.getAttribute('data-filter') || 'ALL';
    applyFiltersAndRender();
  });
});

// Controles de Modal y Logout
btnOpenModal.addEventListener('click', () => modalIncident.classList.remove('hidden'));
btnCloseModal.addEventListener('click', () => modalIncident.classList.add('hidden'));

// Controles de la Consola Forense SIEM
if (btnOpenAudit) {
  btnOpenAudit.addEventListener('click', () => {
    if (modalAudit) modalAudit.classList.remove('hidden');
    loadAuditLogs();
  });
}

if (btnCloseAudit) {
  btnCloseAudit.addEventListener('click', () => {
    if (modalAudit) modalAudit.classList.add('hidden');
  });
}

if (btnCloseAuditFooter) {
  btnCloseAuditFooter.addEventListener('click', () => {
    if (modalAudit) modalAudit.classList.add('hidden');
  });
}

if (btnRefreshAudit) {
  btnRefreshAudit.addEventListener('click', () => {
    loadAuditLogs();
  });
}

// =========================================
// Exportación de Reportes Forenses en CSV
// =========================================

// Sanitización para CSV con mitigación contra inyección de fórmulas (CWE-1236)
function sanitizeForCSV(field) {
  if (field === null || field === undefined) return '';
  let str = String(field).trim();
  // Neutralizar fórmulas maliciosas de hojas de cálculo
  if (/^[=+\-@\t\r]/.test(str)) {
    str = "'" + str;
  }
  // Escapar comillas dobles internas duplicándolas (RFC 4180)
  return str.replace(/"/g, '""');
}

// Estampa de tiempo local para nomenclatura de archivos: YYYY-MM-DD_HHmm
function getTimestampForFilename() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  return `${year}-${month}-${day}_${hours}${minutes}`;
}

// Generador y descargador de Blob con BOM UTF-8
function downloadCSV(csvContent, filename) {
  // \uFEFF garantiza compatibilidad con caracteres especiales (tildes, ñ) en Excel
  const blob = new Blob(['\uFEFF' + csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// Función principal de exportación de incidentes a CSV
function exportToCSV(data, filename) {
  const incidents = Array.isArray(data) ? data : [];
  if (incidents.length === 0) {
    alert('No hay incidentes disponibles para exportar en la vista actual.');
    return;
  }

  // Cabeceras exactas según especificación
  const headers = ['ID', 'Título', 'Prioridad', 'Estado', 'Reportado Por', 'Fecha', 'Descripción'];
  const rows = [headers.map(h => `"${h}"`).join(',')];

  incidents.forEach((inc) => {
    const authorName = inc.author ? `${inc.author.name} (${inc.author.email})` : 'Sistema';
    const formattedDate = new Date(inc.createdAt).toLocaleString('es-ES');

    const row = [
      `"${sanitizeForCSV(inc.id)}"`,
      `"${sanitizeForCSV(inc.title)}"`,
      `"${sanitizeForCSV(inc.priority)}"`,
      `"${sanitizeForCSV(inc.status)}"`,
      `"${sanitizeForCSV(authorName)}"`,
      `"${sanitizeForCSV(formattedDate)}"`,
      `"${sanitizeForCSV(inc.description)}"`,
    ];
    rows.push(row.join(','));
  });

  const csvContent = rows.join('\r\n');
  const targetFilename = filename || `SentinelDesk_Incidentes_${getTimestampForFilename()}.csv`;
  downloadCSV(csvContent, targetFilename);
}

// Función de exportación de registros de auditoría forense a CSV
function exportAuditToCSV(data, filename) {
  const logs = Array.isArray(data) ? data : [];
  if (logs.length === 0) {
    alert('No hay registros de auditoría cargados para exportar. Abre la consola o recarga los logs.');
    return;
  }

  const headers = ['ID', 'Fecha / Hora', 'Dirección IP', 'Acción Forense', 'Operador', 'Rol', 'Detalles Técnicos'];
  const rows = [headers.map(h => `"${h}"`).join(',')];

  logs.forEach((log) => {
    const formattedDate = new Date(log.createdAt).toLocaleString('es-ES');
    const operator = log.user ? log.user.name : (log.userId || 'Sistema / Sensor');
    const role = log.user ? log.user.role : 'SYSTEM';

    const row = [
      `"${sanitizeForCSV(log.id)}"`,
      `"${sanitizeForCSV(formattedDate)}"`,
      `"${sanitizeForCSV(log.ipAddress || '0.0.0.0')}"`,
      `"${sanitizeForCSV(log.action)}"`,
      `"${sanitizeForCSV(operator)}"`,
      `"${sanitizeForCSV(role)}"`,
      `"${sanitizeForCSV(log.details || '')}"`,
    ];
    rows.push(row.join(','));
  });

  const csvContent = rows.join('\r\n');
  const targetFilename = filename || `SentinelDesk_Auditoria_SIEM_${getTimestampForFilename()}.csv`;
  downloadCSV(csvContent, targetFilename);
}

// Evento de Exportación de Incidentes
if (btnExportCSV) {
  btnExportCSV.addEventListener('click', () => {
    const hasFilter = currentFilter !== 'ALL' || (currentSearch || '').trim() !== '';
    const dataToExport = hasFilter ? currentFilteredIncidents : allIncidents;

    if (!dataToExport || dataToExport.length === 0) {
      alert('No hay incidentes para exportar.');
      return;
    }

    const filename = `SentinelDesk_Incidentes_${getTimestampForFilename()}.csv`;
    exportToCSV(dataToExport, filename);
  });
}

// Evento de Exportación de Auditoría Forense
if (btnExportAuditCSV) {
  btnExportAuditCSV.addEventListener('click', () => {
    if (!currentAuditLogs || currentAuditLogs.length === 0) {
      alert('No hay registros de auditoría en memoria. Por favor, pulsa "Recargar Logs" primero.');
      return;
    }

    const filename = `SentinelDesk_Auditoria_SIEM_${getTimestampForFilename()}.csv`;
    exportAuditToCSV(currentAuditLogs, filename);
  });
}

document.getElementById('btn-logout').addEventListener('click', logout);

function logout() {
  if (chartPriorityInstance) {
    chartPriorityInstance.destroy();
    chartPriorityInstance = null;
  }
  if (chartStatusInstance) {
    chartStatusInstance.destroy();
    chartStatusInstance = null;
  }
  localStorage.removeItem('sentinel_token');
  localStorage.removeItem('sentinel_user');
  window.location.reload();
}