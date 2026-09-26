import express from 'express';
import cors from 'cors';
import authRoutes from './routes/auth.routes.js';
import incidentRoutes from './routes/incident.routes.js';
import auditRoutes from './routes/audit.routes.js';

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Middlewares globales
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Servir la interfaz web estática

// Endpoint de verificación de salud de la API
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'online', 
    system: 'SentinelDesk API v1.0.0',
    timestamp: new Date().toISOString()
  });
});

// Enlazar rutas modulares
app.use('/api/auth', authRoutes);
app.use('/api/incidents', incidentRoutes);
app.use('/api/audit-logs', auditRoutes);

// Poner a escuchar el servidor en 0.0.0.0 para entornos cloud (Render, Railway)
app.listen(PORT, '0.0.0.0', () => {
  console.log(`=========================================`);
  console.log(`🚀 Servidor SentinelDesk activo en http://0.0.0.0:${PORT}`);
  console.log(`🛡️  Seguridad RBAC & Tokens JWT: Habilitados`);
  console.log(`🌐 Entorno: ${process.env.NODE_ENV || 'production'}`);
  console.log(`=========================================`);
});