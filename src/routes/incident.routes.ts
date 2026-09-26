import { Router, Response } from 'express';
import { PrismaClient, Role, Status, Priority } from '@prisma/client';
import { authenticateToken, authorizeRoles, AuthRequest } from '../middlewares/auth.js';

const router = Router();
const prisma = new PrismaClient();

// Aplicar autenticación obligatoria a todas las rutas de incidentes
router.use(authenticateToken);

// 1. Obtener incidentes (Filtrado según el rol del usuario)
router.get('/', async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const user = req.user!;
    let incidents;

    // Si es ADMIN o TECH, ve todos los tickets
    if (user.role === Role.ADMIN || user.role === Role.TECH) {
      incidents = await prisma.incident.findMany({
        include: {
          author: { select: { id: true, name: true, email: true } },
          assignedTo: { select: { id: true, name: true, email: true } },
        },
        orderBy: { createdAt: 'desc' },
      });
    } else {
      // Si es USER, únicamente ve los que él mismo creó
      incidents = await prisma.incident.findMany({
        where: { authorId: user.id },
        include: {
          author: { select: { id: true, name: true, email: true } },
        },
        orderBy: { createdAt: 'desc' },
      });
    }

    res.json(incidents);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener incidentes.' });
  }
});

// 2. Crear un nuevo incidente (Cualquier usuario autenticado)
router.post('/', async (req: AuthRequest, res: Response): Promise<void> => {
  const { title, description, priority } = req.body;
  const user = req.user!;
  const ipAddress = req.ip || req.socket.remoteAddress || '0.0.0.0';

  if (!title || !description) {
    res.status(400).json({ error: 'El título y la descripción son requeridos.' });
    return;
  }

  try {
    const incident = await prisma.incident.create({
      data: {
        title,
        description,
        priority: priority || Priority.MEDIUM,
        status: Status.OPEN,
        authorId: user.id,
      },
    });

    // Auditoría automática de la creación
    await prisma.auditLog.create({
      data: {
        action: 'INCIDENT_CREATED',
        ipAddress,
        details: `Incidente "${incident.title}" creado`,
        userId: user.id,
        incidentId: incident.id,
      },
    });

    res.status(201).json(incident);
  } catch (error) {
    res.status(500).json({ error: 'Error al registrar el incidente.' });
  }
});

// 3. Modificar estado de un incidente (Solo ADMIN y TECH)
router.patch('/:id/status', authorizeRoles(Role.ADMIN, Role.TECH), async (req: AuthRequest, res: Response): Promise<void> => {
const id = req.params.id as string;
const { status } = req.body;
const user = req.user!;
const ipAddress = req.ip || req.socket.remoteAddress || '0.0.0.0';

try {
  const updatedIncident = await prisma.incident.update({
    where: { id },
    data: { status },
  });    // Registrar cambio de estado en Auditoría
    await prisma.auditLog.create({
      data: {
        action: 'INCIDENT_STATUS_UPDATED',
        ipAddress,
        details: `Estado cambiado a [${status}] por ${user.email}`,
        userId: user.id,
        incidentId: updatedIncident.id,
      },
    });

    res.json(updatedIncident);
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar el estado del incidente.' });
  }
});

export default router;