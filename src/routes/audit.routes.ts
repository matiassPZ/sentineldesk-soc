import { Router, Response } from 'express';
import { PrismaClient, Role } from '@prisma/client';
import { authenticateToken, authorizeRoles, AuthRequest } from '../middlewares/auth.js';

const router = Router();
const prisma = new PrismaClient();

// Aplicar autenticación obligatoria y control de acceso estricto RBAC (Solo ADMIN)
router.use(authenticateToken);
router.use(authorizeRoles(Role.ADMIN));

// GET /api/audit-logs - Consultar los últimos 50 registros de auditoría forense SIEM
router.get('/', async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const logs = await prisma.auditLog.findMany({
      take: 50,
      orderBy: { createdAt: 'desc' },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            role: true,
          },
        },
        incident: {
          select: {
            id: true,
            title: true,
          },
        },
      },
    });

    res.json(logs);
  } catch (error) {
    console.error('Error al obtener logs de auditoría forense:', error);
    res.status(500).json({ error: 'Error al consultar logs de auditoría forense.' });
  }
});

export default router;
