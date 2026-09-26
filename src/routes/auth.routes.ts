import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const router = Router();
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';

// Endpoint: POST /api/auth/login
router.post('/login', async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;
  const ipAddress = req.ip || req.socket.remoteAddress || '0.0.0.0';

  if (!email || !password) {
    res.status(400).json({ error: 'Debes proporcionar email y contraseña.' });
    return;
  }

  try {
    // 1. Buscar usuario por email
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      // Registrar intento fallido en Auditoría
      await prisma.auditLog.create({
        data: {
          action: 'FAILED_LOGIN_UNKNOWN_USER',
          ipAddress,
          details: `Intento de acceso fallido para el correo: ${email}`,
        },
      });
      res.status(401).json({ error: 'Credenciales inválidas.' });
      return;
    }

    // 2. Comparar la contraseña ingresada con el hash de la base de datos
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      // Registrar intento fallido con usuario existente
      await prisma.auditLog.create({
        data: {
          action: 'FAILED_LOGIN_BAD_PASSWORD',
          ipAddress,
          details: `Contraseña incorrecta para el usuario: ${email}`,
          userId: user.id,
        },
      });
      res.status(401).json({ error: 'Credenciales inválidas.' });
      return;
    }

    // 3. Generar Token JWT con información básica y Rol (RBAC)
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: '8h' } // Token válido durante una jornada laboral
    );

    // 4. Registrar acceso exitoso en Auditoría
    await prisma.auditLog.create({
      data: {
        action: 'LOGIN_SUCCESS',
        ipAddress,
        details: `Inicio de sesión exitoso como [${user.role}]`,
        userId: user.id,
      },
    });

    // 5. Responder con el token y datos públicos del usuario
    res.json({
      message: 'Autenticación exitosa',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Error en autenticación:', error);
    res.status(500).json({ error: 'Error interno del servidor durante el login.' });
  }
});

export default router;