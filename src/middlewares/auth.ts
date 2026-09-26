import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { Role } from '@prisma/client';

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: Role;
}

// Extender la interfaz Request de Express para adjuntar el usuario verificado
export interface AuthRequest extends Request {
  user?: AuthenticatedUser;
}

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';

// 1. Middleware para verificar la validez del Token JWT
export const authenticateToken = (req: AuthRequest, res: Response, next: NextFunction): void => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer <TOKEN>"

  if (!token) {
    res.status(401).json({ error: 'Acceso denegado: Token no proporcionado.' });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as AuthenticatedUser;
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Token inválido o expirado.' });
    return;
  }
};

// 2. Middleware para Control de Acceso Basado en Roles (RBAC)
export const authorizeRoles = (...allowedRoles: Role[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'No autenticado.' });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({ 
        error: `Acceso restringido: El rol [${req.user.role}] no tiene permisos para esta acción.` 
      });
      return;
    }

    next();
  };
};