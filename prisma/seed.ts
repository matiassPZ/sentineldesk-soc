import { PrismaClient, Role, Priority, Status } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('--- Iniciando carga inicial segura (Seed) ---');

  // 1. Limpieza de tablas previas (en orden de relaciones)
  await prisma.auditLog.deleteMany();
  await prisma.incident.deleteMany();
  await prisma.user.deleteMany();

  // 2. Encriptar contraseñas con Hash Salted (Nunca guardar contraseñas en texto plano)
  const passwordAdmin = await bcrypt.hash('AdminPass2026!', 10);
  const passwordUser = await bcrypt.hash('UserPass2026!', 10);

  // 3. Crear Usuario Administrador (RBAC: ADMIN)
  const admin = await prisma.user.create({
    data: {
      name: 'Matias Administrador',
      email: 'admin@sentineldesk.com',
      password: passwordAdmin,
      role: Role.ADMIN,
    },
  });

  // 4. Crear Usuario Operador (RBAC: USER)
  const operador = await prisma.user.create({
    data: {
      name: 'Carlos Empleado',
      email: 'carlos@empresa.com',
      password: passwordUser,
      role: Role.USER,
    },
  });

  console.log('✔ Usuarios creados con contraseñas encriptadas');

  // 5. El usuario reporta un incidente crítico de seguridad
  const incident = await prisma.incident.create({
    data: {
      title: 'Fuga de credenciales detectada en servidor VPN',
      description: 'Se detectaron múltiples intentos anómalos de inicio de sesión desde una IP desconocida.',
      priority: Priority.CRITICAL,
      status: Status.OPEN,
      authorId: operador.id,
    },
  });

  console.log('✔ Incidente de ciberseguridad registrado');

  // 6. Registro inmutable en el Log de Auditoría (Trazabilidad forense)
  await prisma.auditLog.create({
    data: {
      action: 'INCIDENT_CREATED_BY_USER',
      ipAddress: '190.181.25.10', // IP simulada del cliente
      details: `Incidente "${incident.title}" creado con prioridad ${incident.priority}`,
      userId: operador.id,
      incidentId: incident.id,
    },
  });

  console.log('✔ Registro forense guardado en AuditLog');
  console.log('--- Proceso finalizado con éxito ---');
}

main()
  .catch((e) => {
    console.error('Error durante el seed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });