# Proxmox Backup Dashboard

Dashboard Docker/Compose para inventariar VM y CT, consultar copias y snapshots,
editar políticas de backup y sincronizar los trabajos gestionados con Proxmox.

## Despliegue

1. Copiar `backup-dashboard/config/` con los tokens y claves SSH del entorno.
2. Crear `backup-dashboard/data/` para la política persistente.
3. Ejecutar:

```bash
docker compose up -d --build
```

El servicio escucha en el puerto `8788`.

El estado de la política se conserva en `data/policy.json`; las credenciales no
forman parte del repositorio.
