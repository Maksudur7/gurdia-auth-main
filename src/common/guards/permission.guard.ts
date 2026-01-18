import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PrismaService } from '../../prisma/prisma.service.js';

@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 1. Controller ba Handler theke proyojoniyo permissions gulo nin
    const requiredPermissions = this.reflector.get<string[]>('permissions', context.getHandler());
    
    // Jodi kono permission set kora na thake, tobe access allow korun
    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user; // SessionGuard theke asche

    if (!user || !user.roleId) {
      throw new ForbiddenException('User role not found');
    }

    // 2. Database theke oi Role ar sob permissions gulo khunje ber korun
    // Note: SessionGuard e jodi permissions include kora na thake, tobe aikhane check korte hobe
    const rolePermissions = await this.prisma.rolePermission.findMany({
      where: { roleId: user.roleId },
      include: { permission: true }
    });

    const userPermissions = rolePermissions.map(rp => rp.permission?.action);

    // 3. Check korun dorkari sob permission user ar ache ki na
    const hasPermission = requiredPermissions.every(permission => 
      userPermissions.includes(permission)
    );

    if (!hasPermission) {
      throw new ForbiddenException('Security Alert: You do not have the required permissions for this action.');
    }

    return true;
  }
}