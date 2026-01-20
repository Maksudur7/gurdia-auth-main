import { Injectable } from '@nestjs/common';
import bcrypt from 'bcryptjs';
import { UpdateAuthDto } from '../../src/auth/dto/update-auth.dto.js';
import { PrismaService } from '../../src/prisma/prisma.service.js';

@Injectable()
export class UsersService {
    constructor(
        private prisma: PrismaService,
    ) { }

    async createAuditLog(
        userId: string,
        action: string,
        ip: string,
        device?: string,
        geo?: string,
    ) {
        return await this.prisma.auditLog.create({
            data: {
                userId,
                action,
                ip,
                device,
                geo,
            },
            include: {
                user: true,
            },
        });
    }

    findAllUsers() {
        return this.prisma.user.findMany({
            include: { role: true },
        });
    }

    async findOneUsers(id: string) {
        return this.prisma.user.findUnique({
            where: { id },
        });
    }

    async updateOneUsers(id: string, updateAuthDto: UpdateAuthDto) {
        console.log('Target ID:', id);

        const user = await this.prisma.user.findUnique({ where: { id } });
        if (!user) {
            throw new Error(`User with ID ${id} not found`);
        }

        if (updateAuthDto.password) {
            const salt = await bcrypt.genSalt(10);
            updateAuthDto.password = await bcrypt.hash(updateAuthDto.password, salt);
        }

        const updateData: any = {
            name: updateAuthDto.name,
            email: updateAuthDto.email,
            password: updateAuthDto.password,
            image: updateAuthDto.imageUrl,
        };

        if (updateAuthDto.role) {
            const roleRecord = await this.prisma.role.findUnique({
                where: { name: updateAuthDto.role as string },
            });

            if (roleRecord) {
                updateData.roleId = roleRecord.id;
            } else {
                throw new Error(`Role ${updateAuthDto.role} not found in database`);
            }
        }

        return this.prisma.user.update({
            where: { id },
            data: updateData,
            include: { role: true },
        });
    }

    async deletUser(userId: string, ip: string) {
        const user = await this.prisma.user.update({
            where: { id: userId },
            data: {
                deletedAt: new Date(),
                status: 'DORMANT',
            },
        });

        await this.createAuditLog(userId, `USER_SOFT_DELETED_ID_${userId}`, ip);

        return {
            message: 'User successfully deactivated (Soft Delete)',
            user,
        };
    }

    async deleteUserByAdmin(targetUserId: string, adminId: string, ip: string) {
        const user = await this.prisma.user.update({
            where: { id: targetUserId },
            data: {
                deletedAt: new Date(),
                status: 'DORMANT',
            },
        });

        await this.prisma.auditLog.create({
            data: {
                userId: adminId,
                action: `ADMIN_DELETED_USER_ID_${targetUserId}`,
                ip: ip,
            },
        });

        return { message: 'User soft-deleted by admin successfully', user };
    }

    async getAuditLog() {
        return await this.prisma.auditLog.findMany({
            orderBy: { createdAt: 'desc' },
            include: { user: true },
        });
    }
}
