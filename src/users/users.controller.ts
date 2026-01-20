import { Body, Controller, Delete, Get, Ip, Param, Patch, Req, UseGuards } from '@nestjs/common';
import { Permissions } from '../../src/common/decorators/permissions.decorator.js';
import { Roles } from '../../src/common/decorators/roles.decorator.js';
import { PermissionGuard } from '../../src/common/guards/permission.guard.js';
import { RolesGuard } from '../../src/common/guards/roles.guard.js';
import { SessionGuard } from '../../src/common/guards/session.guard.js';
import { StatusGuard } from '../../src/common/guards/status.guard.js';
import { UsersService } from './users.service.js';
import { PolicyGuard } from '../../src/common/guards/policy.guard.js';
import { UpdateAuthDto } from '../../src/auth/dto/update-auth.dto.js';

@Controller('users')
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    @Get('users')
    @UseGuards(SessionGuard, StatusGuard, RolesGuard, PermissionGuard)
    @Roles('ADMIN', 'SUB_ADMIN')
    @Permissions('user.read')
    async findAll() {
        return await this.usersService.findAllUsers();
    }

    @Get('users/:id')
    @UseGuards(SessionGuard, StatusGuard, PolicyGuard)
    async findOne(@Param('id') id: string) {
        const result = await this.usersService.findOneUsers(id);
        return result
    }

    @Patch('users/:id')
    @UseGuards(SessionGuard, StatusGuard, PolicyGuard, PermissionGuard)
    async update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
        return await this.usersService.updateOneUsers(id, updateAuthDto);
    }

    @Delete('users/:id')
    @UseGuards(SessionGuard, StatusGuard, PolicyGuard)
    async remove(
        @Req() req: any,
        @Ip() ip: string
    ) {
        const userId = req.user.id;
        return await this.usersService.deletUser(userId, ip);
    }

    @Delete('delete-user/:id')
    @Roles('ADMIN')
    @UseGuards(SessionGuard, RolesGuard, PermissionGuard)
    @Permissions('user.delete')
    async removeUser(
        @Param('id') targetId: string,
        @Req() req: any,
        @Ip() ip: string
    ) {
        const adminId = req.user.id;
        return await this.usersService.deleteUserByAdmin(targetId, adminId, ip);
    }


    @Get('audit-logs')
    @Roles('ADMIN')
    @UseGuards(SessionGuard, RolesGuard, PermissionGuard)
    @Permissions('admin.manage')
    async getLogs() {
        return await this.usersService.getAuditLog();
    }

    // just test for admin 

    @Get('admin-only-data')
    @Roles('ADMIN') // শুধু ADMIN এক্সেস পাবে
    @UseGuards(SessionGuard, RolesGuard)
    async getAdminData() {
        return { message: "Welcome, Admin!" };
    }
}
