import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Req, Ip } from '@nestjs/common';
import { AuthService } from './auth.service.js';
import { CreateAuthDto } from './dto/create-auth.dto.js';
import { UpdateAuthDto } from './dto/update-auth.dto.js';
import { PolicyGuard } from '../common/guards/policy.guard.js';
import { SessionGuard } from '../common/guards/session.guard.js';
import { Roles } from '../../src/common/decorators/roles.decorator.js';
import { RolesGuard } from '../../src/common/guards/roles.guard.js';
import { StatusGuard } from '../../src/common/guards/status.guard.js';
import { PermissionGuard } from '../../src/common/guards/permission.guard.js';
import { Permissions } from '../../src/common/decorators/permissions.decorator.js';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('register')
  async create(@Body() createAuthDto: CreateAuthDto, @Ip() ip: string) {
    return await this.authService.regsterUser(createAuthDto, ip);
  }

  @Post('login')
  async login(@Body() body: { email: string; password: string }, @Req() request: { ip: string }) {
    return await this.authService.loginUser(body.email, body.password, request.ip);
  }

  @Post('verify-otp')
  async verifyOtp(@Body() body: { userId: string, otp: string }, @Req() request: { ip: string }) {
    return await this.authService.verifyOtpAndLogin(body.userId, body.otp, request.ip);
  }

  @Get('users')
  @UseGuards(SessionGuard, StatusGuard, RolesGuard, PermissionGuard)
  @Roles('ADMIN', 'SUB_ADMIN')
  @Permissions('user.read')
  async findAll() {
    return await this.authService.findAllUsers();
  }

  @Get('users/:id')
  @UseGuards(SessionGuard, StatusGuard, PolicyGuard)
  async findOne(@Param('id') id: string) {
    const result = await this.authService.findOneUsers(id);
    return result
  }

  @Patch('users/:id')
  @UseGuards(SessionGuard, StatusGuard, PolicyGuard, PermissionGuard)
  async update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
    return await this.authService.updateOneUsers(id, updateAuthDto);
  }

  @Delete('users/:id')
  @UseGuards(SessionGuard, StatusGuard, PolicyGuard)
  async remove(
    @Req() req: any,
    @Ip() ip: string
  ) {
    const userId = req.user.id;
    return await this.authService.deletUser(userId, ip);
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
    return await this.authService.deleteUserByAdmin(targetId, adminId, ip);
  }


  @Get('audit-logs')
  @Roles('ADMIN')
  @UseGuards(SessionGuard, RolesGuard, PermissionGuard)
  @Permissions('admin.manage')
  async getLogs() {
    return await this.authService.getAuditLog();
  }

  // just test for admin 

  @Get('admin-only-data')
  @Roles('ADMIN') // শুধু ADMIN এক্সেস পাবে
  @UseGuards(SessionGuard, RolesGuard)
  async getAdminData() {
    return { message: "Welcome, Admin!" };
  }
}
