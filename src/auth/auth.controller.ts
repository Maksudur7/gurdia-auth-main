import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Req, Ip } from '@nestjs/common';
import { AuthService } from './auth.service.js';
import { CreateAuthDto } from './dto/create-auth.dto.js';
import { SessionGuard } from '../common/guards/session.guard.js';
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

  @Post('roles')
  @UseGuards(SessionGuard, PermissionGuard)
  @Permissions('role.create')
  async createRole(@Body() body: { name: string; permissions: string[] }) {
    return this.authService.createRole(body.name, body.permissions);
  }

  @Post('roles/assign')
  @UseGuards(SessionGuard, PermissionGuard)
  @Permissions('role.assign')
  async assignRole(@Body() body: { userId: string; roleName: string }) {
    return this.authService.assignRole(body.userId, body.roleName);
  }

  @Post('logout')
  @UseGuards(SessionGuard)
  async logout(@Req() req: any, @Ip() ip: string) {
    const userId = req.user.id;
    return await this.authService.logoutUser(userId, ip);
  }

  @Post('forget-password')
  async forgetPassword(@Body('email') email: string) {
    return await this.authService.sendPasswordResetOtp(email);
  }

  @Patch('two-factor')
  @UseGuards(SessionGuard)
  async toggleTwoFactor(@Req() req: any, @Body('enable') enable: boolean) {
    return this.authService.updateTwoFactor(req.user.id, enable);
  }

}
