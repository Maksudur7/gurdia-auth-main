import { InjectRedis } from '@nestjs-modules/ioredis';
import { Injectable, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import bcrypt from 'bcryptjs';
import { Redis } from 'ioredis';
import { PrismaService } from '../prisma/prisma.service.js';
import { CreateAuthDto } from './dto/create-auth.dto.js';
import { sendOtpEmail } from '../common/mail.service.js';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    @InjectRedis() private readonly redisClient: Redis,
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

  async validateUserStatusAndRecover(user: any) {
    if (user.status === 'BLOCK') {
      throw new Error('Your account is blocked. Please contact support.');
    }
    if (user.deletedAt) {
      const now = new Date();
      const deletedDate = new Date(user.deletedAt);

      const diffInDays = Math.floor(
        (now.getTime() - deletedDate.getTime()) / (1000 * 60 * 60 * 24),
      );

      if (diffInDays <= 60) {
        return await this.prisma.user.update({
          where: { id: user.id },
          data: {
            deletedAt: null,
            status: 'ACTIVE',
          },
        });
      } else {
        throw new Error('Account recovery period has expired.');
      }
    }
    return user;
  }

  async verifyOtpAndLogin(userId: string, otp: string, currentIp: string) {
    const savedOtp = await this.redisClient.get(`otp:${userId}`);

    if (!savedOtp || savedOtp !== otp) {
      await this.createAuditLog(userId, 'OTP_VERIFICATION_FAILED', currentIp);
      throw new Error('Invalid or expired OTP');
    }

    await this.redisClient.del(`otp:${userId}`);

    const user = await this.prisma.user.update({
      where: { id: userId },
      data: { lastLoginIp: currentIp } as any,
      include: { role: true },
    });

    const payload = {
      sub: user.id,
      email: user.email,
      status: user.status,
      role: user.role?.name,
    };
    const token = await this.jwtService.signAsync(payload);

    await this.redisClient.set(`session:${user.id}`, token, 'EX', 86400);
    await this.createAuditLog(user.id, 'USER_LOGIN_SUCCESS_VIA_OTP', currentIp);
    return {
      message: 'OTP Verified. Login successful',
      access_token: token,
      user: { id: user.id, email: user.email, role: user.role?.name },
    };
  }

  async regsterUser(createAuthDto: CreateAuthDto, ip: string) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: createAuthDto.email },
    });

    if (existingUser) {
      if (existingUser.deletedAt) {
        const salt = bcrypt.genSaltSync(10);
        const hashPassword = bcrypt.hashSync(createAuthDto.password, salt);

        const recoveredUser = await this.prisma.user.update({
          where: { id: existingUser.id },
          data: {
            password: hashPassword,
            name: createAuthDto.name,
            deletedAt: null,
            status: 'ACTIVE',
          },
          include: { role: true },
        });

        await this.createAuditLog(
          recoveredUser.id,
          'USER_ACCOUNT_RECOVERED',
          ip,
        );
        const payload = {
          sub: recoveredUser.id,
          email: recoveredUser.email,
          role: recoveredUser.role?.name,
        };
        const token = await this.jwtService.signAsync(payload);

        return {
          message: 'Account recovered successfully',
          access_token: token,
          user: {
            id: recoveredUser.id,
            email: recoveredUser.email,
            role: recoveredUser.role?.name,
          },
        };
      } else {
        throw new Error('Email already in use');
      }
    }
    const roleName = createAuthDto.role || 'USER'
    let userRole = await this.prisma.role.findUnique({
      where: { name: roleName },
    });

    const targetRole = createAuthDto.role || 'USER';
    if (!userRole) {
      userRole = await this.prisma.role.upsert({
        where: { name: targetRole },
        update: {},
        create: { name: targetRole },
      });
    }

    const salt = bcrypt.genSaltSync(10);
    const hashPassword = bcrypt.hashSync(createAuthDto.password, salt);
    const result = await this.prisma.user.create({
      data: {
        name: createAuthDto.name,
        email: createAuthDto.email,
        password: hashPassword,
        image: createAuthDto.imageUrl,
        roleId: userRole.id,
        status: 'ACTIVE',
      },
      include: { role: true },
    });

    const payload = {
      sub: result.id,
      email: result.email,
      role: result.role?.name,
    };
    const token = await this.jwtService.signAsync(payload);
    await this.createAuditLog(result.id, 'USER_REGISTERED', ip);
    return {
      message: 'User created successfully',
      access_token: token,
      user: { id: result.id, email: result.email, role: result.role?.name },
    };
  }

  async loginUser(email: string, pass: string, currentIp: string) {
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: { role: true },
    });
    if (!user) {
      throw new Error('Unauthorized access');
    }
    const userPass = user.password;
    const passMatch = await bcrypt.compareSync(pass, userPass as string);
    if (!passMatch) {
      throw new Error('Wrong password');
    }
    const finalUser = await this.validateUserStatusAndRecover(user);

    const isNewIp = !(user as any).lastLoginIp || (user as any).lastLoginIp !== currentIp;

    if (isNewIp) {
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await this.redisClient.set(`otp:${finalUser.id}`, otp, 'EX', 300);

      console.log(">>>> GENERATED OTP:", otp);

      try {
        await sendOtpEmail(user.email, otp);
        console.log("Email sent successfully to:", user.email);
      } catch (err) {
        console.error("Mail service error details:", err);
      }

      return {
        message: 'OTP verification required.',
        requiresOtp: true,
        userId: finalUser.id,
      };
    }

    await this.prisma.user.update({
      where: { id: finalUser.id },
      data: { lastLoginIp: currentIp } as any,
    });

    const payload = {
      sub: user.id,
      email: user.email,
      status: finalUser.status,
      role: user.role?.name,
    };
    const token = await this.jwtService.signAsync(payload);

    await this.redisClient.set(`session:${finalUser.id}`, token);
    await this.createAuditLog(user.id, 'USER_LOGIN_SUCCESS', currentIp);
    return {
      message: 'Login successful',
      access_token: token,
      user: {
        id: user.id,
        email: user.email,
        status: finalUser.status,
        role: user.role?.name,
      },
    };
  }

  async createRole(name: string, permissionNames: string[]) {
    const permissions = await this.prisma.permission.findMany({
      where: {
        action: { in: permissionNames },
      },
    });

    return this.prisma.role.create({
      data: {
        name,
        permissions: {
          create: permissions.map((p) => ({
            permissionId: p.id,
          })),
        },
      },
    });
  }

  async assignRole(userId: string, roleName: string) {
    const role = await this.prisma.role.findUnique({ where: { name: roleName } });
    if (!role) throw new NotFoundException('Role not found');

    return this.prisma.user.update({
      where: { id: userId },
      data: { roleId: role.id }
    });
  }

  async logoutUser(userId: string, ip: string) {
    await this.redisClient.del(`session:${userId}`);
    await this.createAuditLog(userId, 'LOGOUT', ip);
    return { message: 'Logged out successfully' };
  }

  async sendPasswordResetOtp(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException('User not found');

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await this.redisClient.set(`reset_otp:${email}`, otp, 'EX', 600);

    await sendOtpEmail(email, otp);
    return { message: 'Password reset OTP sent to email' };
  }

  async updateTwoFactor(userId: string, enable: boolean) {
    const updatedUser = await this.prisma.user.update({
      where: { id: userId },
      data: { isTwoFactorEnable: enable },
    });

    const action = enable ? '2FA_ENABLED' : '2FA_DISABLED';
    await this.createAuditLog(userId, action, 'INTERNAL_SYSTEM');

    return {
      message: `Two-Factor Authentication has been ${enable ? 'enabled' : 'disabled'} successfully.`,
      isTwoFactorEnabled: updatedUser.isTwoFactorEnable,
    };
  }

}
