import { InjectRedis } from '@nestjs-modules/ioredis';
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import bcrypt from 'bcryptjs';
import { Redis } from 'ioredis';
import { PrismaService } from '../prisma/prisma.service.js';
import { CreateAuthDto } from './dto/create-auth.dto.js';
import { UpdateAuthDto } from './dto/update-auth.dto.js';

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

    await this.redisClient.set(`session:${user.id}`, token);
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

    if ((user as any).lastLoginIp && (user as any).lastLoginIp !== currentIp) {
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      await this.redisClient.set(`otp:${finalUser.id}`, otp, 'EX', 300);
      await this.createAuditLog(user.id, 'OTP_SENT_NEW_IP', currentIp);
      console.log(`\n--- [SECURITY ALERT] ---`);
      console.log(`New Device/IP: ${currentIp}`);
      console.log(`User ID: ${finalUser.id}`);
      console.log(`Verification OTP: ${otp}`);
      console.log(`------------------------\n`);
      return {
        message: 'New device or IP detected. OTP verification required.',
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
