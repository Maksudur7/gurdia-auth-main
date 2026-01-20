import { Global, Module } from '@nestjs/common';
import { AppController } from './app.controller.js';
import { AppService } from './app.service.js';
import { AuthModule } from './auth/auth.module.js';
import { PrismaModule } from './prisma/prisma.module.js';
import { PrismaService } from './prisma/prisma.service.js';
import { ConfigModule, ConfigService } from '@nestjs/config'; 
import { RedisModule } from '@nestjs-modules/ioredis';
import { UsersService } from './users/users.service.js';
import { UsersModule } from './users/users.module.js';
import { UsersController } from './users/users.controller.js';

@Global()
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    RedisModule.forRootAsync({ 
      useFactory: (configService: ConfigService) => ({
        type: 'single',
        url: `redis://${configService.get('REDIS_HOST') || 'redis'}:6379`,
      }),
      inject: [ConfigService],
    }),
    AuthModule,
    PrismaModule,
    UsersModule,
  ],
  controllers: [AppController, UsersController],
  providers: [AppService, PrismaService, UsersService],
})
export class AppModule { }