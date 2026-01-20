import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';

async function bootstrap() {
  try {
    const app = await NestFactory.create(AppModule);
    console.log('🚀 NestJS starting...');
    app.useGlobalPipes(new ValidationPipe());
    await app.listen(3001);
    console.log(' Server is live on http://localhost:3001');
  } catch (error) {
    console.error(' Server failed to start:', error);
  }
}
bootstrap();
