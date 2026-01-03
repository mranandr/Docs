import { Module } from '@nestjs/common';
import { RobotsTxtController } from './robots.txt.controller';
import { VersionController } from './version.controller';
import { VersionService } from './version.service';
import { AuthModule } from 'src/core/auth/auth.module';
import { UserModule } from 'src/core/user/user.module';

@Module({
  imports: [
    AuthModule,     
    UserModule,   
  ],
  controllers: [RobotsTxtController, VersionController],
  providers: [VersionService],
})
export class SecurityModule {}
