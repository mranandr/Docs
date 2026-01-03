import { Module } from '@nestjs/common';
import { AttachmentService } from './services/attachment.service';
import { AttachmentController } from './attachment.controller';
import { StorageModule } from '../../integrations/storage/storage.module';
import { UserModule } from '../user/user.module';
import { AttachmentProcessor } from './processors/attachment.processor';
import { SpaceModule } from '../space/space.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    StorageModule,
    UserModule,
    SpaceModule,     
    AuthModule,
  ],
  providers: [AttachmentService, AttachmentProcessor],
  controllers: [AttachmentController],
})
export class AttachmentModule {}
