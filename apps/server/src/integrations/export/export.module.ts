import { forwardRef, Module } from '@nestjs/common';
import { ExportService } from './export.service';
import { ExportController } from './export.controller';
import { StorageModule } from '../storage/storage.module';
import { AuthModule } from 'src/core/auth/auth.module';
import { UserModule } from 'src/core/user/user.module';

@Module({
  imports: [StorageModule,
    forwardRef(() => AuthModule),
    forwardRef(() => UserModule),   
  ],
  providers: [ExportService],
  controllers: [ExportController],
})
export class ExportModule {}
