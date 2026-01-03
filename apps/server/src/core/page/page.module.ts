import { forwardRef, Module } from '@nestjs/common';
import { PageService } from './services/page.service';
import { PageController } from './page.controller';
import { PageHistoryService } from './services/page-history.service';
import { TrashCleanupService } from './services/trash-cleanup.service';
import { StorageModule } from '../../integrations/storage/storage.module';
import { AuthModule } from '../auth/auth.module';
import { UserModule } from '../user/user.module';

@Module({
  controllers: [PageController],
  providers: [PageService, PageHistoryService, TrashCleanupService],
  exports: [PageService, PageHistoryService],
  imports: [
  forwardRef(() => AuthModule),
  forwardRef(() => UserModule),
  StorageModule
]

})
export class PageModule {}
