import { forwardRef, Module } from '@nestjs/common';
import { ShareController } from './share.controller';
import { ShareService } from './share.service';
import { ShareSeoController } from './share-seo.controller';
import { KeycloakTokenService } from '../auth/token.service';
import { AuthModule } from '../auth/auth.module';
import { UserModule } from '../user/user.module';

@Module({
  imports: [
  forwardRef(() => AuthModule),
  forwardRef(() => UserModule),
],
  controllers: [ShareController, ShareSeoController],
  providers: [ShareService, KeycloakTokenService],
  exports: [ShareService],
})
export class ShareModule {}
