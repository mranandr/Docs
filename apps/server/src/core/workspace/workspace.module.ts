import { Module, forwardRef } from '@nestjs/common';
import { WorkspaceService } from './services/workspace.service';
import { WorkspaceController } from './controllers/workspace.controller';
import { SpaceModule } from '../space/space.module';
import { WorkspaceInvitationService } from './services/workspace-invitation.service';
import { AuthModule } from '../auth/auth.module';
import { UserModule } from '../user/user.module';
@Module({
  imports: [
    forwardRef(() => SpaceModule),
    forwardRef(() => UserModule),
    AuthModule,       
  ],
  providers: [WorkspaceService, WorkspaceInvitationService],
  controllers: [WorkspaceController],
  exports: [WorkspaceService],
})
export class WorkspaceModule {}
