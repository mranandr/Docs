import { Module } from '@nestjs/common';
import { WorkspaceService } from './services/workspace.service';
import { WorkspaceController } from './controllers/workspace.controller';
import { SpaceModule } from '../space/space.module';
import { WorkspaceInvitationService } from './services/workspace-invitation.service';
import { TokenModule } from '../auth/token.module';
import { AuthService } from '../auth/services/auth.service';
import { SignupService } from '../auth/services/signup.service';
import { UserService } from '../user/user.service';

@Module({
  imports: [SpaceModule, TokenModule],
  controllers: [WorkspaceController],
  providers: [SignupService,WorkspaceService, WorkspaceInvitationService, AuthService, UserService],
  exports: [SignupService, WorkspaceService, UserService],
})
export class WorkspaceModule {}