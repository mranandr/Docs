import { Module, forwardRef } from '@nestjs/common';
import { SpaceService } from './services/space.service';
import { SpaceController } from './space.controller';
import { SpaceMemberService } from './services/space-member.service';
import { UserModule } from '../user/user.module';
import { WorkspaceModule } from '../workspace/workspace.module';
@Module({
  imports: [
    forwardRef(() => UserModule),
    forwardRef(() => WorkspaceModule), 
  ],
  controllers: [SpaceController],
  providers: [SpaceService, SpaceMemberService],
  exports: [SpaceService, SpaceMemberService],
})
export class SpaceModule {}
