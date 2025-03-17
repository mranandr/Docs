import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './services/auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { WorkspaceModule } from '../workspace/workspace.module';
import { SignupService } from './services/signup.service';
import { TokenModule } from './token.module';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { UserModule } from '../user/user.module';
import { DatabaseModule } from '@docmost/db/database.module';
import { SpaceMemberService } from '../space/services/space-member.service';
import { SpaceModule } from '../space/space.module';
import { EnvironmentModule } from 'src/integrations/environment/environment.module';
import { EnvironmentService } from 'src/integrations/environment/environment.service'; 
import { UserService } from '../user/user.service';

@Module({
  imports: [WorkspaceModule, TokenModule, WorkspaceModule, UserModule, DatabaseModule, SpaceModule, EnvironmentModule, ],
  controllers: [AuthController],
  providers: [AuthService, SignupService, JwtStrategy, UserRepo, SpaceMemberService, EnvironmentService],
  exports: [AuthService, SpaceMemberService, SpaceModule, EnvironmentModule, SignupService],
})
export class AuthModule {}
