import { Module } from '@nestjs/common';
import { WsGateway } from './ws.gateway';
import { KeycloakTokenService } from 'src/core/auth/token.service';
import { UserModule } from 'src/core/user/user.module';
import { SpaceMemberRepo } from '@docmost/db/repos/space/space-member.repo';

@Module({
  imports: [UserModule],  
  providers: [
    WsGateway,
    KeycloakTokenService,  
    SpaceMemberRepo,       
  ],
})
export class WsModule {}
