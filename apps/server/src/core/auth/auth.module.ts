import { Module, forwardRef } from '@nestjs/common';
import { UserModule } from '../user/user.module';                  
import { KeycloakTokenService } from './token.service';
import { KeycloakAuthGuard } from './auth.guard';
import { Reflector } from '@nestjs/core';
@Module({
  imports: [
    forwardRef(() => UserModule), 
  ],
  providers: [KeycloakTokenService, KeycloakAuthGuard, Reflector],
  exports: [KeycloakTokenService, KeycloakAuthGuard],
})
export class AuthModule {}
