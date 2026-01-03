import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
  Inject,
  forwardRef,
} from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from 'src/common/decorators/public.decorator';
import { UserService } from '../user/user.service';
@Injectable()
export class KeycloakAuthGuard implements CanActivate {
  private readonly logger = new Logger(KeycloakAuthGuard.name);

  constructor(
    @Inject(forwardRef(() => UserService))
    private readonly usersService: UserService,
    private readonly reflector: Reflector,
  ) {}
  private jwksClientInstance = jwksClient({
    jwksUri: `${process.env.KEYCLOAK_BASE_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/certs`,
    cache: true, 
    cacheMaxEntries: 5, 
    cacheMaxAge: 60 * 60 * 1000,  
    rateLimit: true, 
    jwksRequestsPerMinute: 10, 
  });
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;
  
    const req = context.switchToHttp().getRequest();
    const authHeader = req.headers['authorization'];
  
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      this.logger.warn(`Missing or invalid Authorization header`);
      throw new UnauthorizedException('Missing or invalid Authorization header');
    }
  
    const token = authHeader.split(' ')[1];
  
    try {
      const decoded = await this.verifyToken(token);
  
      if (!decoded?.email) {
        throw new UnauthorizedException('Invalid token: Missing email');
      }
      const user = await this.usersService.findByEmail(decoded.email);

      if (!user) {
        throw new UnauthorizedException('User not found');
        }
        req.user = {
          id: user.id,
          email: user.email,
          workspaceId: user.workspaceId,
          role: user.role, 
          name: user.name,
        };
      return true;
    } catch (err) {
      this.logger.error(`Token verification failed: ${err}`);
      throw new UnauthorizedException(`Invalid or expired token: ${err}`);
    }
  }
  
  private async verifyToken(token: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const decodedHeader = jwt.decode(token, { complete: true })?.header;
      if (!decodedHeader?.kid) {
        this.logger.error('Token missing key ID');
        return reject(new Error('Token missing key ID'));
      }

      this.jwksClientInstance.getSigningKey(decodedHeader.kid, (err, key) => {
        if (err || !key) {
          this.logger.error(`Failed to fetch signing key: ${err?.message || 'Key not found'}`);
          return reject(err ?? new Error('Signing key not found'));
        }

        const signingKey = key.getPublicKey();
    
        jwt.verify(
          token,
          signingKey,
          {
            algorithms: ['RS256'],
            issuer: `${process.env.KEYCLOAK_BASE_URL}/realms/${process.env.KEYCLOAK_REALM}`,
          },
          (verifyErr, decoded) => {
            if (verifyErr) {
              this.logger.error(`JWT verification failed: ${verifyErr.message}`, verifyErr.stack);
              return reject(verifyErr);
            }
      
            resolve(decoded);
          },
        );
      });
    });
  }
}