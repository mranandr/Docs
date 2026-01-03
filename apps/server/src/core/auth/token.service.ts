import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';
import { JwtType, JwtCollabPayload, JwtAttachmentPayload } from './auth.util';

@Injectable()
export class KeycloakTokenService {
  private readonly logger = new Logger(KeycloakTokenService.name);

  private ATTACHMENT_SECRET = process.env.ATTACHMENT_TOKEN_SECRET;

  private jwksClientInstance = jwksClient({
    jwksUri: `${process.env.KEYCLOAK_BASE_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/certs`,
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
  });

  async verifyToken(token: string, type: JwtType): Promise<any> {
    if (type === JwtType.ATTACHMENT) {
      return this.verifyAttachmentToken(token);
    }

    if (type === JwtType.COLLAB) {
      return this.verifyCollabToken(token);
    }

    return this.verifyAccessToken(token);
  }

  private verifyAttachmentToken(token: string): JwtAttachmentPayload {
    return jwt.verify(token, this.ATTACHMENT_SECRET) as JwtAttachmentPayload;
  }

  private verifyCollabToken(token: string): JwtCollabPayload {
    return jwt.verify(token, this.ATTACHMENT_SECRET) as JwtCollabPayload;
  }

  private async verifyAccessToken(token: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const header = jwt.decode(token, { complete: true })?.header;

      if (!header?.kid) {
        return reject(new UnauthorizedException('Token missing key ID'));
      }

      this.jwksClientInstance.getSigningKey(header.kid, (err, key) => {
        if (err || !key) return reject(err);

        const signingKey = key.getPublicKey();

        jwt.verify(
          token,
          signingKey,
          {
            algorithms: ['RS256'],
            issuer: `${process.env.KEYCLOAK_BASE_URL}/realms/${process.env.KEYCLOAK_REALM}`,
          },
          (verifyErr, payload) => {
            if (verifyErr) return reject(verifyErr);
            resolve(payload);
          },
        );
      });
    });
  }

  generateAttachmentToken(payload: {
    attachmentId: string;
    pageId: string;
    workspaceId: string;
  }): string {
    return jwt.sign(payload, this.ATTACHMENT_SECRET, { expiresIn: '15m' });
  }

  generateCollabToken(payload: {
    sub: string;
    pageId: string;
    workspaceId: string;
  }): string {
    return jwt.sign(payload, this.ATTACHMENT_SECRET, { expiresIn: '30m' });
  }
}
