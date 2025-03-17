import { Injectable } from '@nestjs/common';
import * as dotenv from 'dotenv';

dotenv.config();

@Injectable()
export class EnvironmentService {
  getAppSecret(): string {
    return process.env.JWT_SECRET; 
  }

  isCloud(): boolean {
    return process.env.JWT_SECRET === 'true';
  }
}
