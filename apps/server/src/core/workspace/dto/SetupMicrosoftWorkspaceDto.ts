import { IsEmail, IsString, MinLength } from 'class-validator';

export class SetupMicrosoftWorkspaceDto {
  @IsString()
  @MinLength(2)
  organization: string;

  @IsString()
  @MinLength(2)
  workspace: string;

  @IsEmail({}, { message: 'email must be an email' })
  email: string;

  @IsString()
  @MinLength(2)
  name: string;

  @IsString()
  auth_type: 'jwt' | 'sso';

  @IsString()
  sso_provider?: 'microsoft' | 'Docmost';

  @IsString()
  sso_id?: string;



}