import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { LoginDto } from '../dto/login.dto';
import { CreateUserDto } from '../dto/create-user.dto';
import { TokenService } from './token.service';
import { SignupService } from './signup.service';
import { CreateAdminUserDto } from '../dto/create-admin-user.dto';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import {
  comparePasswordHash,
  hashPassword,
  nanoIdGen,
} from '../../../common/helpers';
import axios from 'axios';
import { v7 as genUuidV7 } from 'uuid';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { MailService } from '../../../integrations/mail/mail.service';
import ChangePasswordEmail from '@docmost/transactional/emails/change-password-email';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import ForgotPasswordEmail from '@docmost/transactional/emails/forgot-password-email';
import { UserTokenRepo } from '@docmost/db/repos/user-token/user-token.repo';
import { PasswordResetDto } from '../dto/password-reset.dto';
import { sql } from 'kysely';
import { User, UserToken } from '@docmost/db/types/entity.types';
import { UserTokenType } from '../auth.constants';
import { KyselyDB } from '@docmost/db/types/kysely.types';
import { InjectKysely } from 'nestjs-kysely';
import { executeTx } from '@docmost/db/utils';
import { VerifyUserTokenDto } from '../dto/verify-user-token.dto';
import { EnvironmentService } from 'src/integrations/environment/environment.service';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { UserRole } from 'src/common/helpers/types/permission';
import * as bcrypt from 'bcrypt';
import { WorkspaceService } from 'src/core/workspace/services/workspace.service';
import { SetupMicrosoftWorkspaceDto } from 'src/core/workspace/dto/SetupMicrosoftWorkspaceDto';
import { UserService } from 'src/core/user/user.service';


@Injectable()
export class AuthService {
  private readonly CLIENT_ID = this.configService.get<string>('AZURE_CLIENT_ID');
  private readonly CLIENT_SECRET = this.configService.get<string>('AZURE_CLIENT_SECRET');
  private readonly TENANT_ID = this.configService.get<string>('AZURE_TENANT_ID');
  private readonly REDIRECT_URI = this.configService.get<string>('REDIRECT_URI');
  private readonly DEFAULT_WORKSPACE_ID = '018d20f2-79f0-7d95-b46a-28120d64a035';
  private readonly saltRounds = 10;  
  

  constructor(
    private readonly signupService: SignupService,
    private readonly tokenService: TokenService,
    private readonly userTokenRepo: UserTokenRepo,
    private readonly mailService: MailService,
    private readonly environmentService: EnvironmentService,
    private readonly configService: ConfigService,
    private readonly workspaceService:WorkspaceService,
    private readonly userService: UserService,

    @InjectKysely() private readonly db: KyselyDB,
    private readonly userRepo:UserRepo,
    private readonly workspaceRepo: WorkspaceRepo,
  ) {}

  async createOrUpdateMicrosoftUser(microsoftUser: any): Promise<User> {
    if (!microsoftUser?.email) {
      throw new Error('Invalid Microsoft user data');
    }
  
    const user = await this.userRepo.findOne({
      email: microsoftUser.email,
      workspaceId: this.DEFAULT_WORKSPACE_ID,

    });
  
    if (!user) {
      const newUser = await this.userRepo.insertUser({
        email: microsoftUser.email,
        name: microsoftUser.displayName,
        workspaceId: this.DEFAULT_WORKSPACE_ID,
        auth_type: 'sso',
        sso_provider: "microsoft",
      });
  
       newUser;
    }
    return user;
  }

  async setup(createAdminUserDto: CreateAdminUserDto) {
    const { workspace, user } =
      await this.signupService.initialSetup(createAdminUserDto);

    const authToken = await this.tokenService.generateAccessToken(user);
    return { workspace, authToken };
  }

  async setupMicrosoftWorkspace(setupWorkspaceDto: SetupMicrosoftWorkspaceDto) {
    const { organization, workspace, email, name } = setupWorkspaceDto;
  
    if (!organization || !workspace || !email || !name) {
      throw new BadRequestException('Missing required fields');
    }
  
    const createdWorkspace = await this.workspaceService.createMicrosoftWorkspace({
      organization: organization,
      workspace: workspace,
      email: email,
      name: name,
      auth_type: 'sso',
      sso_provider: 'microsoft',
    });
  
    const user = await this.userRepo.create({
      email,
      name,
      workspaceId: createdWorkspace.workspace.id,
      auth_type: 'sso',
      sso_provider: 'microsoft',
    });
  
    const token = await this.generateJwt(user.id, createdWorkspace.workspace.id);
  
    return { token, workspace: createdWorkspace.workspace };
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }

  async comparePasswordHash(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  async loginWithJWT(email: string, password: string): Promise<string> {
    const user = await this.userRepo.findByEmail(email, 'Docmost');
  
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
  
    const isValidPassword = await this.comparePasswordHash(password, user.password);
    if (!isValidPassword) {
      throw new UnauthorizedException('Invalid credentials');
    }
  
    return this.generateJwt(user.id, user.workspaceId);
  }

  async loginWithSSO(email: string, provider: 'microsoft'): Promise<string> {
    const user = await this.userRepo.findByEmail(email, 'sso');
  
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
  
    return this.generateJwt(user.id, user.workspaceId);
  }

  async loginWithMicrosoft(code: string) {
    const accessToken = await this.getMicrosoftToken(code);
  
    const microsoftUser = await this.microsoftGetUserInfo(accessToken);
  
    if (!microsoftUser || !microsoftUser.email) {
      throw new BadRequestException('Microsoft login failed');
    }
  
    let user = await this.userService.findByEmail(microsoftUser.email, 'sso');
  
    let requiresSetup = false;
  
    if (!user) {
      const workspace = await this.workspaceService.createMicrosoftWorkspace({
        organization: microsoftUser.email.split('@')[1],
        workspace: microsoftUser.email.split('@')[0],
        email: microsoftUser.email,
        name: microsoftUser.displayName || microsoftUser.email.split('@')[0],
        auth_type: 'sso',
        sso_provider: 'microsoft',
      });
  
      user = await this.userRepo.create({
        name: microsoftUser.displayName || microsoftUser.email.split('@')[0],
        email: microsoftUser.email,
        avatarUrl: microsoftUser.avatar || '',
        auth_type: 'sso',
        sso_provider: 'microsoft',
        id: microsoftUser.id,
        emailVerifiedAt: new Date(),
        role: UserRole.ADMIN,
        workspaceId: workspace.workspace.id,
        locale: microsoftUser.locale || 'en',
        timezone: microsoftUser.timezone || 'UTC',
        lastLoginAt: new Date(),
      });
  
      requiresSetup = true;
    } else {
      await this.userService.updateUser({ lastLoginAt: new Date() }, user.id, user.workspaceId);
    }
  
    return { user, requiresSetup };
  }
  

async createUser(userData: { email: string; name: string; workspaceId: string; auth_service: 'Docmost' | 'microsoft' }) {
  return await this.userRepo.insertUser({
    ...userData,
    auth_type: 'sso',
    sso_provider: userData.auth_service === 'microsoft' ? 'microsoft' : undefined, 
  });
}

  async handleMicrosoftLogin(userData: { email: string; name: string; sso_id: string }) {
    const workspaceId = this.DEFAULT_WORKSPACE_ID;
  
    const existingUser = await this.userRepo.findOne({
      email: userData.email,
      workspaceId,
    });
  
    if (existingUser) {
      return existingUser;
    }
  
    return await this.userRepo.insertUser({
      email: userData.email,
      name: userData.name,
      workspaceId,
      auth_type: 'sso', 
      sso_provider: 'microsoft',
    });
  }

  async exchangeCodeForToken(code: string): Promise<string> {
    const tokenUrl = `https://login.microsoftonline.com/${this.TENANT_ID}/oauth2/v2.0/token`;
    const params = new URLSearchParams({
      client_id: this.CLIENT_ID,
      client_secret: this.CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: this.REDIRECT_URI,
    });
  
    const response = await axios.post(tokenUrl, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    return response.data.access_token;
  }


async microsoftGetUserInfo(accessToken: string): Promise<any> {
  const response = await axios.get('https://graph.microsoft.com/v1.0/me', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return response.data;
}

  async findOrCreateMicrosoftUser(email: string, name?: string, avatarUrl?: string): Promise<User> {
    const workspaceId = this.DEFAULT_WORKSPACE_ID;
    let user = await this.userRepo.findOne({
      email,
      workspaceId,
      auth_service: 'microsoft', 
    });
  
    return user;
  }
  

  async findUserByEmail(email: string, workspaceId?: string, microsoftUser?: any) {
    if (!email) {
      throw new BadRequestException('Email is required');
    }

    const userName = microsoftUser?.name;
    const userEmail = microsoftUser?.email || email;
    const userWorkspaceId = microsoftUser?.workspaceId || workspaceId;

    const existingWorkspace = await this.db
      .selectFrom('workspaces')
      .select('id')
      .limit(1)
      .executeTakeFirst();

    const finalWorkspaceId = userWorkspaceId ?? existingWorkspace?.id ?? 'CBL-workspace-id';

    await this.db.insertInto('users').values({
      id: genUuidV7(),
      name: userName,
      email: userEmail,
      workspaceId: finalWorkspaceId,
      role: UserRole.MEMBER,
      createdAt: new Date(),
      updatedAt: new Date(),
    }).execute();

    return workspaceId
      ? this.userRepo.findOne({ email: userEmail, workspaceId: finalWorkspaceId })
      : this.userRepo.findOne({ email: userEmail , workspaceId});
  }
  getAuthProvider(): 'Docmost' | 'microsoft' {
    return 'Docmost';
  }
  

  getMicrosoftAuthUrl(): string {
    const clientId = this.CLIENT_ID;
    const tenantId = this.TENANT_ID;
    const redirectUri = this.REDIRECT_URI;
    const scope = 'openid email profile User.Read';

    if (!clientId || !tenantId || !redirectUri) {
      throw new Error('Missing environment variables for Microsoft authentication');
    }

    return `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(
      redirectUri,
    )}&response_mode=query&scope=${encodeURIComponent(scope)}`;
  }

  async createUserFromMS(accessToken: string): Promise<User> {
    try {
      const graphAPIUrl = 'https://graph.microsoft.com/v1.0/me';
      const response = await fetch(graphAPIUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      const msUser = await response.json();

      const workspaceId = this.DEFAULT_WORKSPACE_ID;
      let workspace = await this.workspaceRepo.findById(workspaceId);

      if (!workspace) {
        workspace = await this.workspaceRepo.insertWorkspace({
          id: workspaceId,
          name: 'CBL',
        });
      }

      const newUser: User = {
        id: msUser.id,
        name: msUser.displayName,
        avatarUrl: msUser.photo || '',
        email: msUser.mail,
        createdAt: new Date(),
        updatedAt: new Date(),
        workspaceId: workspaceId,
        emailVerifiedAt: null,
        invitedById: null,
        lastActiveAt: null,
        lastLoginAt: null,
        locale: null,
        role: null,
        settings: null,
        timezone: null,
        deactivatedAt: null,
        deletedAt: null,
        password: '',
        auth_type: 'sso',
        sso_provider: 'microsoft', 
      };

      const insertedUser = await this.userRepo.save(newUser);
      return insertedUser;
    } catch (error) {
      console.error('Error creating user from MS:', error);
      throw error;
    }
  }

  async generateJwt(userId: string, workspaceId?: string): Promise<string> {
    const jwtSecret = process.env.JWT_SECRET;
    return jwt.sign({ userId, workspaceId }, jwtSecret, { expiresIn: '1h' });
  }

  async microsoftLogin(code: string, workspaceId: string): Promise<string> {
    const tokenResponse = await this.getMicrosoftToken(code);
    const accessToken = tokenResponse.access_token;
    const microsoftUserInfo = await this.microsoftGetUserInfo(accessToken);
    const email = microsoftUserInfo.mail || microsoftUserInfo.userPrincipalName;
    await this.microsoftSaveUser(email, 'microsoft'); 
    const authProvider: "sso" | "Docmost" = "sso"; 
    const user = await this.userRepo.findByEmail(email, authProvider);


    if (!user) {
      throw new UnauthorizedException('Failed to authenticate');
    }

    return this.generateJwt(user.id, workspaceId);
  }

  async generateJwtToken(userId: string, workspaceId: string): Promise<string> {
    const user = await this.userRepo.findById(userId, workspaceId);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const jwtSecret = process.env.JWT_SECRET || 'defaultSecret';
    return jwt.sign({ userId: user.id, email: user.email }, jwtSecret, { expiresIn: '1h' });
  }

  async createMsUser(userData: { email: string; name: string; workspaceId: string }) {
    return await this.userRepo.create(userData);
  }

  async findMsUserByEmail(email: string): Promise<User | null> {
    return await this.userRepo.findOne({ email, workspaceId: 'defaultWorkspace' });
  }

  async getMicrosoftToken(code: string): Promise<any> {
    const tenantId = this.configService.get<string>('AZURE_TENANT_ID');
    const clientId = this.configService.get<string>('AZURE_CLIENT_ID');
    const clientSecret = this.configService.get<string>('AZURE_CLIENT_SECRET');
    const redirectUri = this.configService.get<string>('REDIRECT_URI');

    const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
    const params = new URLSearchParams();
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
    params.append('code', code);
    params.append('grant_type', 'authorization_code');
    params.append('redirect_uri', redirectUri);

    try {
      const response = await axios.post(tokenUrl, params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      return response.data;
    } catch (error: any) {
      console.error('Failed to get Microsoft token:', error.response?.data || error.message);
      throw new UnauthorizedException('Failed to authenticate with Microsoft');
    }
  }

  async microsoftSaveUser(email: string, authProvider: 'Docmost' | 'microsoft'): Promise<void> {
    const workspaceId = this.DEFAULT_WORKSPACE_ID;
    let workspace = await this.workspaceRepo.findById(workspaceId);
  
    if (!workspace) {
      workspace = await this.workspaceRepo.insertWorkspace({
        id: workspaceId,
        name: 'CBL',
      });
    }
  
    // If Microsoft, use "sso", otherwise, exclude auth_type (or handle separately)
    const isMicrosoft = authProvider === "microsoft";
  
    const user = await this.userRepo.findByEmail(email, isMicrosoft ? "sso" : "Docmost");
    if (!user) {
      await this.userRepo.insertUser({
        email,
        name: email.split('@')[0],
        workspaceId,
        auth_type: isMicrosoft ? "sso" : "Docmost",
        sso_provider: isMicrosoft ? "microsoft" : "Docmost",
        role: UserRole.OWNER,
      });
    }
  }
  
  async login(loginDto: LoginDto, workspaceId: string) {
    const user = await this.userRepo.findByEmail(loginDto.email, 'Docmost'); 

    if (!user || !(await this.comparePasswordHash(loginDto.password, user.password))) {
      throw new UnauthorizedException('Email or password does not match');
    }

    user.lastLoginAt = new Date();
    await this.userRepo.updateLastLogin(user.id, workspaceId);

    return this.tokenService.generateAccessToken(user);
  }

  async register(createUserDto: CreateUserDto, workspaceId: string) {
    const user = await this.signupService.signup(createUserDto, workspaceId);
    return this.tokenService.generateAccessToken(user);
  }

  async changePassword(changePasswordDto: ChangePasswordDto, userId: string, workspaceId: string) {
    const user = await this.userRepo.findById(userId, workspaceId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const isValidPassword = await this.comparePasswordHash(changePasswordDto.oldPassword, user.password);
    if (!isValidPassword) {
      throw new BadRequestException('Current password is incorrect');
    }

    const newPasswordHash = await this.hashPassword(changePasswordDto.newPassword);
    await this.userRepo.updateUser({ password: newPasswordHash }, userId, workspaceId);

    const emailTemplate = ChangePasswordEmail({ username: user.name });
    await this.mailService.sendToQueue({
      to: user.email,
      subject: 'Your password has been changed',
      template: emailTemplate,
    });
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto, workspaceId: string) {
    const user = await this.userRepo.findByEmail(forgotPasswordDto.email, 'Docmost');

    if (!user) {
      return;
    }

    const token = nanoIdGen(16);
    const resetLink = `${this.environmentService.getAppUrl()}/password-reset?token=${token}`;

    await this.userTokenRepo.insertUserToken({
      token,
      userId: user.id,
      workspaceId: user.workspaceId,
      expiresAt: new Date(new Date().getTime() + 60 * 60 * 1000), // 1 hour
      type: UserTokenType.FORGOT_PASSWORD,
    });

    const emailTemplate = ForgotPasswordEmail({
      username: user.name,
      resetLink,
    });

    await this.mailService.sendToQueue({
      to: user.email,
      subject: 'Reset your password',
      template: emailTemplate,
    });
  }

  async passwordReset(passwordResetDto: PasswordResetDto, workspaceId: string) {
    const userToken = await this.userTokenRepo.findById(
      passwordResetDto.token,
      workspaceId,
    );

    if (
      !userToken ||
      userToken.type !== UserTokenType.FORGOT_PASSWORD ||
      userToken.expiresAt < new Date()
    ) {
      throw new BadRequestException('Invalid or expired token');
    }

    const user = await this.userRepo.findById(userToken.userId, workspaceId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const newPasswordHash = await this.hashPassword(passwordResetDto.newPassword);

    await executeTx(this.db, async (trx) => {
      await this.userRepo.updateUser(
        { password: newPasswordHash },
        user.id,
        workspaceId,
      );

      await trx
        .deleteFrom('userTokens')
        .where('userId', '=', user.id)
        .where('type', '=', UserTokenType.FORGOT_PASSWORD)
        .execute();
    });

    const emailTemplate = ChangePasswordEmail({ username: user.name });
    await this.mailService.sendToQueue({
      to: user.email,
      subject: 'Your password has been changed',
      template: emailTemplate,
    });

    return this.tokenService.generateAccessToken(user);
  }

  async verifyUserToken(
    userTokenDto: VerifyUserTokenDto,
    workspaceId: string,
  ): Promise<void> {
    const userToken = await this.userTokenRepo.findById(
      userTokenDto.token,
      workspaceId,
    );

    if (
      !userToken ||
      userToken.type !== userTokenDto.type ||
      userToken.expiresAt < new Date()
    ) {
      throw new BadRequestException('Invalid or expired token');
    }
  }

  async getCollabToken(userId: string, workspaceId: string) {
    const user = await this.userRepo.findById(userId, workspaceId);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const token = await this.tokenService.generateCollabToken(userId, workspaceId);
    return { token };
  }
  
}