import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  UseGuards,
  Request,
  NotFoundException,
  BadRequestException,
  Res,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { FastifyReply } from 'fastify';
import { Response } from 'express'; 
import { AuthService } from './services/auth.service';
import { SetupGuard } from './guards/setup.guard';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { AuthUser } from '../../common/decorators/auth-user.decorator';
import { AuthWorkspace } from '../../common/decorators/auth-workspace.decorator';
import { LoginDto } from './dto/login.dto';
import { CreateAdminUserDto } from './dto/create-admin-user.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { PasswordResetDto } from './dto/password-reset.dto';
import { VerifyUserTokenDto } from './dto/verify-user-token.dto';
import { User, Workspace } from '@docmost/db/types/entity.types';
import { CreateUserDto } from './dto/create-user.dto';
import { WorkspaceService } from '../workspace/services/workspace.service';
import { CreateWorkspaceDto } from '../workspace/dto/create-workspace.dto';
import { UserService } from '../user/user.service';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { addDays } from 'date-fns';
import { EnvironmentService } from 'src/integrations/environment/environment.service';
import { SetupMicrosoftWorkspaceDto } from '../workspace/dto/SetupMicrosoftWorkspaceDto';
import { UserRole } from 'src/common/helpers/types/permission';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';

@Controller('auth')
export class AuthController {
  private readonly userRepo: UserRepo;
  private readonly workspaceRepo: WorkspaceRepo;

  constructor(
    private readonly authService: AuthService,
    private readonly workspaceService: WorkspaceService,
    private readonly userService: UserService,
    private readonly environmentService: EnvironmentService,
  ) {}

  @Post('login')
  async login(@Body() loginDto: LoginDto, @Request() req) {
    const user = await this.userService.findById(loginDto.email, loginDto.microsoftId);

    const workspace = await this.workspaceService.findById(user.id);

    if (!workspace) {
      return {
        message: 'No workspace found. Please create a workspace.',
        user,
        requiresWorkspaceCreation: true,
      };
    }

    return { workspace, message: 'Welcome back!' };
  }

  @Post('setup-workspace')
  async setupWorkspace(@Body() setupWorkspaceDto: SetupMicrosoftWorkspaceDto) {
    const { email, name, organization, workspace: workspaceName } = setupWorkspaceDto;
  
    // Create the workspace
    const createdWorkspace = await this.workspaceService.createMicrosoftWorkspace({
      organization: organization,
      workspace: workspaceName,
      email,
      name,
      auth_type: 'sso',
      sso_provider: 'microsoft',
    });
  
    const user = await this.userRepo.insertUser({
      email,
      name,
      workspaceId: createdWorkspace.workspace.id,
      auth_type: 'sso',
      sso_provider: 'microsoft',
    });
  
    const token = await this.authService.generateJwt(user.id, createdWorkspace.workspace.id);
  
    return { token, workspace: createdWorkspace };
  }
  
  

  @Post('create-workspace')
  async createWorkspace(
    @Body() createWorkspaceDto: CreateWorkspaceDto,
    @Query('userId') userId: string,
  ) {
    if (!userId) {
      throw new BadRequestException('User ID is required');
    }

    const user = await this.userService.findById(createWorkspaceDto.name, createWorkspaceDto.hostname);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    const workspace = await this.workspaceService.create(
      user,
      createWorkspaceDto,
    );
    return { workspace, message: 'Workspace created successfully!' };
  }

  @Post('register')
  async register(@Body() createUserDto: CreateUserDto, @Query('workspaceId') workspaceId: string) {
    if (!workspaceId) {
      throw new BadRequestException('Workspace ID is required');
    }

    const user = await this.authService.register(createUserDto, workspaceId);
    return { user };
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  async changePassword(
    @Body() changePasswordDto: ChangePasswordDto,
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    if (!user || !workspace) {
      throw new BadRequestException('User and workspace are required');
    }

    await this.authService.changePassword(changePasswordDto, user.id, workspace.id);
    return { message: 'Password changed successfully' };
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto, @Query('workspaceId') workspaceId: string) {
    if (!workspaceId) {
      throw new BadRequestException('Workspace ID is required');
    }

    await this.authService.forgotPassword(forgotPasswordDto, workspaceId);
    return { message: 'Password reset email sent' };
  }

  @Post('password-reset')
  async passwordReset(@Body() passwordResetDto: PasswordResetDto, @Query('workspaceId') workspaceId: string) {
    if (!workspaceId) {
      throw new BadRequestException('Workspace ID is required');
    }

    const token = await this.authService.passwordReset(passwordResetDto, workspaceId);
    return { token };
  }

  @Post('verify-token')
  async verifyToken(@Body() verifyUserTokenDto: VerifyUserTokenDto, @Query('workspaceId') workspaceId: string) {
    if (!workspaceId) {
      throw new BadRequestException('Workspace ID is required');
    }

    await this.authService.verifyUserToken(verifyUserTokenDto, workspaceId);
    return { message: 'Token verified successfully' };
  }

  @Post('setup-register')
  async setupMicrosoftWorkspace(@Body() payload: SetupMicrosoftWorkspaceDto) {
    try {
      const { organization, workspace, email, name } = payload;
  
      // Validate payload (optional, if not already handled by DTO validation)
      if (!organization || !workspace || !email || !name) {
        throw new BadRequestException('All fields are required');
      }
  
      // Create the workspace
      const workspaces = await this.workspaceService.createMicrosoftWorkspace({
        organization: organization,
        workspace: workspace,
        email: email,
        name: name,
        auth_type: 'sso',
        sso_provider: 'microsoft',
      });
  
      // Create the user
      const user = await this.userRepo.insertUser({
        email,
        name,
        workspaceId: workspaces.workspace.id,
        role: UserRole.OWNER,
        auth_type: 'sso', // Required field
        sso_provider: 'microsoft', // Required if using SSO
      });
  
      return { message: 'Workspace and user created successfully', workspace: workspaces.workspace, user };
    } catch (error) {
      let errorMessage = 'Failed to create workspace';
      if (error instanceof Error) {
        errorMessage = error.message;
      }
      throw new BadRequestException(errorMessage);
    }
  }
  

  // async loginWithMicrosoft(code: string) {
  //   // Step 1: Get the access token using the authorization code
  //   const accessToken = await this.getMicrosoftAuthUrl(code);
  
  //   // Step 2: Fetch user info from Microsoft Graph API
  //   const microsoftUser = await this.mic(accessToken);
  
  //   if (!microsoftUser || !microsoftUser.email) {
  //     throw new BadRequestException('Microsoft login failed');
  //   }
  
  //   // Step 3: Check if the user already exists in your database
  //   let user = await this.userService.findByEmail(microsoftUser.email, 'sso');
  
  //   let requiresSetup = false;
  
  //   if (!user) {
  //     // Step 4: Create a new workspace and user if the user doesn't exist
  //     const workspace = await this.workspaceService.createMicrosoftWorkspace({
  //       name: microsoftUser.email.split('@')[0], // Use email prefix as workspace name
  //       organization: microsoftUser.email.split('@')[1], // Use domain as organization name
  //     });
  
  //     // Step 5: Create the user in your database
  //     user = await this.userRepo.create({
  //       name: microsoftUser.displayName || microsoftUser.email.split('@')[0],
  //       email: microsoftUser.email,
  //       avatarUrl: microsoftUser.avatar || '',
  //       auth_type: 'sso',
  //       sso_provider: 'microsoft',
  //       id: microsoftUser.id,
  //       emailVerifiedAt: new Date(),
  //       role: UserRole.ADMIN, // Assign a default role
  //       workspaceId: workspace.id,
  //       locale: microsoftUser.locale || 'en',
  //       timezone: microsoftUser.timezone || 'UTC',
  //       lastLoginAt: new Date(),
  //     });
  
  //     requiresSetup = true; // Mark that setup is required for new users
  //   } else {
  //     // Step 6: Update the user's last login time if they already exist
  //     await this.userService.updateUser({ lastLoginAt: new Date() }, user.id, user.workspaceId);
  //   }
  
  //   // Step 7: Return the user and whether setup is required
  //   return { user, requiresSetup };
  // }
  
  // @UseGuards(SetupGuard)
  // @HttpCode(HttpStatus.OK)
  // @Post('setup')
  // async setupWorkspace(
  //   @Res({ passthrough: true }) res: FastifyReply,
  //   @Body() createAdminUserDto: CreateAdminUserDto,
  // ) {
  //   const { workspace, authToken } =
  //     await this.authService.setup(createAdminUserDto);

  //   this.setAuthCookie(res, authToken);
  //   return workspace;
  // }
  
  setAuthCookie(res: FastifyReply, token: string) {
    res.setCookie('authToken', token, {
      httpOnly: true,
      path: '/',
      expires: addDays(new Date(), 30),
      secure: this.environmentService.isCloud(),
    });
  }

  @Get('microsoft/auth-url')
  async getMicrosoftAuthUrl() {
    const authUrl = this.authService.getMicrosoftAuthUrl();
    return { authUrl };
  }

  @UseGuards(JwtAuthGuard)
  @Get('collab-token')
  async getCollabToken(@AuthUser() user: User, @AuthWorkspace() workspace: Workspace) {
    if (!user || !workspace) {
      throw new BadRequestException('User and workspace are required');
    }

    const token = await this.authService.getCollabToken(user.id, workspace.id);
    return { token };
  }
}