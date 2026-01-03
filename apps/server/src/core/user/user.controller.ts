import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { AuthUser } from '../../common/decorators/auth-user.decorator';
import { AuthWorkspace } from '../../common/decorators/auth-workspace.decorator';
import { User, Workspace } from '@docmost/db/types/entity.types';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { KeycloakAuthGuard } from '../auth/auth.guard';

@UseGuards(KeycloakAuthGuard)
@Controller('users')
export class UserController {
  constructor(
    private readonly userService: UserService,
    private readonly workspaceRepo: WorkspaceRepo,
  ) {}

@HttpCode(HttpStatus.OK)
@Post('me')
async getUserInfo(
  @AuthUser() authUser: User,
  @AuthWorkspace() workspace?: Workspace | null,  
) {
  let workspaceInfo = null;

  if (workspace) {
    const memberCount = await this.workspaceRepo.getActiveUserCount(workspace.id);

    const { licenseKey, ...rest } = workspace;

    workspaceInfo = {
      ...rest,
      memberCount,
      hasLicenseKey: Boolean(licenseKey),
    };
  }

  return {
    user: authUser,
    workspace: workspaceInfo,
    onboardingCompleted: Boolean(workspace), 
  };
}


  @HttpCode(HttpStatus.OK)
  @Post('update')
  async updateUser(
    @Body() updateUserDto: UpdateUserDto,
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    return this.userService.update(updateUserDto, user.id, workspace);
  }
}
