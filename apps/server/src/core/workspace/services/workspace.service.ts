import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { v7 as genUuidV7 } from 'uuid';
import { CreateWorkspaceDto } from '../dto/create-workspace.dto';
import { UpdateWorkspaceDto } from '../dto/update-workspace.dto';
import { SpaceService } from '../../space/services/space.service';
import { CreateSpaceDto } from '../../space/dto/create-space.dto';
import { SpaceRole, UserRole } from '../../../common/helpers/types/permission';
import { SpaceMemberService } from '../../space/services/space-member.service';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { KyselyDB, KyselyTransaction } from '@docmost/db/types/kysely.types';
import { executeTx } from '@docmost/db/utils';
import { InjectKysely } from 'nestjs-kysely';
import { User } from '@docmost/db/types/entity.types';
import { GroupUserRepo } from '@docmost/db/repos/group/group-user.repo';
import { GroupRepo } from '@docmost/db/repos/group/group.repo';
import { PaginationOptions } from '@docmost/db/pagination/pagination-options';
import { PaginationResult } from '@docmost/db/pagination/pagination';
import { UpdateWorkspaceUserRoleDto } from '../dto/update-workspace-user-role.dto';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { Workspaces } from '@docmost/db/types/db';
import { sql } from 'kysely';
import { SetupMicrosoftWorkspaceDto } from '../dto/SetupMicrosoftWorkspaceDto';

@Injectable()
export class WorkspaceService {
  private readonly workspaceRepo: WorkspaceRepo;
  private readonly groupUserRepo: GroupUserRepo;
  private readonly userRepo: UserRepo;
  private readonly groupRepo: GroupRepo;


  constructor(
    private readonly spaceService: SpaceService,
    private readonly spaceMemberService: SpaceMemberService,

    @InjectKysely() private readonly db: KyselyDB,
  ) {}

  async findById(workspaceId: string) {
    return this.workspaceRepo.findById(workspaceId);
  }

  async getWorkspaceInfo(workspaceId: string) {
    const workspace = this.workspaceRepo.findById(workspaceId);
    if (!workspace) {
      throw new NotFoundException('Workspace not found');
    }

    return workspace;
  }

  async getWorkspacePublicData(workspaceId: string) {
    const workspace = await this.db
      .selectFrom('workspaces')
      .select(['id'])
      .where('id', '=', workspaceId)
      .executeTakeFirst();
    if (!workspace) {
      throw new NotFoundException('Workspace not found');
    }

    return workspace;
  }

  async addUserToWorkspace(
    userId: string,
    workspaceId: string,
    trx?: KyselyTransaction,
  ): Promise<void> {
    const query = trx ? trx : this.db; 
    await query
      .updateTable('users')
      .set({ workspaceId, role: UserRole.MEMBER })
      .where('id', '=', userId)
      .execute();
  }




  async update(workspaceId: string, updateWorkspaceDto: UpdateWorkspaceDto) {
    const workspace = await this.workspaceRepo.findById(workspaceId);
    if (!workspace) {
      throw new NotFoundException('Workspace not found');
    }

    if (updateWorkspaceDto.name) {
      workspace.name = updateWorkspaceDto.name;
    }

    if (updateWorkspaceDto.logo) {
      workspace.logo = updateWorkspaceDto.logo;
    }

    await this.workspaceRepo.updateWorkspace(updateWorkspaceDto, workspaceId);
    return workspace;
  }

  async getWorkspaceUsers(
    workspaceId: string,
    pagination: PaginationOptions,
  ): Promise<PaginationResult<User>> {
    const users = await this.userRepo.getUsersPaginated(
      workspaceId,
      pagination,
    );

    return users;
  }

  async updateWorkspaceUserRole(
    authUser: User,
    userRoleDto: UpdateWorkspaceUserRoleDto,
    workspaceId: string,
  ) {
    const user = await this.userRepo.findById(userRoleDto.userId, workspaceId);
  
    // Cast the role to UserRole
    const newRole = userRoleDto.role.toLowerCase() as UserRole;
  
    if (!user) {
      throw new BadRequestException('Workspace member not found');
    }
  
    // Validate the role
    if (!Object.values(UserRole).includes(newRole)) {
      throw new BadRequestException('Invalid role');
    }
  
    // Prevent ADMIN from managing OWNER role
    if (
      (authUser.role === UserRole.ADMIN && newRole === UserRole.OWNER) ||
      (authUser.role === UserRole.ADMIN && user.role === UserRole.OWNER)
    ) {
      throw new ForbiddenException();
    }
  
    if (user.role === newRole) {
      return user;
    }
  
    const workspaceOwnerCount = await this.userRepo.roleCountByWorkspaceId(
      workspaceId,
    );
  
    if (user.role === UserRole.OWNER && workspaceOwnerCount === 1) {
      throw new BadRequestException('There must be at least one workspace owner');
    }
  
    await this.userRepo.updateUser(
      {
        role: newRole,
      },
      user.id,
      workspaceId,
    );
  }

  async deactivateUser(): Promise<any> {
    return 'todo';
  }

  async createMicrosoftWorkspace(payload: SetupMicrosoftWorkspaceDto) {
    const { organization, workspace, email, name, auth_type, sso_provider } = payload;
  
    const createdWorkspace = await this.workspaceRepo.insertWorkspace({
      name: workspace,
      organization: organization,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  
    const user = await this.userRepo.insertUser({
      email,
      name,
      workspaceId: createdWorkspace.id,
      role: UserRole.OWNER,
      auth_type,
      sso_provider,
    });
  
    return { workspace: createdWorkspace, user };
  }
  

  async handleFirstUserLogin(user: User, createWorkspaceDto: CreateWorkspaceDto) {
    const existingWorkspace = await this.workspaceRepo.findFirst();

    if (!existingWorkspace) {
      return this.create(user, createWorkspaceDto); 
    }

    return existingWorkspace; 
  }

  async create(
    user: User,
    createWorkspaceDto: CreateWorkspaceDto,
    trx?: KyselyTransaction,
  ) {
    return await executeTx(
      this.db,
      async (trx) => {
        let hostname = undefined;
        let trialEndAt = undefined;
        let status = undefined;
        let plan = undefined;


        // create workspace
        const workspace = await this.workspaceRepo.insertWorkspace(
          {
            name: createWorkspaceDto.name,
            description: createWorkspaceDto.description,
            hostname,
          },
          trx,
        );

        // create default group
        const group = await this.groupRepo.createDefaultGroup(workspace.id, {
          userId: user.id,
          trx: trx,
        });

        // add user to workspace
        await trx
          .updateTable('users')
          .set({
            workspaceId: workspace.id,
            role: UserRole.OWNER,
          })
          .where('users.id', '=', user.id)
          .execute();

        // add user to default group created above
        await this.groupUserRepo.insertGroupUser(
          {
            userId: user.id,
            groupId: group.id,
          },
          trx,
        );

        // create default space
        const spaceInfo: CreateSpaceDto = {
          name: 'General',
          slug: 'general',
        };

        const createdSpace = await this.spaceService.create(
          user.id,
          workspace.id,
          spaceInfo,
          trx,
        );

        // and add user to space as owner
        await this.spaceMemberService.addUserToSpace(
          user.id,
          createdSpace.id,
          SpaceRole.ADMIN,
          workspace.id,
          trx,
        );

        // add default group to space as writer
        await this.spaceMemberService.addGroupToSpace(
          group.id,
          createdSpace.id,
          SpaceRole.WRITER,
          workspace.id,
          trx,
        );

        // update default spaceId
        workspace.defaultSpaceId = createdSpace.id;
        await this.workspaceRepo.updateWorkspace(
          {
            defaultSpaceId: createdSpace.id,
          },
          workspace.id,
          trx,
        );

        return workspace;
      },
      trx,
    );
  }

}
