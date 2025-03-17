import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateUserDto } from '../dto/create-user.dto';
import { WorkspaceService } from '../../workspace/services/workspace.service';
import { CreateWorkspaceDto } from '../../workspace/dto/create-workspace.dto';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { KyselyDB, KyselyTransaction } from '@docmost/db/types/kysely.types';
import { executeTx } from '@docmost/db/utils';
import { v7 as genUuidV7} from 'uuid';
import { InjectKysely } from 'nestjs-kysely';
import { User, Workspace } from '@docmost/db/types/entity.types';
import { GroupUserRepo } from '@docmost/db/repos/group/group-user.repo';
import { UserRole } from '../../../common/helpers/types/permission';
import { sql } from 'kysely';
import { GroupRepo } from '@docmost/db/repos/group/group.repo';
import { CreateSpaceDto } from 'src/core/space/dto/create-space.dto';
import { SpaceMemberService } from 'src/core/space/services/space-member.service';
import { SpaceService } from 'src/core/space/services/space.service';
import { SpaceRole } from '../../../common/helpers/types/permission';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { CreateAdminUserDto } from '../dto/create-admin-user.dto';
import { AuthUser } from 'src/common/decorators/auth-user.decorator';
import { authenticate } from 'passport';

@Injectable()
export class SignupService {
  private readonly userRepo: UserRepo;
  private readonly groupUserRepo: GroupUserRepo; 
  private readonly groupRepo: GroupRepo;        
  private readonly workspaceRepo: WorkspaceRepo; 


  constructor(
    private readonly workspaceService: WorkspaceService,
    private readonly spaceService: SpaceService,
    private readonly spaceMemberService: SpaceMemberService,

    @InjectKysely() private readonly db: KyselyDB,
  ) {}

  async signup(
    createUserDto: CreateUserDto,
    workspaceId: string,
    trx?: KyselyTransaction,
  ): Promise<User> {
    const userCheck = await this.userRepo.findByEmail(
      createUserDto.email,
      'sso',
    );

    if (userCheck) {
      throw new BadRequestException(
        'An account with this email already exists in this workspace',
      );
    }

    return await executeTx(
      this.db,
      async (trx) => {
        const user = await this.userRepo.insertUser(
          {
            ...createUserDto,
            workspaceId: workspaceId,
            auth_type: 'sso',
        sso_provider: 'microsoft', 
        role: UserRole.OWNER,
        createdAt: new Date(),
        deactivatedAt: null,
        deletedAt: null,
        emailVerifiedAt: new Date(),
        invitedById: null,
        lastActiveAt: null,
        lastLoginAt: new Date(),
        updatedAt: new Date(),
          },
        );

        await this.workspaceService.addUserToWorkspace(
          user.id,
          workspaceId,
          trx,
        );

        await this.groupUserRepo.addUserToDefaultGroup(
          user.id,
          workspaceId,
          trx,
        );
        return user;
      },
      trx,
    );
  }


  async create(
    user: User,
    createWorkspaceDto: CreateWorkspaceDto,
    trx?: KyselyTransaction,
  ): Promise<Workspace> {
    return await executeTx(
      this.db,
      async (trx) => {
        // Create workspace
        const workspace = await trx
          .insertInto('workspaces')
          .values({
            id: genUuidV7(),
            name: createWorkspaceDto.name,
            hostname: createWorkspaceDto.hostname,
            description: createWorkspaceDto.description,
            ownerId: user.id,
            createdAt: sql`now()`, 
            updatedAt: sql`now()`, 
          })
          .returningAll()
          .executeTakeFirstOrThrow();
  
        await trx
          .updateTable('users')
          .set({ workspaceId: workspace.id, role: UserRole.OWNER })
          .where('id', '=', user.id)
          .execute();
  
        const group = await this.groupRepo.createDefaultGroup(workspace.id, {
          userId: user.id,
          trx: trx,
        });
  
        await this.groupUserRepo.insertGroupUser(
          {
            userId: user.id,
            groupId: group.id,
          },
          trx,
        );
  
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
  
        // Add user to space as admin
        await this.spaceMemberService.addUserToSpace(
          user.id,
          createdSpace.id,
          SpaceRole.ADMIN,
          workspace.id,
          trx,
        );
  
        // Add group to space as writer
        await this.spaceMemberService.addGroupToSpace(
          group.id,
          createdSpace.id,
          SpaceRole.WRITER,
          workspace.id,
          trx,
        );
  
        // Update the workspace with the created default space
        workspace.defaultSpaceId = createdSpace.id;
        await this.workspaceRepo.updateWorkspace(
          { defaultSpaceId: createdSpace.id },
          workspace.id,
          trx,
        );
  
        return workspace;
      },
      trx,
    );
  }
  async initialSetup(
    createAdminUserDto: CreateAdminUserDto,
    trx?: KyselyTransaction,
  ) {
    let user: User,
      workspace: Workspace = null;

    await executeTx(
      this.db,
      async (trx) => {
        user = await this.userRepo.insertUser(
          {
            name: createAdminUserDto.name,
            email: createAdminUserDto.email,
            role: UserRole.OWNER,
            workspaceId: workspace.id,
            auth_type:'Docmost',

          },
        );

        const workspaceData: CreateWorkspaceDto = {
          name: createAdminUserDto.workspaceName,
          email: createAdminUserDto.email, 

        };

        workspace = await this.workspaceService.create(
          user,
          workspaceData,
          trx,
        );

        user.workspaceId = workspace.id;
        return user;
      },
      trx,
    );

    return { user, workspace };
  }

}
