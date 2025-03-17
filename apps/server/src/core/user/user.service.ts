import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { InjectKysely } from 'nestjs-kysely';
import { KyselyDB } from '@docmost/db/types/kysely.types';
import { UserRole } from 'src/common/helpers/types/permission';
import { User } from '@docmost/db/types/entity.types';

@Injectable()
export class UserService {
  constructor(private userRepo: UserRepo,
    @InjectKysely()
    private readonly db: KyselyDB,
  ) {}

  async integrateMsUser(msUserId: string): Promise<void> {
    const msUser = await this.db
    .selectFrom('users') 
    .selectAll()
    .where('id', '=', msUserId)
    .executeTakeFirst();
    if (!msUser) {
      throw new Error('MsUser not found');
    }


    const userExists = await this.db.selectFrom('users').selectAll().where('email', '=', msUser.email).executeTakeFirst();
    if (!userExists) {
      await this.db.insertInto('users').values({
        email: msUser.email,
        name: msUser.name,
        avatarUrl: msUser.avatarUrl,
        workspaceId: msUser.workspaceId,
        createdAt: new Date(),
        updatedAt: new Date(),
      }).execute();
    }
  }

  async isFirstUser(): Promise<boolean> {
    const count = await this.db
      .selectFrom('users')
      .select(({ fn }) => fn.count<number>('id').as('userCount'))
      .executeTakeFirst();
  
    return count?.userCount === 0;
  }
  

  async findById(userId: string, workspaceId: string) {
    return this.userRepo.findById(userId, workspaceId);
  }

  async update(
    updateUserDto: UpdateUserDto,
    userId: string,
    workspaceId: string,
  ) {
    const user = await this.userRepo.findById(userId, workspaceId);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (typeof updateUserDto.fullPageWidth !== 'undefined') {
      return this.updateUserPageWidthPreference(
        userId,
        updateUserDto.fullPageWidth,
      );
    }

    if (updateUserDto.name) {
      user.name = updateUserDto.name;
    }

    if (updateUserDto.email && user.email != updateUserDto.email) {
      if (await this.userRepo.findByEmail(updateUserDto.email, 'Docmost')) {
        throw new BadRequestException('A user with this email already exists');
      }
      user.email = updateUserDto.email;
    }

    if (updateUserDto.avatarUrl) {
      user.avatarUrl = updateUserDto.avatarUrl;
    }

    if (updateUserDto.locale) {
      user.locale = updateUserDto.locale;
    }

    await this.userRepo.updateUser(
      { ...updateUserDto, role: updateUserDto.role as UserRole }, 
      userId, 
      workspaceId
    );
    return user;
  }


  async updateUserPageWidthPreference(userId: string, fullPageWidth: boolean) {
    return this.userRepo.updatePreference(
      userId,
      'fullPageWidth',
      fullPageWidth,
    );
  }
  async findByEmail(email: string, auth_type: "Docmost" | "sso") {
    return this.userRepo.findByEmail(email, auth_type);
  }
  
  async updateUser(updateData: Partial<User>, userId: string, workspaceId: string) {
    return this.userRepo.updateUser(updateData, userId, workspaceId);
  }
}