import { Injectable } from '@nestjs/common';
import { InjectKysely } from 'nestjs-kysely';
import { KyselyDB, KyselyTransaction } from '@docmost/db/types/kysely.types';
import { Users } from '@docmost/db/types/db';
import { dbOrTx } from '@docmost/db/utils';
import {
  InsertableUser,
  UpdatableUser,
  User,
} from '@docmost/db/types/entity.types';
import { PaginationOptions } from '../../pagination/pagination-options';
import { executeWithPagination } from '@docmost/db/pagination/pagination';
import { sql } from 'kysely';
import { AuthService } from '../../../core/auth/services/auth.service';
import { UserRole } from 'src/common/helpers/types/permission';

@Injectable()
export class UserRepo {
  private readonly authService: AuthService; 
  constructor(
    @InjectKysely() private readonly db: KyselyDB,
  ) {}
  private baseFields: Array<keyof Users> = [
    'id', 'email', 'name', 'emailVerifiedAt', 'avatarUrl', 'role',
    'workspaceId', 'locale', 'timezone', 'settings', 'lastLoginAt',
    'deactivatedAt', 'createdAt', 'updatedAt', 'deletedAt', 'role'
  ];

  async findOne(userFilter: { email: string; workspaceId: string; auth_service?: 'Docmost' | 'microsoft' }) {
    return await this.db
      .selectFrom('users')
      .selectAll()
      .where('users.email', '=', userFilter.email)
      .where('users.workspaceId', '=', userFilter.workspaceId)
      .where('users.sso_provider', '=', userFilter.auth_service ?? 'Docmost')
      .executeTakeFirst();
  }

  async findByEmail(email: string, auth_type: 'Docmost' | 'sso'): Promise<User | undefined> {
    return this.db
      .selectFrom('users')
      .selectAll()
      .where('email', '=', email)
      .where('auth_type', '=', auth_type)
      .executeTakeFirst();
  }

  async insertUser(payload: {
    email: string;
    name: string;
    workspaceId: string;
    auth_type: string;
    sso_provider: string;
    role?: string;
  }) {
    const user = await this.db.insertInto('users').values({
      email: payload.email,
      name: payload.name,
      workspaceId: payload.workspaceId,
      auth_type: payload.auth_type as 'Docmost' | 'sso',
      sso_provider: payload.sso_provider as 'microsoft' | 'Docmost',
      createdAt: new Date(),
      updatedAt: new Date(),
      role: UserRole.OWNER,
      password: null,
      emailVerifiedAt: new Date(),
    }).returning('id').executeTakeFirst();
  
    return user;
  }

  async updateUser(
    updatableUser: UpdatableUser,
    userId: string,
    workspaceId: string,
  ) {
    const db = dbOrTx(this.db);

    return await db
      .updateTable('users')
      .set({ ...updatableUser, updatedAt: new Date() })
      .where('id', '=', userId)
      .where('workspaceId', '=', workspaceId)
      .execute();
  }

  async getUsersPaginated(workspaceId: string, pagination: PaginationOptions) {
    let query = this.db
      .selectFrom('users')
      .select(this.baseFields)
      .where('workspaceId', '=', workspaceId)
      .orderBy('createdAt', 'asc');

    if (pagination.query) {
      query = query.where((eb) =>
        eb('users.name', 'ilike', `%${pagination.query}%`).or(
          'users.email',
          'ilike',
          `%${pagination.query}%`,
        ),
      );
    }

    return executeWithPagination(query, {
      page: pagination.page,
      perPage: pagination.limit,
    });
  }

  async updatePreference(userId: string, prefKey: string, prefValue: string | boolean) {
    return await this.db
      .updateTable('users')
      .set({
        settings: sql`COALESCE(settings, '{}'::jsonb)
                || jsonb_build_object('preferences', COALESCE(settings->'preferences', '{}'::jsonb) 
                || jsonb_build_object('${sql.raw(prefKey)}', ${sql.lit(prefValue)}))`,
        updatedAt: new Date(),
      })
      .where('id', '=', userId)
      .returning(this.baseFields)
      .executeTakeFirst();
  }

  async findById(userId: string, workspaceId: string): Promise<User | null> {
    return this.db
      .selectFrom('users')
      .selectAll()
      .where('id', '=', userId)
      .where('workspaceId', '=', workspaceId)
      .executeTakeFirst();
  }

  async roleCountByWorkspaceId(workspaceId: string): Promise<number> {
    const result = await this.db
      .selectFrom('users')
      .select((eb) => eb.fn.countAll().as('count'))
      .where('workspaceId', '=', workspaceId)
      .executeTakeFirst();

    return Number(result?.count) ?? 0;
  }

  async create(userData: InsertableUser): Promise<User> {
    return this.db
      .insertInto('users')
      .values(userData)
      .returningAll()
      .executeTakeFirstOrThrow();
  }

  async save(user: User): Promise<User> {
    const userToUpdate = await this.db
      .selectFrom('users')
      .selectAll()
      .where('id', '=', user.id)
      .executeTakeFirst();

    if (userToUpdate) {
      await this.db
        .updateTable('users')
        .set(user)
        .where('id', '=', user.id)
        .execute();
    } else {
      await this.db.insertInto('users').values(user).execute();
    }

    return user;
  }

  async updateLastLogin(userId: string, workspaceId: string): Promise<void> {
    const user = await this.findById(userId, workspaceId);
    if (user) {
      user.lastLoginAt = new Date();
      await this.save(user);
    }
  }

  async createUser(userData: { email: string; workspaceId: string; auth_service?: 'microsoft' | 'Docmost' }) {
    return this.db.transaction().execute(async (trx) => {
      try {
        // Step 1: Check if workspace exists
        const workspaceExists = await trx
          .selectFrom('workspaces')
          .select('id')
          .where('id', '=', userData.workspaceId)
          .executeTakeFirst();
  
        if (!workspaceExists) {
          await trx
            .insertInto('workspaces')
            .values({
              id: userData.workspaceId,
              createdAt: new Date(),
              updatedAt: new Date(),
              // Add other required fields for workspace
            })
            .returning('id')
            .executeTakeFirst();
          console.log(`Created new workspace with ID: ${userData.workspaceId}`);
        }
  
        let user = await trx
          .selectFrom('users')
          .selectAll()
          .where('email', '=', userData.email)
          .where('workspaceId', '=', userData.workspaceId)
          .where('sso_provider', '=', userData.auth_service ?? 'Docmost')
          .executeTakeFirst();
  
        if (!user) {
          const hashedPassword = await this.authService.hashPassword('');
  
          const newUser: InsertableUser = {
            email: userData.email.toLowerCase(),
            workspaceId: userData.workspaceId,
            name: userData.email.split('@')[0],
            password: hashedPassword,
            locale: 'en-US',
            role: UserRole.MEMBER,
            lastLoginAt: new Date(),
            createdAt: new Date(),
            updatedAt: new Date(),
            auth_type: userData.auth_service === 'microsoft' ? 'Docmost' : 'Docmost',
          };
  
          user = await trx
            .insertInto('users')
            .values(newUser)
            .returningAll()
            .executeTakeFirst();
          console.log(`Created new user with email: ${userData.email}`);
        }
  
        return user;
      } catch (error) {
        console.error('Error during user and workspace creation:', error);
        throw error; 
      }
    });
  }
}