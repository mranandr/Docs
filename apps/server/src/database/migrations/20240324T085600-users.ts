import { Kysely, sql } from 'kysely';

export async function up(db: Kysely<any>): Promise<void> {
  await db.schema
    .createTable('users')
    .addColumn('id', 'uuid', (col) =>
      col.primaryKey().defaultTo(sql`gen_uuid_v7()`),
    )
    .addColumn('name', 'varchar', (col) => col)
    .addColumn('email', 'varchar', (col) => col.notNull())
    .addColumn('email_verified_at', 'timestamptz', (col) => col)
    .addColumn('password', 'varchar', (col) => col) 
    .addColumn('avatar_url', 'varchar', (col) => col)
    .addColumn('role', 'varchar', (col) => col)
    .addColumn('invited_by_id', 'uuid', (col) =>
      col.references('users.id').onDelete('set null'),
    )
    .addColumn('workspace_id', 'uuid', (col) =>
      col.references('workspaces.id').onDelete('cascade'),
    )
    .addColumn('locale', 'varchar', (col) => col)
    .addColumn('timezone', 'varchar', (col) => col)
    .addColumn('settings', 'jsonb', (col) => col)
    .addColumn('last_active_at', 'timestamptz', (col) => col)
    .addColumn('last_login_at', 'timestamptz', (col) => col)
    .addColumn('deactivated_at', 'timestamptz', (col) => col)
    .addColumn('created_at', 'timestamptz', (col) =>
      col.notNull().defaultTo(sql`now()`),
    )
    .addColumn('auth_service', 'varchar', (col) =>
      col.notNull().check(sql`auth_service IN ('jwt', 'sso', 'microsoft')`),
    )    
    .addColumn('sso_provider', 'varchar', (col) => col) 
    .addColumn('auth_type', 'varchar', (col) => col)
    .addColumn('sso_id', 'varchar', (col) => col.unique()) 
    .addColumn('updated_at', 'timestamptz', (col) =>
      col.notNull().defaultTo(sql`now()`),
    )
    .addColumn('deleted_at', 'timestamptz', (col) => col)
    .addUniqueConstraint('users_email_workspace_id_unique', [
      'email',
      'workspace_id',
    ])
    .execute();

  await db.schema
    .createIndex('idx_users_auth_service')
    .on('users')
    .columns(['auth_service'])
    .execute();
}

export async function down(db: Kysely<any>): Promise<void> {
  await db.schema.dropIndex('idx_users_auth_service').execute();
  await db.schema.dropTable('users').execute();
}
