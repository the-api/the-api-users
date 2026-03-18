const columns = [
  ['timeCreated', (table, knex) => table.timestamp('timeCreated').notNullable().defaultTo(knex.fn.now())],
  ['timeUpdated', (table) => table.timestamp('timeUpdated')],
  ['timeDeleted', (table) => table.timestamp('timeDeleted')],
  ['isBlocked', (table) => table.boolean('isBlocked').notNullable().defaultTo(false)],
  ['isDeleted', (table) => table.boolean('isDeleted').notNullable().defaultTo(false)],
  ['login', (table) => table.string('login', 255).unique()],
  ['password', (table) => table.string('password', 255).nullable()],
  ['salt', (table) => table.string('salt', 255).nullable()],
  ['timePasswordChanged', (table) => table.timestamp('timePasswordChanged')],
  ['email', (table) => table.string('email', 1024).nullable()],
  ['isEmailVerified', (table) => table.boolean('isEmailVerified').notNullable().defaultTo(false)],
  ['isEmailInvalid', (table) => table.boolean('isEmailInvalid').notNullable().defaultTo(false)],
  ['phone', (table) => table.string('phone', 255).unique()],
  ['isPhoneVerified', (table) => table.boolean('isPhoneVerified').notNullable().defaultTo(false)],
  ['isPhoneInvalid', (table) => table.boolean('isPhoneInvalid').notNullable().defaultTo(false)],
  ['fullName', (table) => table.string('fullName', 1024)],
  ['displayName', (table) => table.string('displayName', 255)],
  ['avatar', (table) => table.string('avatar', 2048)],
  ['role', (table) => table.string('role', 128)],
  ['locale', (table) => table.string('locale', 32)],
  ['timezone', (table) => table.string('timezone', 32)],
  ['refresh', (table) => table.string('refresh', 255)],
  ['timeRefreshExpired', (table) => table.timestamp('timeRefreshExpired')],
  ['oauthProviders', (table) => table.jsonb('oauthProviders')],
  ['registerCode', (table) => table.string('registerCode', 128)],
  ['registerCodeAttempts', (table) => table.integer('registerCodeAttempts').notNullable().defaultTo(0)],
  ['timeRegisterCodeExpired', (table) => table.timestamp('timeRegisterCodeExpired')],
  ['recoverCode', (table) => table.string('recoverCode', 128)],
  ['recoverCodeAttempts', (table) => table.integer('recoverCodeAttempts').notNullable().defaultTo(0)],
  ['timeRecoverCodeExpired', (table) => table.timestamp('timeRecoverCodeExpired')],
  ['phoneCode', (table) => table.string('phoneCode', 32)],
  ['phoneCodeAttempts', (table) => table.integer('phoneCodeAttempts').notNullable().defaultTo(0)],
  ['timePhoneCodeExpired', (table) => table.timestamp('timePhoneCodeExpired')],
  ['phoneToChange', (table) => table.string('phoneToChange', 255)],
  ['phoneChangeCode', (table) => table.string('phoneChangeCode', 32)],
  ['phoneChangeCodeAttempts', (table) => table.integer('phoneChangeCodeAttempts').notNullable().defaultTo(0)],
  ['timePhoneChangeCodeExpired', (table) => table.timestamp('timePhoneChangeCodeExpired')],
  ['emailToChange', (table) => table.string('emailToChange', 1024)],
  ['emailChangeCode', (table) => table.string('emailChangeCode', 128)],
  ['emailChangeCodeAttempts', (table) => table.integer('emailChangeCodeAttempts').notNullable().defaultTo(0)],
  ['timeEmailChangeCodeExpired', (table) => table.timestamp('timeEmailChangeCodeExpired')],
];

exports.up = async (knex) => {
  const hasUsersTable = await knex.schema.hasTable('users');

  if (!hasUsersTable) {
    return;
  }

  for (const [columnName, addColumn] of columns) {
    const hasColumn = await knex.schema.hasColumn('users', columnName);

    if (!hasColumn) {
      await knex.schema.alterTable('users', (table) => {
        addColumn(table, knex);
      });
    }
  }
};

exports.down = () => {};
