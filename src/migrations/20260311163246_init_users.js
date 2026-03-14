exports.up = (knex) => knex.schema
  .createTable('users', (table) => {
    table.increments('id');
    table.timestamp('timeCreated').notNullable().defaultTo(knex.fn.now());
    table.timestamp('timeUpdated');
    table.timestamp('timeDeleted');
    table.boolean('isBlocked').notNullable().defaultTo(false);
    table.boolean('isDeleted').notNullable().defaultTo(false);

    table.string('login', 255).unique();
    table.string('password', 255).notNullable();
    table.string('salt', 255).notNullable();
    table.timestamp('timePasswordChanged');

    table.string('email', 1024).notNullable().unique();
    table.boolean('isEmailVerified').notNullable().defaultTo(false);
    table.boolean('isEmailInvalid').notNullable().defaultTo(false);

    table.string('phone', 255).unique();
    table.boolean('isPhoneVerified').notNullable().defaultTo(false);
    table.boolean('isPhoneInvalid').notNullable().defaultTo(false);

    table.string('fullName', 255);

    table.string('avatar', 2048);

    table.string('role', 128);

    //locale, timezone
    table.string('locale', 32);
    table.string('timezone', 32);

    table.string('refresh', 255);
    table.timestamp('timeRefreshExpired');

    table.string('registerCode', 128);
    table.integer('registerCodeAttempts').notNullable().defaultTo(0);
    table.timestamp('timeRegisterCodeExpired');

    table.string('recoverCode', 128);
    table.integer('recoverCodeAttempts').notNullable().defaultTo(0);
    table.timestamp('timeRecoverCodeExpired');

    table.string('phoneCode', 32);
    table.integer('phoneCodeAttempts').notNullable().defaultTo(0);
    table.timestamp('timePhoneCodeExpired');
    table.string('phoneToChange', 255);
    table.string('phoneChangeCode', 32);
    table.integer('phoneChangeCodeAttempts').notNullable().defaultTo(0);
    table.timestamp('timePhoneChangeCodeExpired');

    table.string('emailToChange', 1024);
    table.string('emailChangeCode', 128);
    table.integer('emailChangeCodeAttempts').notNullable().defaultTo(0);
    table.timestamp('timeEmailChangeCodeExpired');
  })

exports.down = (knex) => knex.schema.dropTable('users');
