const banColumns = [
  ['isBanned', (table) => table.boolean('isBanned').notNullable().defaultTo(false)],
  ['bannedCode', (table) => table.string('bannedCode', 255)],
  ['bannedReason', (table) => table.text('bannedReason')],
  ['bannedAt', (table) => table.timestamp('bannedAt', { useTz: true })],
  ['bannedUntil', (table) => table.timestamp('bannedUntil', { useTz: true })],
];

const addMissingColumns = async (knex, columns) => {
  for (const [columnName, addColumn] of columns) {
    if (!(await knex.schema.hasColumn('users', columnName))) {
      await knex.schema.alterTable('users', addColumn);
    }
  }
};

exports.up = async (knex) => {
  if (!(await knex.schema.hasTable('users'))) return;

  await addMissingColumns(knex, banColumns);

  if (await knex.schema.hasColumn('users', 'isBlocked')) {
    await knex.schema.alterTable('users', (table) => {
      table.dropColumn('isBlocked');
    });
  }
};

exports.down = async (knex) => {
  if (!(await knex.schema.hasTable('users'))) return;

  if (!(await knex.schema.hasColumn('users', 'isBlocked'))) {
    await knex.schema.alterTable('users', (table) => {
      table.boolean('isBlocked').notNullable().defaultTo(false);
    });
  }

  const existingColumns = [];
  for (const [columnName] of banColumns) {
    if (await knex.schema.hasColumn('users', columnName)) {
      existingColumns.push(columnName);
    }
  }

  if (existingColumns.length) {
    await knex.schema.alterTable('users', (table) => {
      table.dropColumns(...existingColumns);
    });
  }
};
