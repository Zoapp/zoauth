const migrations = [
  {
    id: 1,
    name: "add_salt_column_to_users_table",
    queries: [
      "ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `salt` VARCHAR(128);",
      "ALTER TABLE `users` MODIFY `password` VARCHAR(128) COLLATE utf8_unicode_ci DEFAULT NULL;",
    ],
  },
];

export default migrations;
