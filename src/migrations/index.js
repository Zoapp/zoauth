const migrations = [
  {
    id: 1,
    name: "add_salt_column_to_users_table",
    queries: [
      "ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `salt` VARCHAR(128);",
      "ALTER TABLE `users` MODIFY `password` VARCHAR(128) COLLATE utf8_unicode_ci DEFAULT NULL;",
    ],
  },
  {
    id: 2,
    name: "add_user_state_account",
    queries: [
      "ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `account_state` varchar(20) NOT NULL DEFAULT 'enable';",
      "ALTER TABLE `users` ALTER `account_state` SET DEFAULT 'disable';",
      "ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `account_state_updated_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;",
    ],
  },
];

export default migrations;
