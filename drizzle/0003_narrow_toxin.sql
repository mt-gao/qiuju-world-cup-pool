ALTER TABLE `fixture_entries` ADD `edit_unlocked_at` text;--> statement-breakpoint
ALTER TABLE `fixture_entries` ADD `revision` integer DEFAULT 1 NOT NULL;