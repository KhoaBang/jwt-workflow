CREATE TABLE `info` (
	`id` INT(11) NOT NULL AUTO_INCREMENT,
	`username` VARCHAR(30) NOT NULL COLLATE 'utf8mb4_uca1400_ai_ci',
	`email` VARCHAR(30) NOT NULL COLLATE 'utf8mb4_uca1400_ai_ci',
	`password` VARCHAR(30) NOT NULL COLLATE 'utf8mb4_uca1400_ai_ci',
	`created_at` DATETIME NOT NULL DEFAULT current_timestamp(),
	PRIMARY KEY (`id`) USING BTREE,
	UNIQUE INDEX `email` (`email`) USING BTREE
)
ENGINE=InnoDB
;
CREATE TABLE refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    user_email VARCHAR(255),
    status ENUM('active', 'revoked') DEFAULT 'active',
    expires_at DATETIME,
    FOREIGN KEY (user_email) REFERENCES info(email)
);
