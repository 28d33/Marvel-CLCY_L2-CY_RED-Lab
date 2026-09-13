-- DVWA database seed (mirrors dvwa/includes/DBMS/MySQL.php setup)
CREATE TABLE IF NOT EXISTS users (user_id int(6),first_name varchar(15),last_name varchar(15), user varchar(15), password varchar(32),avatar varchar(70), last_login TIMESTAMP, failed_login INT(3), PRIMARY KEY (user_id));

INSERT INTO users (user_id, first_name, last_name, user, password, avatar, last_login, failed_login) VALUES
    ('1','admin','admin','admin',MD5('password'),'hackable/users/admin.jpg', NOW(), '0'),
    ('2','Gordon','Brown','gordonb',MD5('abc123'),'hackable/users/gordonb.jpg', NOW(), '0'),
    ('3','Hack','Me','1337',MD5('charley'),'hackable/users/1337.jpg', NOW(), '0'),
    ('4','Pablo','Picasso','pablo',MD5('letmein'),'hackable/users/pablo.jpg', NOW(), '0'),
    ('5','Bob','Smith','smithy',MD5('password'),'hackable/users/smithy.jpg', NOW(), '0');

ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user';
UPDATE users SET role = 'admin' WHERE user = 'admin';
ALTER TABLE users ADD COLUMN IF NOT EXISTS account_enabled TINYINT(1) DEFAULT 1;

CREATE TABLE IF NOT EXISTS access_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    target_id INT NOT NULL,
    action VARCHAR(50) NOT NULL,
    timestamp DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (target_id) REFERENCES users(user_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    target_id INT NOT NULL,
    action VARCHAR(50) NOT NULL,
    timestamp DATETIME NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (target_id) REFERENCES users(user_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS guestbook (comment_id SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT, comment varchar(300), name varchar(100), PRIMARY KEY (comment_id));
INSERT INTO guestbook VALUES ('1','This is a test comment.','test');