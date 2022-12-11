CREATE DATABASE IF NOT EXISTS nord_files;
USE nord_files;
CREATE TABLE if not exists files_info (path VARCHAR(255) PRIMARY KEY, size INT NOT NULL, type VARCHAR(3) NOT NULL, architecture ENUM ('32', '64'), imports INT, exports INT, INDEX(size, type));
