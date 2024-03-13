CREATE USER 'caching_sha2'@'%';
GRANT ALL PRIVILEGES ON test.* TO 'caching_sha2'@'%';
ALTER USER 'caching_sha2'@'%' IDENTIFIED WITH caching_sha2_password BY 'password';
