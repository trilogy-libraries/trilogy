CREATE USER 'native'@'%';
GRANT ALL PRIVILEGES ON test.* TO 'native'@'%';
ALTER USER 'native'@'%' IDENTIFIED WITH mysql_native_password BY '';
