-- Thu hồi tất cả quyền của user
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'nasv2user'@'%';

-- Chỉ cấp quyền SELECT
GRANT SELECT ON nasv2db.* TO 'nasv2user'@'%';

-- Áp dụng thay đổi
FLUSH PRIVILEGES;
