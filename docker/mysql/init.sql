-- 创建 Nacos 配置数据库
CREATE DATABASE IF NOT EXISTS nacos_config;

-- 创建应用数据库
CREATE DATABASE IF NOT EXISTS spring_cloud_demo;

USE spring_cloud_demo;

-- 创建用户表
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建产品表
CREATE TABLE IF NOT EXISTS products (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 插入测试用户（用户名即密码，BCrypt加密后）
-- user_1 密码: user_1
-- editor_1 密码: editor_1
-- adm_1 密码: adm_1
INSERT INTO users (username, password, role, enabled) VALUES
('user_1', '$2a$10$xleee.ThY33OPoScHKKIKu7.c1zw0kCLShs2TIpbf698wmM1tvhD6', 'USER', TRUE),
('editor_1', '$2a$10$inI9hATzDdCoe0Rim/98oe6ZNp0t4WYqEskA9NJfwBIRSOeeSZ1qK', 'EDITOR', TRUE),
('adm_1', '$2a$10$ibIabmYZMHS8aOT3IzZBAul10qe1DCuPA0OY5NOr6fx/pQlnud9MO', 'PRODUCT_ADMIN', TRUE)
ON DUPLICATE KEY UPDATE username=username;

-- 插入测试产品数据
INSERT INTO products (name) VALUES
('示例产品1'),
('示例产品2'),
('示例产品3')
ON DUPLICATE KEY UPDATE name=name;
