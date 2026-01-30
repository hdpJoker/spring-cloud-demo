# Spring Cloud Demo

基于 Spring Boot 3.x + Spring Cloud 2023.x + Spring Cloud Alibaba 的微服务演示项目，集成了 OAuth2 认证授权、服务注册发现、API 网关等功能。

## 环境要求

- **JDK 17+** (必须)
- Maven 3.6+
- Docker 20.10+
- Docker Compose 1.29+

## 项目简介

本项目是一个完整的微服务架构演示系统，展示了如何使用现代化的 Spring 技术栈构建企业级应用。系统包含以下核心模块：

- **UAA 服务**：统一认证授权中心，支持数据库登录、LDAP 登录、GitHub OAuth2 登录
- **Product 服务**：产品管理服务，演示资源服务器和基于角色的访问控制
- **Gateway 服务**：API 网关，统一入口和路由转发（唯一对外暴露端口 7573）
- **Common 模块**：公共实体和工具类

## 技术栈

- **Spring Boot 3.2.10**: 基础应用框架
- **Spring Cloud 2023.0.3**: 微服务框架
- **Spring Cloud Alibaba 2023.0.1.0**: 阿里云微服务组件
- **Spring Authorization Server 1.2.5**: OAuth2/OIDC 授权服务器
- **Nacos 2.3.0**: 服务注册发现与配置中心
- **MySQL 8.0**: 关系型数据库
- **OpenLDAP 1.5.0**: LDAP 目录服务

## 快速开始

### 1. 构建项目

```bash
# 编译整个项目
mvn clean install -DskipTests
```

### 2. 使用 Docker Compose 启动

```bash
# 进入 docker 目录
cd docker

# 启动所有服务
docker-compose up -d

# 查看服务状态
docker-compose ps

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down

# 停止服务并清理数据
docker-compose down -v
```

### 3. 访问登录页面

打开浏览器访问：**http://localhost:7573/login.html**

页面支持三种登录方式：
- 数据库用户名密码登录
- LDAP 登录
- GitHub OAuth2 登录

## 测试用户

### 数据库用户

| 用户名 | 密码 | 角色 | 权限 |
|--------|------|------|------|
| user_1 | user_1 | USER | 查看产品 |
| editor_1 | editor_1 | EDITOR | 查看、添加、修改、删除产品 |
| adm_1 | adm_1 | PRODUCT_ADMIN | 所有权限 |

### LDAP 用户

| 用户名 | 密码 | 角色 | 权限 |
|--------|------|------|------|
| ldap_user_1 | ldap_user_1 | USER | 查看产品 |
| ldap_editor_1 | ldap_editor_1 | EDITOR | 查看、添加、修改、删除产品 |
| ldap_adm_1 | ldap_adm_1 | PRODUCT_ADMIN | 所有权限 |

### GitHub 登录

GitHub 登录后自动获得 **EDITOR** 角色。

## API 权限说明

| 角色 | 查看产品 | 添加产品 | 修改产品 | 删除产品 |
|------|---------|---------|---------|---------|
| USER | ✓ | ✗ | ✗ | ✗ |
| EDITOR | ✓ | ✓ | ✓ | ✓ |
| PRODUCT_ADMIN | ✓ | ✓ | ✓ | ✓ |

## CURL 命令测试

### 1. 获取 Access Token（数据库用户）

**使用 user_1 用户（USER 角色）：**

```bash
curl -X POST "http://localhost:7573/uaa/api/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user_1&password=user_1"
```

**使用 editor_1 用户（EDITOR 角色）：**

```bash
curl -X POST "http://localhost:7573/uaa/api/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=editor_1&password=editor_1"
```

**使用 adm_1 用户（PRODUCT_ADMIN 角色）：**

```bash
curl -X POST "http://localhost:7573/uaa/api/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=adm_1&password=adm_1"
```

**响应示例：**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "refresh_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 1799,
  "scope": "read write USER"
}
```

### 2. 获取 Access Token（LDAP 用户）

```bash
curl -X POST "http://localhost:7573/uaa/api/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=ldap_editor_1&password=ldap_editor_1"
```

### 3. 查看产品列表

需要 USER、EDITOR 或 PRODUCT_ADMIN 角色。

```bash
# 设置 TOKEN 变量（替换为实际获取的 token）
TOKEN="eyJhbGciOiJSUzI1NiJ9..."

# 获取产品列表
curl -X GET "http://localhost:7573/api/products" \
  -H "Authorization: Bearer ${TOKEN}"
```

**响应示例：**

```json
[
  {"id": 1, "name": "示例产品1"},
  {"id": 2, "name": "示例产品2"},
  {"id": 3, "name": "示例产品3"}
]
```

### 4. 添加产品

需要 EDITOR 或 PRODUCT_ADMIN 角色。

```bash
curl -X POST "http://localhost:7573/api/products" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"name": "新产品"}'
```

**响应示例：**

```json
{"id": 4, "name": "新产品"}
```

### 5. 修改产品

需要 EDITOR 或 PRODUCT_ADMIN 角色。

```bash
curl -X PUT "http://localhost:7573/api/products/4" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"name": "更新后的产品名称"}'
```

**响应示例：**

```json
{"id": 4, "name": "更新后的产品名称"}
```

### 6. 删除产品

需要 EDITOR 或 PRODUCT_ADMIN 角色。

```bash
curl -X DELETE "http://localhost:7573/api/products/4" \
  -H "Authorization: Bearer ${TOKEN}"
```

### 完整测试脚本

```bash
#!/bin/bash

# 1. 使用 editor_1 获取 Token
echo "=== 获取 Access Token ==="
RESPONSE=$(curl -s -X POST "http://localhost:7573/uaa/api/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=editor_1&password=editor_1")

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

# 提取 token
TOKEN=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token', ''))" 2>/dev/null)

if [ -z "$TOKEN" ]; then
  echo "获取 Token 失败"
  exit 1
fi

echo ""
echo "=== 获取产品列表 ==="
curl -s -X GET "http://localhost:7573/api/products" \
  -H "Authorization: Bearer ${TOKEN}" | python3 -m json.tool 2>/dev/null

echo ""
echo "=== 添加产品 ==="
curl -s -X POST "http://localhost:7573/api/products" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"name": "测试产品"}' | python3 -m json.tool 2>/dev/null

echo ""
echo "=== 再次获取产品列表 ==="
curl -s -X GET "http://localhost:7573/api/products" \
  -H "Authorization: Bearer ${TOKEN}" | python3 -m json.tool 2>/dev/null
```

## GitHub OAuth2 配置

如果需要使用 GitHub 登录功能，需要创建 GitHub OAuth App：

1. 访问 https://github.com/settings/applications/new
2. 填写应用信息：
   - Application name: Spring Cloud Demo
   - Homepage URL: http://localhost:7573
   - Authorization callback URL: http://localhost:7573/uaa/login/oauth2/code/github
3. 获取 Client ID 和 Client Secret
4. 启动时设置环境变量：

```bash
export GITHUB_CLIENT_ID=your-client-id
export GITHUB_CLIENT_SECRET=your-client-secret
docker-compose up -d
```

## 服务端口说明

| 服务 | 端口 | 说明 |
|------|------|------|
| Gateway | 7573 | **唯一对外暴露端口** |
| UAA | 8081 | 内部服务 |
| Product | 8082 | 内部服务 |
| MySQL | 3306 | 内部服务 |
| Nacos | 8848 | 内部服务 |
| OpenLDAP | 389 | 内部服务 |

## 项目结构

```
spring-cloud-demo/
├── docker/                          # Docker 配置
│   ├── docker-compose.yaml          # 容器编排文件
│   ├── mysql/
│   │   └── init.sql                 # 数据库初始化脚本
│   ├── nacos/
│   │   └── application.properties   # Nacos 配置
│   ├── openldap/
│   │   └── users.ldif               # LDAP 用户数据
│   └── services/                    # 服务 Dockerfile
├── spring-cloud-demo-common/        # 公共模块
├── spring-cloud-demo-uaa/           # 认证授权服务
├── spring-cloud-demo-product/       # 产品服务
└── spring-cloud-demo-gateway/       # 网关服务
```

## 故障排查

### 服务无法启动

```bash
# 检查容器状态
docker-compose ps

# 查看服务日志
docker-compose logs mysql
docker-compose logs nacos
docker-compose logs uaa
docker-compose logs product
docker-compose logs gateway
```

### 获取 Token 失败

1. 确认 UAA 服务已启动
2. 检查用户名和密码是否正确
3. 确认数据库初始化成功

### API 调用返回 403

1. 确认 Token 有效
2. 检查用户角色是否有足够权限
3. 查看服务日志获取详细错误信息

## 许可证

MIT
