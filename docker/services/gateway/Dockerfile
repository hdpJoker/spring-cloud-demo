# 构建阶段
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /build
# 配置腾讯云Maven镜像
RUN mkdir -p /root/.m2 && \
    echo '<?xml version="1.0" encoding="UTF-8"?><settings xmlns="http://maven.apache.org/SETTINGS/1.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd"><mirrors><mirror><id>tencent</id><mirrorOf>central</mirrorOf><url>https://mirrors.cloud.tencent.com/nexus/repository/maven-public/</url></mirror></mirrors></settings>' > /root/.m2/settings.xml

# 复制公共模块和POM文件
COPY pom.xml .
COPY spring-cloud-demo-common/pom.xml spring-cloud-demo-common/
COPY spring-cloud-demo-common/src spring-cloud-demo-common/src
# 复制Gateway模块
COPY spring-cloud-demo-gateway/pom.xml spring-cloud-demo-gateway/
COPY spring-cloud-demo-gateway/src spring-cloud-demo-gateway/src

# 修改父 pom.xml，只保留需要的模块
RUN sed -e '/spring-cloud-demo-uaa/d' -e '/spring-cloud-demo-product/d' pom.xml > pom-tmp.xml && \
    mv pom-tmp.xml pom.xml

# 构建项目
RUN mvn clean package -DskipTests

# 运行阶段
FROM amazoncorretto:17-alpine
WORKDIR /app
RUN addgroup -S appuser && adduser -S appuser -G appuser
COPY --from=builder --chown=appuser:appuser /build/spring-cloud-demo-gateway/target/spring-cloud-demo-gateway-1.0.0.jar app.jar
USER appuser
EXPOSE 7573
ENTRYPOINT ["java", "-jar", "app.jar"]
