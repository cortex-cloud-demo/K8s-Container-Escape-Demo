FROM maven:3.8.4-jdk-11 AS build
WORKDIR /app
COPY app /app
RUN mvn clean package

FROM tomcat:9.0-slim

ARG GIT_COMMIT=unknown
ARG GIT_REPO_URL=https://github.com/cortex-cloud-demo/K8s-Container-Escape-Demo
ARG BUILD_DATE=unknown

LABEL maintainer="chrisley75"
LABEL purpose="Demo Web App vulnerable - Unsecure by Design"
LABEL org.opencontainers.image.ref.name="k8s-escape-demo-vuln-app"
LABEL org.opencontainers.image.title="vuln-app"
LABEL org.opencontainers.image.description="Spring4Shell (CVE-2022-22965) vulnerable demo app for K8s container escape"
LABEL org.opencontainers.image.source="${GIT_REPO_URL}"
LABEL org.opencontainers.image.url="${GIT_REPO_URL}"
LABEL org.opencontainers.image.documentation="${GIT_REPO_URL}/blob/main/README.md"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL com.cortex.demo.dockerfile_path="Dockerfile"
LABEL com.cortex.demo.git_commit="${GIT_COMMIT}"
LABEL com.cortex.demo.git_repo_url="${GIT_REPO_URL}"

COPY flag /flag
EXPOSE 8080
COPY --from=build /app/target/app.war $CATALINA_HOME/webapps
# Intentionally use old Debian repos for vulnerable base image
RUN echo "deb http://archive.debian.org/debian stretch stretch-security main contrib non-free" > /etc/apt/sources.list
