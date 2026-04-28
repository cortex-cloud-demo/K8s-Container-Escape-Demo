FROM maven:3.8.4-jdk-11 AS build
WORKDIR /app
COPY app /app
RUN mvn clean package

FROM tomcat:9.0-slim

LABEL maintainer="chrisley75"
LABEL purpose="Demo Web App vulnerable - Unsecure by Design"
LABEL org.opencontainers.image.ref.name="k8s-escape-demo-vuln-app"

COPY flag /flag
EXPOSE 8080
COPY --from=build /app/target/app.war $CATALINA_HOME/webapps
# Intentionally use old Debian repos for vulnerable base image
RUN echo "deb http://archive.debian.org/debian stretch stretch-security main contrib non-free" > /etc/apt/sources.list
