FROM maven:3.8.4-jdk-11 AS build
WORKDIR /app
COPY app /app
RUN mvn clean package

FROM tomcat:9.0-slim
COPY flag /flag
EXPOSE 8080
COPY --from=build /app/target/app.war $CATALINA_HOME/webapps/
# Ensure ROOT webapp exists (needed for AccessLogValve exploit fallback)
RUN mkdir -p $CATALINA_HOME/webapps/ROOT
# Intentionally use old Debian repos for vulnerable base image
RUN echo "deb http://archive.debian.org/debian stretch stretch-security main contrib non-free" > /etc/apt/sources.list
