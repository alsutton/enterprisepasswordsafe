FROM tomcat:9.0-alpine

RUN rm -rf /usr/local/tomcat/webapps ; mkdir /usr/local/tomcat/webapps ; mkdir /eps-db ; touch /eps-db/.keep
ENV EPS_DATABASE_HOME=/eps-db

COPY build/libs/enterprisepasswordsafe.war /usr/local/tomcat/webapps/ROOT.war
