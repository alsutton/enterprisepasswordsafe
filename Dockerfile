FROM tomcat:9.0-alpine

RUN rm -rf /usr/local/tomcat/webapps ; mkdir /usr/local/tomcat/webapps

COPY build/libs/enterprisepasswordsafe.war /usr/local/tomcat/webapps/ROOT.war
