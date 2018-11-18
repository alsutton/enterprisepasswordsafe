FROM tomcat:9.0-alpine

RUN rm -rf /usr/local/tomcat/webapps; mkdir /usr/local/tomcat/webapps
COPY build/libs/enterprisepasswordsafe.war /usr/local/tomcat/webapps/ROOT.war

#
# These are an exmple of the values you need to set to configure the database. The
# values given here will create a database which is local to the docker container and
# will not persist between restarts. To configure a persistent database please
# change the values appropriately
#
ENV EPS_DATABASE_TYPE="Apache Derby"
ENV EPS_JDBC_DRIVER_CLASS="org.apache.derby.jdbc.EmbeddedDriver"
ENV EPS_JDBC_URL="jdbc:derby:/eps-db/pwsafe-hsqldb;create=true"
ENV EPS_DATABASE_USERNAME=""
ENV EPS_DATABASE_PASSWORD=""

# Create the home directory for our demo database
RUN  mkdir /eps-db ; touch /eps-db/.keep