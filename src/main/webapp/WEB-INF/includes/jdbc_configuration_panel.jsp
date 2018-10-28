<%@ page language="java" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%--
Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  --%>
<fieldset>
    <div class="form-group">
        <label for="database">Database Type</label>
        <select name="database" id="database" class="form-control">
            <c:choose>
                <c:when test="${(requestScope.jdbcConfig != null) && (requestScope.jdbcConfig.dbType != null)}">
                    <c:forEach var="dbType" items="${requestScope.dbTypes}">
                        <c:choose>
                            <c:when test="${dbType eq requestScope.jdbcConfig.dbType}">
                                <option selected="selected"><c:out value="${dbType}"/></option>
                            </c:when>
                            <c:otherwise>
                                <option><c:out value="${dbType}"/></option>
                            </c:otherwise>
                        </c:choose>
                    </c:forEach>
                </c:when>
                <c:otherwise>
                    <c:forEach var="dbType" items="${requestScope.dbTypes}">
                        <option><c:out value="${dbTydbType}"/></option>
                    </c:forEach>
                </c:otherwise>
            </c:choose>
        </select>
    </div>

    <div class="alert alert-info" id="driver_install_warning">
        You will need to ensure that the JDBC drivers for your database have been correctly
        installed before the EPS will be able to talk to the database.
    </div>

    <div class="form-group">
        <label for="jdbcdriver">JDBC Driver</label>
        <c:choose>
            <c:when test="${(requestScope.jdbcConfig != null) && (requestScope.jdbcConfig.driver != null)}">
                <input type="text" class="form-control" name="jdbcdriver" id="jdbcdriver"
                       value="<c:out value='${requestScope.jdbcConfig.driver}' />"/>
            </c:when>
            <c:otherwise>
                <input type="text" class="form-control" name="jdbcdriver" id="jdbcdriver"/>
            </c:otherwise>
        </c:choose>
    </div>

    <div class="form-group">
        <label for="jdbcurl">JDBC URL</label>
        <c:choose>
            <c:when test="${(requestScope.jdbcConfig != null) && (requestScope.jdbcConfig.url != null)}">
                <input type="text" name="jdbcurl" id="jdbcurl" class="form-control"
                       value="<c:out value='${requestScope.jdbcConfig.url}' />"/>
            </c:when>
            <c:otherwise>
                <input type="text" name="jdbcurl" id="jdbcurl" class="form-control"/>
            </c:otherwise>
        </c:choose>
    </div>

    <div class="form-group">
        <label for="jdbcusername">Database Username</label>
        <c:choose>
            <c:when test="${(requestScope.jdbcConfig != null) && (requestScope.jdbcConfig.username != null)}">
                <input type="text" name="jdbcusername" id="jdbcusername" class="form-control"
                       value="<c:out value='${requestScope.jdbcConfig.username}' />"/>
            </c:when>
            <c:otherwise>
                <input type="text" name="jdbcusername" id="jdbcusername" class="form-control"/>
            </c:otherwise>
        </c:choose>
    </div>

    <div class="form-group">
        <label for="jdbcpassword">Database Password</label>
        <input type="password" name="jdbcpassword" id="jdbcpassword" class="form-control"/>
    </div>

    <div class="form-group">
        <label for="initialise">Initialise database <span class="form-help">(If you initialise the database the only login available will be 'admin' with the password 'admin'.)</span></label>
        <select name="initialise" id="initialise" class="form-control">
            <option selected="selected">No</option>
            <option>Yes</option>
        </select>
    </div>

    <button type="submit" class="btn btn-primary">Use Configuration</button>
</fieldset>
<script language="JavaScript" src="<c:url value='/js/jdbcoptions.js'/>"></script>
