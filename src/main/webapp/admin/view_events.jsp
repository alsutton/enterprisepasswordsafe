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
<html lang="en">
<head>
<title>View Events</title>
</head>
<body>
<form action="<c:url value='/admin/ViewEvents' />" method="POST" accept-charset="ISO-8859-1"
      class="form-horizontal" role="form" name="EventReportOptions">
    <fieldset>
        <div class="form-group">
            <label for="startdate" class="control-label col-md-2">Start Date :</label>
            <div class="col-md-10">
                <input type="date" name="startdate" id="startdate" class="form-control" value="${requestScope.startdate}"/>
            </div>
        </div>
        <div class="form-group">
            <label for="enddate" class="control-label col-md-2">End Date :</label>
            <div class="col-md-10">
                <input type="date" name="enddate" id="enddate" class="form-control" value="${requestScope.enddate}"/>
            </div>
        </div>

        <c:if test="${not empty requestScope.users}">
            <div class="form-group">
                <label for="ulimit" class="control-label col-md-2">User :</label>
                <div class="col-md-10">
                    <select name="ulimit" id="ulimit" class="form-control">
                        <option value="-1" selected="selected">- All Users -</option>
                        <c:forEach var="thisUser" items="${requestScope.users}">
                            <option value="${thisUser.id}">
                                <c:out value="${thisUser.name}" />
                                <c:if test="${not empty thisUser.fullName}">
                                    &nbsp;(<c:out value="${thisUser.fullName}"/>)
                                </c:if>
                            </option>
                        </c:forEach>
                    </select>
                </div>
            </div>
        </c:if>

        <c:if test="${not empty requestScope.plist}">
            <div class="form-group">
                <label for="id" class="control-label col-md-2">Password :</label>
                <div class="col-md-10">
                    <select name="id" id="id" class="form-control">
                        <option value="-1" selected="selected">All Passwords</option>
                        <c:forEach var="thisPassword" items="${requestScope.plist}">
                            <option value="${thisPassword.id}'/>">
                                <c:out value="${thisPassword.representation}" />
                            </option>
                        </c:forEach>
                    </select>
                </div>
            </div>
        </c:if>

        <div class="form-group">
            <label for="export" class="control-label col-md-2">Output to :</label>
            <div class="col-md-10">
                <select name="export" id="export" class="form-control">
                    <option value="N">Browser</option>
                    <option value="Y">CSV File</option>
                </select>
            </div>
        </div>

        <button type="submit" class="btn btn-primary text-align-right col-md-offset-2">View Events</button>
    </fieldset>
</form>

<jsp:include page="/WEB-INF/includes/display_events.jsp" />

<script src="<c:url value='/js/bootstrap-datepicker.js' />"></script>
<script src="<c:url value='/js/eventlogdatepicker.js'/>"></script>
</body>
</html>
