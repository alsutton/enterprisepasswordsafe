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
    <title>Available Integration Scripts</title>
</head>
<body>
<div class="row">
    <div class="col-md-12">
        <a href="<c:url value='/admin/IntegrationModules' />"><span
                class="glyphicon glyphicon-chevron-left">&nbsp;</span> Back to module list</a>
    </div>
</div>
<div class="row">
    <div class="col-md-12">
        <c:url var="createLink" value="/admin/CreateIMScript">
            <c:param name="id" value="${requestScope.moduleId}"/>
        </c:url>
        <a href="${createLink}" class="btn btn-xs btn-default">Create new script</a>
    </div>
</div>

<c:choose>
    <c:when test="${empty requestScope.scripts}">
        <div class="row">
            <div class="col-md-12">No scripts have been installed</div>
        </div>
    </c:when>
    <c:otherwise>
        <c:forEach var="thisScript" items="${requestScope.scripts}">
            <div class="row">
                <div class="col-md-12">
                    <c:url var="editLink" value="/admin/EditIMScript">
                        <c:param name="scriptid" value="${thisScript.id}"/>
                    </c:url>
                    <c:url var="deleteLink" value="/admin/DeleteIMScript">
                        <c:param name="scriptid" value="${thisScript.id}"/>
                    </c:url>
                    <a href="${deleteLink}"><span class="glyphicon glyphicon-trash">&nbsp;</span></a>&nbsp;
                    <a href="${editLink}"><span class="glyphicon glyphicon-pencil">&nbsp;</span></a>&nbsp;
                    <c:out value="${thisScript.name}"/>
                </div>
            </div>
        </c:forEach>
    </c:otherwise>
</c:choose>
</body>
</html>
