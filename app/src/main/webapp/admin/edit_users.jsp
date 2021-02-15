<%@ page %>
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
<head><title>Users</title></head>
<body>

<div class="row">
    <div class="col-md-12">
        <a href="<c:url value='/admin/User'/>" class="btn btn-sm btn-default">Add User</a>
        <a href="<c:url value='/admin/ImportUserFile'/>" class="btn btn-sm btn-default">Import Users</a>
    </div>
</div>
<div class="spacer">&nbsp;</div>

<c:choose>
    <c:when test="${empty requestScope.users}">
        <div class="row">
            <div class="col-md-12">No users have been defined</div>
        </div>
    </c:when>
    <c:otherwise>
        <c:forEach var="thisUser" items="${requestScope.users}">
            <div class="row">
                <div class="col-md-12">
                    <c:url var="edit_link" value="/admin/User">
                        <c:param name="userId" value="${thisUser.id}"/>
                    </c:url>
                    <c:url var="delete_link" value="/admin/DeleteUser">
                        <c:param name="id" value="${thisUser.id}"/>
                    </c:url>
                    <a href="${delete_link}" name="delete_<c:out value='${thisUser.userName}'/>">
                        <span class="glyphicon glyphicon-trash"></span>
                    </a>
                    <a href="${edit_link}" name="edit_<c:out value='${thisUser.userName}'/>">
                        <span class="glyphicon glyphicon-pencil"></span>
                    </a>
                    <c:out value="${thisUser.userName}"/>
                    <c:if test="${not empty thisUser.fullName}">
                        &nbsp;(<c:out value="${thisUser.fullName}"/>)
                    </c:if>
                </div>
            </div>
        </c:forEach>
    </c:otherwise>
</c:choose>

</body>
</html>
