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
<head><title>Password Restrictions</title></head>
<body>
<div class="row">
    <div class="col-md-12">
        <a href="<c:url value='/admin/PasswordRestrictionsAddStage1'/>" name="add">Add a new permission</a>
    </div>
</div>

<c:choose>
    <c:when test="${empty requestScope.restriction_list}">
        <div class="row">
            <div class="col-md-12">
                No restrictions have been created
            </div>
        </div>
    </c:when>
    <c:otherwise>
        <c:forEach var="thisRestriction" items="${requestScope.restriction_list}">
            <c:url var="editLink" value="/admin/PasswordRestrictionsEditStage1">
                <c:param name="id" value="${thisRestriction.id}"/>
            </c:url>
            <c:url var="deleteLink" value="/admin/PasswordRestrictionsDelete">
                <c:param name="id" value="${thisRestriction.id}"/>
            </c:url>
            <div class="row">
                <div class="col-md-12">
                    <a href="${editLink}" name="edit_<c:out value='${thisRestriction.name}'/>">
                        <span class="glyphicon glyphicon-pencil"></span>
                    </a>&nbsp;
                    <a href="${deleteLink}" name="delete_<c:out value='${thisRestriction.name}'/>">
                        <span class="glyphicon glyphicon-trash"></span>
                    </a>&nbsp;
                    <c:out value="${thisRestriction.name}"/>
                </div>
            </div>
        </c:forEach>
    </c:otherwise>
</c:choose>
</body>
</html>
