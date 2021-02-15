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
<head><title>Groups</title></head>
<body>

<div class="row">
    <div class="col-md-12">
        <a href="<c:url value='/admin/CreateGroup'/>" class="btn btn-sm btn-default">Create Group</a>
        <a href="<c:url value='/admin/ImportGroupFile'/>" class="btn btn-sm btn-default">Import Groups</a>
    </div>
</div>
<div class="spacer">&nbsp;</div>

<c:choose>
    <c:when test="${empty requestScope.groups}">
        <div class="row">
            <div class="col-md-12">No groups have been defined yet.</div>
        </div>
    </c:when>
    <c:otherwise>
        <div class="spacer">&nbsp;</div>
        <c:forEach var="thisGroup" items="${requestScope.groups}">
            <c:url var="delete_url" value="/admin/DeleteGroup">
                <c:param name="id" value="${thisGroup.groupId}"/>
            </c:url>
            <c:url var="edit_url" value="/admin/EditGroup">
                <c:param name="id" value="${thisGroup.groupId}"/>
            </c:url>
            <div class="row">
                <div class="col-md-12 enabled_${thisGroup.enabled}">
                    <a href="${delete_url}" name="del_${thisGroup.groupName}"><span class="glyphicon glyphicon-trash"></span></a>
                    <a href="${edit_url}" name="edit_${thisGroup.groupName}"><span class="glyphicon glyphicon-pencil"></span></a>
                    <c:out value="${thisGroup.groupName}"/>
                </div>
            </div>
        </c:forEach>
    </c:otherwise>
</c:choose>


</body>
</html>
