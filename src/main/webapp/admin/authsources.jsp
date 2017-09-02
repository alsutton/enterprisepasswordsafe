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
<head><title>Authentication Sources</title></head>
<body>
<div class="row">
    <div class="col-md-12">
        <a href="<c:url value='/admin/AddAuthSourceStage1' />" class="btn btn-default btn-xs">Create New Source</a>
    </div>
</div>

<c:choose>
	<c:when test="${empty requestScope.auth_list}">
		<div class="row">
            <div class="col-md-12">
                <h6>No authentication sources have been defined</h6>
            </div>
        </div>
	</c:when>
	<c:otherwise>
        <ul class="list-unstyled">
            <c:forEach var="thisSource" items="${requestScope.auth_list}">
                <div class="spacer">&nbsp;</div>
                <div class="row">
                    <div class="col-md-12">
                        <c:url var="edit_link" value="/admin/EditAuthSource">
                            <c:param name="id" value="${thisSource.sourceId}"/>
                        </c:url>
                        <c:url var="delete_link" value="/admin/DeleteAuthSource">
                            <c:param name="id" value="${thisSource.sourceId}"/>
                        </c:url>
                        <li>
                            <a href="${delete_link}" name="delete_${thisSource.name}"><span class="glyphicon glyphicon-trash"></span></a>&nbsp;
                            <a href="${edit_link}" name="edit_${thisSource.name}"><span class="glyphicon glyphicon-pencil"></span></a>&nbsp;
                            <c:out value="${thisSource.name}" />
                        </li>
                    </div>
                </div>
            </c:forEach>
        </ul>
	</c:otherwise>
</c:choose>
</body>
</html>
