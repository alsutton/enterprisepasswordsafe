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
<head><title>Personal Passwords</title></head>
<body>
<div class="row">
    <div class="col-md-12 ${expiredClass}">
        <a href="<c:url value='/system/CreatePassword' />" name="createpassword">Create New Password</a>
    </div>
</div>

<c:choose>
	<c:when test="${empty requestScope.objects}">
        <div class="row">
            <div class="col-md-12">
                <i>You have not created any personal passwords</i>
            </div>
        </div>
    </c:when>
	<c:otherwise>
		<c:forEach var="thisPassword" items="${requestScope.objects}">
            <c:choose>
                <c:when test="${thisPassword.expired}">
                    <c:set var="expiredClass" value="expired" />
                </c:when>
                <c:otherwise>
                    <c:set var="expiredClass" value="" />
                </c:otherwise>
            </c:choose>
            <div class="row">
                <div class="col-md-12 ${expiredClass}">
                    <c:url var="edit_link" value="/system/ViewPassword">
                        <c:param name="id" value="${thisPassword.id}" />
                        <c:param name="otid" value="${requestScope.nextOtid}" />
                    </c:url>
                    <c:url var="delete_link" value="/system/DeletePassword">
                        <c:param name="id" value="${thisPassword.id}" />
                    </c:url>
                    <a href="${delete_link}" name="delete_${thisPassword.username}@${thisPassword.location}"><span class="glyphicon glyphicon-trash"></span></a>&nbsp;
                    <a href="${edit_link}" name="edit_${thisPassword.username}@${thisPassword.location}"><span class="glyphicon glyphicon-pencil"></span></a>&nbsp;
                    <c:choose>
                        <c:when test="${empty thisPassword.username}">[Empty Username]</c:when>
                        <c:otherwise><c:out value="${thisPassword.username}"/></c:otherwise>
                    </c:choose>
                    @
                    <c:choose>
                        <c:when test="${empty thisPassword.location}">[Empty System Name]</c:when>
                        <c:otherwise><c:out value="${thisPassword.location}"/></c:otherwise>
                    </c:choose>
                    <c:if test="${not thisPassword.enabled}">&nbsp;<i>(Disabled)</i></c:if>
                </div>
            </div>
		</c:forEach>
	</c:otherwise>
</c:choose>
</body>
</html>