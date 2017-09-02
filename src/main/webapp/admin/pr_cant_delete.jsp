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
    <title>Restriction Removal Blocked</title>
</head>
<body>
<div class="row">
    <div class="col-md-12">
        <a href="<c:url value='/admin/PasswordRestrictions' />"><span
                class="glyphicon glyphicon-chevron-left">&nbsp;</span> Back to restriction list</a>
    </div>
</div>
<div class="row">
    <div class="col-md-12">
        <p>The restriction can not be deleted because it is in use of the following passwords.</p>
        <ul>
            <c:forEach var="thisPassword" items="${requestScope.block_list}">
                <c:url var="editUrl" value="/system/ViewPassword">
                    <c:param name="id" value="${thisPassword.id}"/>
                    <c:param name="otid" value="${requestScope.nextOtid}"/>
                </c:url>
                <li><a href="${editUrl}"><c:out value="thisPassword"/></a></li>
            </c:forEach>
        </ul>
    </div>
</div>
</body>
</html>
