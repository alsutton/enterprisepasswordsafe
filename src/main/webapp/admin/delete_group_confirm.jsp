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
<head><title>Confirm group deletion</title></head>
<body>
<div class="row">
    <div class="col-md-12">Please confirm you wish to delete the following groups;
    </div>
</div>

<div class="blankingrow">&nbsp;</div>

<c:if test="${not empty requestScope.groups}">
    <div class="row">
        <div class="col-md-12">
            <ul>
                <c:forEach var="thisGroup" items="${requestScope.groups}">
                    <li><c:out value="${thisGroup.groupName}"/></li>
                </c:forEach>
            </ul>
        </div>
    </div>
</c:if>

<form action="<c:url value='/admin/DeleteGroup'/>" name="confirm" method="POST"
      accept-charset="utf-8" role="form">
    <fieldset>
        <input type="hidden" name="group_id" value="<c:out value='${requestScope.groupIds}'/>"/>
        <button type="submit" class="btn btn-primary">Delete</button>
    </fieldset>
</form>
</body>
</html>
