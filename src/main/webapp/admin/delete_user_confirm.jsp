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
<head><title>Confirm users to delete</title></head>
<body>
<div class="row">
    <div class="col-md-12">Please confirm you wish to delete the following users;</div>
</div>

<div class="spacer">&nbsp;</div>

<div class="row">
    <div class="col-md-12">
        <ul>
            <c:forEach var="thisUser" items="${requestScope.users}">
                <li><c:out value="${thisUser.userName}"/> (<c:out value="${thisUser.fullName}"/>)</li>
            </c:forEach>
        </ul>
    </div>
</div>

<form action="<c:url value='/admin/DeleteUser' />" method="POST"
      accept-charset="UTF-8" name="confirm">
    <fieldset>
        <input type="hidden" name="userId" value="<c:out value='${requestScope.userIds}'/>"/>

        <button type="submit" class="btn btn-sm btn-primary" name="action" value="delete">Delete</button>
    </fieldset>
</form>
</body>
</html>
