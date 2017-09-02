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
<head><title>Select users to delete</title></head>
<body>

<c:choose>
<c:when test="${empty requestScope.users}">
    <div class="row">
        <div class="col-md-12">No users have been defined</div>
    </div>
</c:when>
<c:otherwise>
<form action="<c:url value='/admin/ConfirmDeleteUser' />" name="userselection" method="POST"
      accept-charset="ISO-8859-1" role="form">
    <fieldset>
        <div class="row">
            <div class="col-md-12">Please select the users you wish to delete</div>
        </div>
        <c:forEach var="thisUser" items="${requestScope.users}">
            <div class="checkbox">
                <label>
                    <input type="checkbox" name="userId" value="<c:out value='${thisUser.userId}' />">
                    <c:out value="${thisUser.userName}"/>
                </label>
            </div>
        </c:forEach>

        <div class="spacer">&nbsp;</div>
        <button type="submit" class="btn btn-sm btn-primary">Delete</button>
    </fieldset>
</form>
</c:otherwise>
</c:choose>
</html>
