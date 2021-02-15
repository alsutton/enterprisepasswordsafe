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
<head><title>Select groups to delete</title></head>
<body>
<c:choose>
    <c:when test="${empty groups}">
        <div class="row">
            <div class="col-md-12">No groups have been defined</div>
        </div>
    </c:when>
    <c:otherwise>
        <div class="row">
            <div class="col-md-12">Please select the groups to delete;</div>
        </div>

        <form action="<c:url value='/admin/ConfirmDeleteGroup'/>" name="groupselection" method="POST"
              accept-charset="utf-8" class="form-horizontal" role="form">
            <fieldset>
                <c:forEach var="thisGroup" items="${groups}">
                    <div class="checkbox">
                        <label>
                            <input type="checkbox"
                                   name="group_id"
                                   id="<c:out value='${thisGroup.groupName}'/>"
                                   value="<c:out value='${thisGroup.groupId}'/>"/> <c:out
                                value="${thisGroup.groupName}"/>
                        </label>
                    </div>
                </c:forEach>

                <div class="spacer">&nbsp;</div>
                <button type="submit" class="btn btn-sm btn-primary">Delete</button>
            </fieldset>
        </form>
    </c:otherwise>
</c:choose>
</body>
</html>
