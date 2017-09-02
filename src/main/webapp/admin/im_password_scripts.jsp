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
<head><title>Integration Scripts for Password</title></head>
<body>
<c:choose>
    <c:when test="${empty requestScope.scripts}">
        <div class="row">
            <div class="col-md-12">
                There are no scripts associated with this password.
            </div>
        </div>
    </c:when>
    <c:otherwise>
        <form action="<c:url value='/admin/UpdatePasswordScripts' />" method="POST"
              accept-charset="ISO-8859-1" role="form">
            <fieldset>
                <input type="hidden" name="id" value="<c:out value='${requestScope.id}'/>"/>

                <div class="row">
                    <div class="col-md-12">Please select the scripts to use with this password;</div>
                </div>

                <c:forEach var="thisScript" items="${requestScope.scripts}">
                    <c:if test="${thisScript.active}">
                        <c:set var="script_checked" value="checked=\"checked\""/>
                    </c:if>
                    <div class="checkbox">
                        <label>
                            <input type="checkbox" name="scripts"
                                   value="<c:out value='${thisScript.scriptId}' />" ${script_checked} />
                            <c:out value="${thisScript.name}"/> (<c:out value="${thisScript.moduleName}"/>)
                        </label>
                    </div>
                </c:forEach>

                <button type="submit" class="btn btn-primary">Update settings</button>
            </fieldset>
        </form>
    </c:otherwise>
</c:choose>
</body>
</html>
