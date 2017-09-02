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
<head><title>Results of import</title></head>
<body>
<c:choose>
    <c:when test="${requestScope.count == 0}">
        <div class="row">
            <div class="col-md-12"><i>Nothing was imported from the file</i></div>
        </div>
    </c:when>
    <c:otherwise>
        <div class="row">
            <div class="col-md-12">
                <span id="import_count">${requestScope.count}</span> items were imported into&nbsp;
                <c:forEach var="thisNode" items="${requestScope.node_parents}">
                    <c:out value="${requestScope.thisNode.name}" />&nbsp;\&nbsp;
                </c:forEach>
                <c:out value="${requestScope.node.name}"/>
            </div>
        </div>
    </c:otherwise>
</c:choose>


<c:if test="${not empty requestScope.error_list}">
	<div class="row">
        <div class="col-md-12"><h4>Errors</h4></div>
    </div>
	<div class="spacer">&nbsp;</div>
	<c:forEach var="thisError" items="${requestScope.error_list}">
        <div class="row">
            <div class="col-md-12">Error : <c:out value="${thisError}" /></div>
        </div>
	</c:forEach>
</c:if>
</body>
</html>