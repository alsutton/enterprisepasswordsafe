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
	<title>Available Upgrades</title>
</head>
<body>
<div class="row">
    <div class="col-md-12">
        <c:choose>
            <c:when test="${empty requestScope.upgrade_list}">
                <p>No upgrades are available at this time.</p>
            </c:when>
            <c:otherwise>
                <p>The follow upgrades can be made to your system;</p>

                <ul>
                <c:forEach var="thisEntry" items="${requestScope.upgrade_list}">
                    <li><c:out value="${thisEntry}"/></li>
                </c:forEach>
                </ul>

                <p>You can apply these now by clicking the button below, or youcan select another option from the left</p>

                <p><a href="<c:url value='/admin/ApplyUpgrades'/>" class="btn btn-primary">Apply upgrades</a></p>
            </c:otherwise>
        </c:choose>
    </div>
</div>
</body>
</html>
