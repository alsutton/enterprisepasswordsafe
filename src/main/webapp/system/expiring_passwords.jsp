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
<head><title>Expiring Passwords</title></head>
<body>
<c:choose>
	<c:when test="${empty requestScope.passwords_expired}"><p><i>No passwords have expired.</i></p></c:when>
	<c:otherwise>
        <div class="row">
            <div class="col-md-12"><c:out value="${requestScope.passwords_expired_count}"/> Password(s) have expired.</div>
        </div>
        <div class="spacer">&nbsp;</div>
        <div class="row">
            <div class="col-md-12">
                <ul>
                    <c:forEach var="thisPassword" items="${requestScope.passwords_expired}">
                        <c:url var="viewLink" value="/system/ViewPassword">
                            <c:param name="id" value="${thisPassword.id}" />
                            <c:param name="otid" value="${requestScope.nextOtid}" />
                        </c:url>
                        <li><a href="${viewLink}"><c:out value="${thisPassword}" /></a></li>
                    </c:forEach>
                </ul>
            </div>
        </div>
		<hr/>
		
		<c:choose>
			<c:when test="${empty requestScope.passwords_expiring}"><p><i>No passwords will expire in the near future.</i></p></c:when>
			<c:otherwise>
                <div class="row">
                    <div class="col-md-12"><c:out value="${requestScope.passwords_expiring_count}"/> Password(s) will expire in the near future.</div>
                </div>
                <div class="spacer">&nbsp;</div>
                <div class="row">
                    <div class="col-md-12">
                        <ul>
                            <c:forEach var="thisPassword" items="${requestScope.passwords_expiring}">
                                <div class="expiringPassword">
                                <c:url var="viewLink" value="/system/ViewPassword">
                                    <c:param name="id" value="${thisPassword.id}" />
                                    <c:param name="otid" value="${requestScope.nextOtid}" />
                                </c:url>
                                <li><a href="${viewLink}"><c:out value="${thisPassword}" /></a></li>
                                </div>
                            </c:forEach>
                        </ul>
                    </div>
                </div>
			</c:otherwise>
		</c:choose>	
	</c:otherwise>
</c:choose>
</body>
</html>