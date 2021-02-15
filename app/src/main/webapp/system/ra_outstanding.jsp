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
<head><title>Outstanding restricted access requests</title></head>
<body>
<div class="row">
    <div class="col-md-12">
        <h4>Outstanding Access Requests</h4>
    </div>
</div>
<c:choose>
<c:when test="${empty requestScope.requests_for_approval}">
    <div class="row">
        <div class="col-md-12">There are no restricted access requests for you to approve or deny</div>
    </div>
</c:when>
<c:otherwise>
    <div class="row">
        <div class="col-md-12">
            <ul>
                <c:forEach var="thisRequest" items="${requestScope.requests_for_approval}">
                    <c:url var="vote_url" value="/system/AnalyseRARequest">
                        <c:param name="rarId" value="${thisRequest.id}"/>
                    </c:url>
                    <li>Request ID : ${thisRequest.id}&nbsp;
                        <a href="${vote_url}" name="rar_${thisRequest.objectId}">[Vote on request]</a>&nbsp;
                        <c:choose>
                            <c:when test="${thisRequest.state == 'A'}">(Current Vote : <b>Approve request</b>)</c:when>
                            <c:otherwise>(Current Vote : <b>Block request</b>)</c:otherwise>
                        </c:choose>
                    </li>
                </c:forEach>
            </ul>
        </div>
    </div>
</c:otherwise>
</c:choose>
</body></html>