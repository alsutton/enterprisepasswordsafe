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
<head><title>EPS : Restricted access - Vote on request</title></head>
<body>
<div class="row">
    <div class="col-md-12">
        <h4>Vote on request ${requestScope.rarId}</h4>

        <c:choose>
            <c:when test="${empty requestScope.aco}"><p>The request relates to a password you do not have access rights to.</p></c:when>
            <c:otherwise><p>The request relates to the password <c:out value="${requestScope.aco}"/></p></c:otherwise>
        </c:choose>

        <p>The reason supplied by <c:out value="${requestScope.requester}" /> for the access request is;</p>
        <pre><c:out value="${requestScope.reason}"/></pre>
    </div>
</div>

<c:url var="approve_url" value="/system/SubmitRAVote">
    <c:param name="rar.id" value="${requestScope.rarId}" />
    <c:param name="rar_vote" value="A" />
</c:url>

<c:url var="deny_url" value="/system/SubmitRAVote">
    <c:param name="rar.id" value="${requestScope.rarId}" />
    <c:param name="rar_vote" value="B" />
</c:url>

<div class="row">
    <div class="col-md-12 text-center">
        <a href="${approve_url}" class="btn btn-primary">Approve Request</a>&nbsp;
        <a href="${deny_url}" class="btn btn-primary">Deny Request</a>
    </div>
</div>

<c:if test="${not empty requestScope.state}">
<div class="spacer">&nbsp;</div>
<div class="row">
    <div class="col-md-12">
        <p>Please note, you have already voted to&nbsp;
        <c:choose>
            <c:when test="${requestScope.state == 'A'}"><b>approve</b></c:when>
            <c:when test="${requestScope.state == 'B'}"><b>block</b></c:when>
        </c:choose>
        &nbsp;this request.</p>
    </div>
</div>
</c:if>
 
</body>
</html>