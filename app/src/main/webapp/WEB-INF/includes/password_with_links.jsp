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
<c:url var="view_link" value="/system/ViewPassword">
    <c:param name="id" value="${param.id}" />
    <c:param name="otid" value="${requestScope.nextOtid}" />
</c:url>
<a href="${view_link}">
    <c:choose>
        <c:when test="${empty param.username}">[Empty Username]</c:when>
        <c:otherwise><c:out value="${param.username}"/></c:otherwise>
    </c:choose>
</a>
&nbsp;@&nbsp;
<c:url var="location_search_link" value="/system/SearchLocation">
    <c:param name="location" value="${param.location}" />
</c:url>
<a href="${location_search_link}">
    <c:choose>
        <c:when test="${empty param.location}">[Empty System Name]</c:when>
        <c:otherwise><c:out value="${param.location}"/></c:otherwise>
    </c:choose>
</a>
