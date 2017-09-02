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

<div class="row">
    <ul class="breadcrumb">
    <c:forEach var="thisNode" items="${requestScope.node_parents}">
        <li>
            <c:url var="nodeLink" value="${param.explorerUrl}">
                <c:param name="nodeId" value="${thisNode.nodeId}"/>
            </c:url>
            <a href="${nodeLink}" name="npath_<c:out value='${thisNode.name}'/>"><c:out value="${thisNode.name}"/></a>
        </li>
    </c:forEach>

    <li class="active"><c:out value='${requestScope.node.name}'/></li>
    </ul>
</div>
