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
<head><title>Password Hierarchy</title></head>
<body>
<jsp:include page="/WEB-INF/includes/hierarchy_breadcrumbs.jsp">
    <jsp:param name="explorerUrl" value="/system/Explorer" />
</jsp:include>

<c:if test="${requestScope.edithierarchy_allowed == 'Y'}">
    <div class="row">
        <div class="col-md-12">
            <ul class="nav nav-tabs">
                <li class="active"><a href="#">View Hierarchy</a></li>
                <li><a href="<c:url value='/subadmin/EditHierarchy'/>" name="edithierarchy">Edit hierarchy</a></li>
                <li><a href="<c:url value='/subadmin/NodeUserPermissions'/>" name="eh_uperms">User Permissions</a></li>
                <li><a href="<c:url value='/subadmin/NodeGroupPermissions'/>" name="eh_gperms">Group Permissions</a></li>
                <li><a href="<c:url value='/subadmin/NodePasswordDefaults'/>" name="eh_dpa">Default Password Access</a></li>
            </ul>
        </div>
    </div>
    <div class="row">&nbsp;</div>
</c:if>

<div class="row">
 <div class="col-md-12">
	<form action="<c:url value='/system/Search'/>" class="form-inline" role="form" method="POST"
          accept-charset="ISO-8859-1" name="search_form">
    <div class="form-group">
        <label class="sr-only" for="username">Username :</label>
        <input type="text" class="form-control" id="username" name="username" placeholder="Username">
    </div>
    <div class="form-group">
        <label class="sr-only" for="system">System :</label>
        <input type="text" class="form-control" id="system" name="system" placeholder="System name">
    </div>
    <button class="btn btn-default" type="submit">Search</button>
	</form>
 </div>
</div>
<div class="row">
	<div class="col-md-4">
		<h3>Sub-Folders</h3>

		<c:choose>
			<c:when test="${empty requestScope.node_children.nodes}"><i>None</i></c:when>
			<c:otherwise>
				<ul class="hierarchysubnodes">
				<c:forEach var="thisNode" items="${requestScope.node_children.nodes}">
                    <c:url var="explorer_link" value="/system/Explorer">
                        <c:param name="nodeId" value="${thisNode.nodeId}" />
                    </c:url>
                    <li><a href="${explorer_link}"><c:out value="${thisNode.name}" /></a></li>
		        </c:forEach>
				</ul>
			</c:otherwise>
		</c:choose>
	</div>
	<div class="col-md-8">
		<h3>Passwords</h3>
		<c:choose>
			<c:when test="${empty requestScope.node_children.objects}"><i>None</i></c:when>
			<c:otherwise>
                <ul class="hierarchyobjects">
                    <c:forEach var="thisPassword" items="${requestScope.node_children.objects}">
                        <li class="expired_${thisPassword.expired} enabled_${thisPassword.enabled}">
                            <jsp:include page="/WEB-INF/includes/password_with_links.jsp">
                                <jsp:param name="id" value="${thisPassword.id}" />
                                <jsp:param name="username" value="${thisPassword.username}" />
                                <jsp:param name="location" value="${thisPassword.location}" />
                            </jsp:include>
                        </li>
                    </c:forEach>
                </ul>
			</c:otherwise>
		</c:choose>
	</div>
</div>
</body>
</html>
