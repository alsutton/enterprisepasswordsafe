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
<head><title>Edit Password Hierarchy</title></head>
<body>

<div class="modal fade" id="addNode" tabindex="-1" role="dialog" aria-labelledby="addNode" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                <h4 class="modal-title">Add Folder</h4>
            </div>
            <form accept-charset="ISO-8859-1" action="<c:url value='/subadmin/CreateNode' />" name="addfolder" role="form" method="POST" class="form-horizontal">
                <div class="modal-body">
                    <label for="name">Folder name :</label>
                    <input type="text" name="name" id="name" class="form-control" />
                </div>
                <div class="modal-footer">
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
    </div>
</div>


<jsp:include page="/WEB-INF/includes/hierarchy_breadcrumbs.jsp">
    <jsp:param name="explorerUrl" value="/subadmin/EditHierarchy" />
</jsp:include>

<div class="row">
    <ul class="nav nav-tabs">
        <li><a href="<c:url value='/system/Explorer'/>">View Hierarchy</a></li>
        <li class="active"><a href="<c:url value='/subadmin/EditHierarchy'/>" name="edithierarchy">Edit hierarchy</a></li>
        <li><a href="<c:url value='/subadmin/NodeUserPermissions'/>" name="eh_uperms">User Permissions</a></li>
        <li><a href="<c:url value='/subadmin/NodeGroupPermissions'/>" name="eh_gperms">Group Permissions</a></li>
        <li><a href="<c:url value='/subadmin/NodePasswordDefaults'/>" name="eh_dpa">Default Password Access</a></li>
    </ul>
</div>
<div class="row">&nbsp;</div>

<form action="<c:url value='/subadmin/EditHierarchy'/>"  method="POST" accept-charset="ISO-8859-1" name="editaction">
<input type="hidden" name="nodeId" value="${requestScope.node.nodeId}" />
<div class="row">
    <div class="col-md-12">
        <div class="btn-group btn-group-sm">
            <button type="button" class="btn btn-default">Copy</button>
            <button type="button" class="btn btn-default">Cut</button>
            <button type="button" class="btn btn-default">Paste</button>
            <button type="button" class="btn btn-default">Delete</button>
        </div>
    </div>
</div>


<div class="row">
    <div class="col-md-4">
        <h3>Folders</h3>

        <p><a data-toggle="modal" href="#addNode" class="btn btn-default btn-xs">Add Folder</a></p>

        <c:choose>
            <c:when test="${empty requestScope.node_children.nodes}">None</c:when>
            <c:otherwise>
                <c:forEach var="thisNode" items="${requestScope.node_children.nodes}">
                    <label>
                        <input type="checkbox" name="node_list" value="${thisNode.nodeId}'/>"/>
                        <c:url var="explorer_url" value="/subadmin/EditHierarchy">
                            <c:param name="nodeId" value="${thisNode.nodeId}" />
                        </c:url>
                        <a href="${explorer_url}"><c:out value="${thisNode.name}" /></a>
                    </label><br/>
                </c:forEach>
            </c:otherwise>
        </c:choose>
    </div>

    <div class="col-md-8">
        <h3>Passwords</h3>
        <p><a href="<c:url value='/system/CreatePassword'/>" class="btn btn-default btn-xs">Add Password</a></p>
        <c:choose>
            <c:when test="${empty requestScope.node_children.objects}">None</c:when>
            <c:otherwise>
                <c:forEach var="thisPassword" items="${requestScope.node_children.objects}">
                            <label>
                                <input type="checkbox" name="node_list" id="node_list" value="p_${thisPassword.id}"/>
                                <jsp:include page="/WEB-INF/includes/password_with_links.jsp">
                                    <jsp:param name="id" value="${thisPassword.id}" />
                                    <jsp:param name="username" value="${thisPassword.username}" />
                                    <jsp:param name="location" value="${thisPassword.location}" />
                                </jsp:include>
                            </label><br />
                        </c:forEach>
            </c:otherwise>
        </c:choose>
    </div>
</div>
</form>

</body>
</html>
