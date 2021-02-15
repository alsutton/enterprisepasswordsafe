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
<jsp:include page="/WEB-INF/includes/hierarchy_breadcrumbs.jsp">
    <jsp:param name="explorerUrl" value="/subadmin/NodeGroupPermissions" />
</jsp:include>

<div class="row">
    <ul class="nav nav-tabs">
        <li><a href="<c:url value='/system/Explorer'/>">View Hierarchy</a></li>
        <li><a href="<c:url value='/subadmin/EditHierarchy'/>" name="edithierarchy">Edit hierarchy</a></li>
        <li><a href="<c:url value='/subadmin/NodeUserPermissions'/>" name="eh_uperms">User Permissions</a></li>
        <li class="active"><a href="<c:url value='/subadmin/NodeGroupPermissions'/>" name="eh_gperms">Group Permissions</a></li>
        <li><a href="<c:url value='/subadmin/NodePasswordDefaults'/>" name="eh_dpa">Default Password Access</a></li>
    </ul>
</div>
<div class="row">&nbsp;</div>

<c:choose>
    <c:when test="${requestScope.node.nodeId eq '0'}">
		<div class="row">
            <div class="col-md-12">You can not set the permissions for the top level. All groups must be able to access it
		in order to log in.
            </div>
        </div>
	</c:when>
	<c:otherwise>
        <div class="row">
            <div class="col-md-12">
                <h4>Please Note:</h4>
                <ol>
                    <li>These permissions are only for the current folder and not the passwords it contains.</li>
                    <li>If this folder does not contain any passwords with access rules allowing the user to either
                        view or modify the password then this folder will not be displayed to the user.</li>
                    <li>Group permissions will be overridden by any user permissions.</li>
                    <li>If a user has <i>Default</i> access to this folder, and <b>any</b> of the groups the user
                        belongs to have been denied access to this folder the user <b>will</b> be denied access.</li>
                </ol>
            </div>
        </div>

        <div class="spacer">&nbsp;</div>

        <c:if test="${not empty requestScope.perms}">
            <form action="<c:url value='/subadmin/UpdateGroupHierarchyPermissions'/>"  method="POST" accept-charset="ISO-8859-1" name="permset">
            <input	type="hidden" name="nodeId" value="${requestScope.node.nodeId}" />
                <div class="row">
                    <div class="col-md-12">
                        <table class="table">
                            <thead><tr><td>Group</td><td>Permissions</td></tr></thead>

                            <tbody class="table-striped">
                                <c:forEach var="thisPermission" items="${requestScope.perms}">
                                    <tr>
                                        <td>
                                            <c:out value="${thisPermission.actorName}"/>
                                        </td>
                                        <td>
                                            <jsp:include page="/WEB-INF/includes/allow_deny_default_selector.jsp">
                                                <jsp:param name="input_name" value="${thisPermission.actorId}_perms" />
                                                <jsp:param name="input_value" value="${thisPermission.rule}" />
                                            </jsp:include>
                                            <input type="hidden" name="${thisPermission.actorId}_orig" value="${thisPermission.rule}" />
                                        </td>
                                    </tr>
                                </c:forEach>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-offset-4 col-md-8">
                        <button type="submit" class="btn btn-primary">Update Permissions</button>
                    </div>
                </div>
            </form>
        </c:if>
	</c:otherwise>
</c:choose>
</body>
</html>
