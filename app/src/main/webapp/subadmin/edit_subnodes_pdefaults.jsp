<%@ page %>
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
<title>Edit Password Hierarchy</title>
</head>
<body>
<jsp:include page="/WEB-INF/includes/hierarchy_breadcrumbs.jsp">
    <jsp:param name="explorerUrl" value="/subadmin/NodePasswordDefaults" />
</jsp:include>

<div class="row">
    <ul class="nav nav-tabs">
        <li><a href="<c:url value='/system/Explorer'/>">View Hierarchy</a></li>
        <li><a href="<c:url value='/subadmin/EditHierarchy'/>" name="edithierarchy">Edit hierarchy</a></li>
        <li><a href="<c:url value='/subadmin/NodeUserPermissions'/>" name="eh_uperms">User Permissions</a></li>
        <li><a href="<c:url value='/subadmin/NodeGroupPermissions'/>" name="eh_gperms">Group Permissions</a></li>
        <li class="active"><a href="<c:url value='/subadmin/NodePasswordDefaults'/>" name="eh_dpa">Default Password Access</a></li>
    </ul>
</div>
<div class="row">&nbsp;</div>

<form action="<c:url value='/subadmin/UpdateNodePasswordDefaults'/>"
      method="POST" accept-charset="ISO-8859-1" name="defaultsset"
      class="form-horizontal" role="form">
    <div class="row">
        <div class="col-md-6"><h4>Default Permissions</h4></div>
        <c:if test="${requestScope.node.nodeId ne '0'}">
            <div class="col-md-6 text-right"><b>(Interited Parent Permission)</b></div>
        </c:if>
    </div>

    <div class="row">
        <div class="col-md-4 text-right">All Users :</div>
        <div class="col-md-4">
            <jsp:include page="/WEB-INF/includes/modify_read_default_selector.jsp">
                <jsp:param name="input_name" value="gperm_2" />
                <jsp:param name="input_value" value="${requestScope.egac}" />
                <jsp:param name="default_text" value="None specified" />
            </jsp:include>
        </div>
        <c:if test="${requestScope.node.nodeId ne '0'}">
            <div class="col-md-4">
                <c:choose>
                    <c:when test="${requestScope.paregac eq 'READ'}">Read</c:when>
                    <c:when test="${requestScope.paregac eq 'MODIFY'}">Modify</c:when>
                    <c:otherwise>From Parent</c:otherwise>
                </c:choose>
            </div>
        </c:if>
    </div>

	<input type="hidden" name="nodeId" value="${requestScope.node.nodeId}" />

    <hr />
    <div class="row"><div class="col-md-12"><h4>Group Permissions</h4></div></div>

    <c:forEach var="group" items="${requestScope.groups}">
        <c:if test="${group.groupId != 2}">
            <div class="row">
                <div class="col-md-4 text-right"><c:out value="${group.groupName}" /> :</div>
                <div class="col-md-4">
                    <jsp:include page="/WEB-INF/includes/modify_read_default_selector.jsp">
                        <jsp:param name="input_name" value="gperm_${group.groupId}" />
                        <jsp:param name="input_value" value="${requestScope.groupPermissions[group.groupId]}" />
                    </jsp:include>
                </div>
                <c:if test="${requestScope.node.nodeId ne '0'}">
                    <div class="col-md-4">
                        <c:choose>
                            <c:when test="${requestScope.groupPermissionsForParent[group.groupId] eq 'READ'}">Read</c:when>
                            <c:when test="${requestScope.groupPermissionsForParent[group.groupId] eq 'MODIFY'}">Modify</c:when>
                            <c:otherwise>From Parent</c:otherwise>
                        </c:choose>
                    </div>
                </c:if>
            </div>
        </c:if>
    </c:forEach>

    <hr />
    <div class="row"><div class="col-md-12"><h4>User Permissions</h4></div></div>

    <c:forEach var="user" items="${requestScope.users}">
        <div class="row">
            <div class="col-md-4 text-right"><c:out value="${user.userName}" /> :</div>
            <div class="col-md-4">
                <jsp:include page="/WEB-INF/includes/modify_read_default_selector.jsp">
                    <jsp:param name="input_name" value="uperm_${user.id}" />
                    <jsp:param name="input_value" value="${requestScope.userPermissions[user.id]}" />
                </jsp:include>
            </div>
            <c:if test="${requestScope.node.nodeId ne '0'}">
                <div class="col-md-4">
                    <c:choose>
                        <c:when test="${requestScope.userPermissionsForParent[user.id] eq 'READ'}">Read</c:when>
                        <c:when test="${requestScope.userPermissionsForParent[user.id] eq 'MODIFY'}">Modify</c:when>
                        <c:otherwise>From Parent</c:otherwise>
                    </c:choose>
                </div>
            </c:if>
        </div>
    </c:forEach>

    <hr />
	<c:if test="${not empty sessionScope.user_is_admin}">
        <div class="row">
            <div class="col-md-10 col-md-offset-2">
                <label for="cascade">
                    <input type="checkbox" id="cascade" name="cascade"/>
                Apply these settings to all passwords and folders in and below this folder</label>
            </div>
        </div>
        <div class="spacer">&nbsp;</div>
	</c:if>

	<div class="row">
        <div class="col-md-8 col-md-offset-4">
            <button type="submit" class="btn btn-primary">Update Defaults</button>
        </div>
    </div>
</form>
</body>
</html>