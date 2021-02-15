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
<head><title>Edit Group</title></head>
<body>
<form action="<c:url value='/admin/UpdateGroupDetails'/>" name="groupdetails"
      method="POST" accept-charset="utf-8" role="form">
    <fieldset>
        <input type="hidden" name="group_id" value="<c:out value='${requestScope.group.groupId}' />"/>

        <div class="row">
            <div class="col-md-12"><h4>Group Information</h4></div>
        </div>

        <div class="form-group">
            <label for="name">Group Name</label>
            <input type="text" size="xlarge" name="name" id="name" class="form-control"
                   value="<c:out value='${requestScope.group.groupName}'/>"/>
        </div>

        <div class="form-group">
            <label class="control-label" for="enabled">Status</label>

            <select name="enabled" id="enabled" class="form-control">
                <c:choose>
                    <c:when test="${requestScope.group.enabled}">
                        <option value="Y" selected="selected">Enabled (current)</option>
                        <option value="N">Disabled</option>
                    </c:when>
                    <c:otherwise>
                        <option value="Y">Enabled</option>
                        <option value="N" selected="selected">Disabled (current)</option>
                    </c:otherwise>
                </c:choose>
            </select>
        </div>

        <button type="submit" class="btn btn-primary">Update</button>
    </fieldset>
</form>

<c:if test="${requestScope.group.enabled}">
    <hr/>
    <div class="row">
        <div class="col-md-12"><h4>Current Members</h4></div>
    </div>
    <div class="row">
        <div class="col-md-12">Number of members : <span id="groupcount"><c:out
                value="${requestScope.membercount}"/></span>
        </div>
    </div>

    <div class="row">
        <div class="col-md-12">Click on a user to remove them from the group</div>
    </div>
    <div class="row">
        <div class="col-md-12">
            <ul>
                <c:forEach var="thisUser" items="${requestScope.group_members}">
                    <c:url var="remove_url" value="/admin/RemoveUserFromGroup">
                        <c:param name="group_id" value="${requestScope.group.groupId}"/>
                        <c:param name="userId" value="${thisUser.id}"/>
                        <c:param name="next_page" value="EditGroup"/>
                    </c:url>
                    <li><a href="${remove_url}" name="remove_${thisUser.id}"><c:out value="${thisUser}"/></a></li>
                </c:forEach>
            </ul>
        </div>
    </div>

    <div class="spacer">&nbsp;</div>

    <c:if test="${not empty requestScope.group_nonmembers}">
        <div class="row">
            <div class="col-md-12"><h4>Current Non-members</h4></div>
        </div>
        <div class="row">
            <div class="col-md-12">Click on a user move them into the group</div>
        </div>
        <div class="row">
            <div class="col-md-12">
                <ul>
                    <c:forEach var="thisUser" items="${requestScope.group_nonMembers}">
                        <c:url var="add_url" value="/admin/AddUserToGroup">
                            <c:param name="group_id" value="${requestScope.group.groupId}"/>
                            <c:param name="userId" value="${thisUser.id}"/>
                            <c:param name="next_page" value="EditGroup"/>
                        </c:url>
                        <li><a href="${add_url}" name="add_${thisUser.id}"><c:out value="${thisUser}"/></a></li>
                    </c:forEach>
                </ul>
            </div>
        </div>
    </c:if>
</c:if>
</body>
</html>
