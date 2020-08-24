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
<head><title>User Profile</title></head>
<body>
<form action="<c:url value='/admin/User'/>" name="userdetails" method="POST"
      accept-charset="utf-8" role="form">
    <fieldset>
        <input type="hidden" name="userId" value="<c:out value='${requestScope.user.id}'/>"/>
        <input type="hidden" name="token" value="<c:out value='${sessionScope.csrfToken}' />"/>

        <div class="form-group">
            <label for="username">Username</label>
            <input name="username" id="username" class="form-control"
                   value="<c:out value='${requestScope.user.userName}'/>"/>
        </div>

        <div class="form-group">
            <label for="fullname">Full Name</label>
            <input type="text" name="fn" id="fullname" class="form-control"
                   value="<c:out value='${requestScope.user.fullName}'/>"/>
        </div>

        <div class="form-group">
            <label for="email">Email</label>
            <input type="text" name="em" id="email" class="form-control"
                    value="<c:out value='${requestScope.user.email}'/>"/>
        </div>

        <div class="form-group">
            <label for="auth_source">Authenticated by</label>
            <select name="auth_source" id="auth_source" class="form-control">
                <c:choose>
                    <c:when test="${requestScope.authsource == null || requestScope.authsource.sourceId eq '0'}">
                        <option value="0" selected="selected">The EPS</option>
                    </c:when>
                    <c:otherwise>
                        <option value="<c:out value='${requestScope.authsource.sourceId}'/>"
                                selected="selected">
                            <c:out value="${requestScope.authsource.name}"/>
                        </option>
                        <option value="0">The EPS</option>
                    </c:otherwise>
                </c:choose>
                <c:forEach var="thisSource" items="${requestScope.auth_list}">
                    <option value="<c:out value='${thisSource.sourceId}'/>">
                        <c:out value="${thisSource.name}"/>
                    </option>
                </c:forEach>
            </select>
        </div>

        <div class="form-group">
            <label for="user_type">User Type</label>
            <c:choose>
                <c:when test="${requestScope.user.administrator}">
                    <c:set var="ut_epsadmin_selected" value="selected=\"selected\"" />
                </c:when>
                <c:when test="${requestScope.user.subadministrator}">
                    <c:set var="ut_epssubadmin_selected" value="selected=\"selected\"" />
                </c:when>
                <c:otherwise>
                    <c:set var="ut_user_selected" value="selected=\"selected\"" />
                </c:otherwise>
            </c:choose>
            <select name="user_type" id="user_type" class="form-control">
                <option value="0" ${ut_epsadmin_selected}>EPS Administrator</option>
                <option value="1" ${ut_epssubadmin_selected}>Password Administrator</option>
                <option value="2" ${ut_user_selected}>Normal User</option>
            </select>
        </div>

        <div class="form-group">
            <label for="user_enabled">Status</label>
            <select name="user_enabled" id="user_enabled" class="form-control">
                <c:choose>
                    <c:when test="${requestScope.user.enabled eq false}">
                        <option value="Y">Enabled</option>
                        <option value="N" selected="selected">Disabled (current)</option>
                    </c:when>
                    <c:otherwise>
                        <option value="Y" selected="selected">Enabled (current)</option>
                        <option value="N">Disabled</option>
                    </c:otherwise>
                </c:choose>
            </select>
        </div>

        <div class="form-group">
            <label for="password1">Password</label>
            <input type="password" id="password1" name="password1" size="20" class="form-control"/>
        </div>

        <div class="form-group">
            <label for="password2">Confirm Password</label>
            <input type="password" id="password2" name="password2" size="20" class="form-control"/>
        </div>

        <jsp:include page="/WEB-INF/includes/yes_no_select.jsp">
            <jsp:param name="input_label" value="Change password at login" />
            <jsp:param name="input_name" value="force_change_password" />
            <jsp:param name="input_value" value="${requestScope.user.passwordLastChanged < 0}" />
        </jsp:include>

        <jsp:include page="/WEB-INF/includes/yes_no_select.jsp">
            <jsp:param name="input_label" value="User can't view passwords" />
            <jsp:param name="input_name" value="noview" />
            <jsp:param name="input_value" value="${requestScope.user.nonViewingUser}" />
        </jsp:include>

        <c:if test="${not empty requestScope.groups}">
            <div class="row">
                <div class="col-md-12"><h3>Group Membership</h3></div>
            </div>

            <div class="form-group">
                <c:forEach var="thisGroup" items="${requestScope.groups}">
                    <c:choose>
                        <c:when test="${requestScope.group_membership_map[thisGroup.groupId] ne null}" >
                            <c:set var="membership_select" value="checked='checked'"/>
                        </c:when>
                        <c:otherwise>
                            <c:set var="membership_select" value=""/>
                        </c:otherwise>
                    </c:choose>
                    <div class="checkbox">
                        <label><input type="checkbox" name="group_${thisGroup.groupId}" ${membership_select}>&nbsp;<c:out value="${thisGroup.groupName}"/></label>
                    </div>
                </c:forEach>
            </div>
        </c:if>

        <c:if test="${not empty requestScope.restrictions}">
            <div class="row">
                <div class="col-md-12"><h3>Login Restrictions</h3></div>
            </div>

            <div class="row">
                <div class="col-md-12"><b>Please note:</b> rules denying access take precedence. Therefore if two zones
                    overlap, and one is configured
                    to allow access, and the other is configured to deny access, the user will be denied access if they log
                    in from a system in the overlapping region.
                </div>
            </div>

            <c:forEach var="thisZone" items="${requestScope.restrictions}">
                <div class="form-group">
                    <label for="zone_${thisZone.id}"><c:out value="${thisZone.name}"/></label>
                    <select name="zone_${thisZone.id}" id="zone_${thisZone.id}" class="form-control">
                        <c:choose>
                            <c:when test="${requestScope.restrictions_map eq null}">
                                <option value="D" selected="selected">Treat zone as unknown</option>
                                <option value="Y">Allow</option>
                                <option value="N">Deny</option>
                            </c:when>
                            <c:otherwise>
                                <c:choose>
                                    <c:when test="${requestScope.restrictions_map[thisZone.id] eq 'N'}">
                                        <option value="D">Treat zone as unknown</option>
                                        <option value="Y">Allow</option>
                                        <option value="N" selected="selected">Deny</option>
                                    </c:when>
                                    <c:when test="${requestScope.restrictions_map[thisZone.id] eq 'Y'}">
                                        <option value="D">Treat zone as unknown</option>
                                        <option value="Y" selected="selected">Allow</option>
                                        <option value="N">Deny</option>
                                    </c:when>
                                    <c:otherwise>
                                        <option value="D" selected="selected">Treat zone as unknown</option>
                                        <option value="Y">Allow</option>
                                        <option value="N">Deny</option>
                                    </c:otherwise>
                                </c:choose>
                            </c:otherwise>
                        </c:choose>
                    </select>
                </div>
            </c:forEach>
        </c:if>

        <button type="submit" class="btn btn-primary">Update Details</button>
    </fieldset>
</form>
</body>
</html>