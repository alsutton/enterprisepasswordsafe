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
<head><title>Edit access rules</title></head>
<body>

<div class="row">
    <div class="col-md-12">
        <h3>
            <span id="username">
            <c:choose>
                <c:when test="${empty requestScope.password.username}">[Empty Username]</c:when>
                <c:otherwise><c:out value="${requestScope.password.username}" /></c:otherwise>
            </c:choose>
            </span>
            &nbsp;@&nbsp;
            <span id="system">
            <c:choose>
                <c:when test="${empty requestScope.password.location}">[Empty System Name]</c:when>
                <c:otherwise><c:out value="${requestScope.password.location}" /></c:otherwise>
            </c:choose>
            </span>
        </h3>
    </div>
</div>

<form action="<c:url value='/subadmin/UpdateAccess'/>" method="POST"
      accept-charset="ISO-8859-1" name="editaccess" role="form">
    <input type="hidden" name="id" value="${requestScope.password.id}">


    <div class="row">
        <div class="col-md-8 col-md-offset-4"><h6>Access</h6></div>
    </div>

    <div class="row">
        <div class="col-md-4 text-right">Default Access Rule :</div>
        <div class="col-md-8">
            <jsp:include page="/WEB-INF/includes/access_control_selector.jsp">
                <jsp:param name="input_name" value="g_2"/>
                <jsp:param name="modifiable" value="${requestScope.egac eq 'RM'}" />
                <jsp:param name="readable" value="${requestScope.egac eq 'R'}" />
            </jsp:include>
        </div>
    </div>

    <hr />

    <div class="row"><div class="col-md-12"><h4>Groups</h4></div></div>

    <c:choose>
        <c:when test="${empty requestScope.gac_summaries}">
            <div class="row"><div class="col-md-12"><i>No groups have been defined yet</i></div></div>
        </c:when>
        <c:otherwise>
            <div class="row"><div class="col-md-12">Any user rules take precedence over group rules.</div></div>

            <div class="row">
                <div class="col-md-4"><h6>Group</h6></div>
                <div class="col-md-4"><h6>Access</h6></div>
                <div class="col-md-2"><h6>RA Approver</h6></div>
                <div class="col-md-2"><h6>View History</h6></div>
            </div>

            <c:forEach var="thisGACSummary" items="${requestScope.gac_summaries}">
                <div class="row">
                    <div class="col-md-4"><c:out value="${thisGACSummary.name}"/></div>
                    <div class="col-md-4">
                        <jsp:include page="/WEB-INF/includes/access_control_selector.jsp">
                            <jsp:param name="input_name" value="g_${thisGACSummary.id}"/>
                            <jsp:param name="modifiable" value="${thisGACSummary.modifiable}" />
                            <jsp:param name="readable" value="${thisGACSummary.readable}" />
                        </jsp:include>
                    </div>
                    <div class="col-md-2">
                        <c:choose>
                            <c:when test="${thisGACSummary.restrictedAccessApprover}">
                                <input type="hidden" name="ogr_${thisGACSummary.id}" value="on"/>
                                <label><input type="checkbox" name="gr_${thisGACSummary.id}" checked="checked" /></label>
                            </c:when>
                            <c:otherwise>
                                <label><input type="checkbox" name="gr_${thisGACSummary.id}" /></label>
                            </c:otherwise>
                        </c:choose>
                    </div>
                    <div class="col-md-2">
                        <c:choose>
                            <c:when test="${thisGACSummary.historyViewer}">
                                <input type="hidden" name="ogh_${thisGACSummary.id}" value="on"/>
                                <label><input type="checkbox" name="gh_${thisGACSummary.id}" checked="checked" /></label>
                            </c:when>
                            <c:otherwise>
                                <label><input type="checkbox" name="gh_${thisGACSummary.id}" /></label>
                            </c:otherwise>
                        </c:choose>
                    </div>
                </div>
            </c:forEach>
        </c:otherwise>
    </c:choose>

    <hr />

    <div class="row"><div class="col-md-12"><h4>Users</h4></div></div>

    <c:choose>
        <c:when test="${empty requestScope.uac_summaries}">
            <div class="row"><div class="col-md-12"><i>No users have been defined yet</i></div></div>
        </c:when>
        <c:otherwise>
            <div class="row">
                <div class="col-md-4"><h6>User</h6></div>
                <div class="col-md-4"><h6>Access</h6></div>
                <div class="col-md-2"><h6>RA Approver</h6></div>
                <div class="col-md-2"><h6>View History</h6></div>
            </div>

            <c:forEach var="thisUACSummary" items="${requestScope.uac_summaries}">
                <div class="row">
                    <div class="col-md-4"><c:out value="${thisUACSummary.name}"/></div>
                    <div class="col-md-4">
                        <jsp:include page="/WEB-INF/includes/access_control_selector.jsp">
                            <jsp:param name="input_name" value="u_${thisUACSummary.id}"/>
                            <jsp:param name="modifiable" value="${thisUACSummary.modifiable}" />
                            <jsp:param name="readable" value="${thisUACSummary.readable}" />
                        </jsp:include>
                    </div>
                    <div class="col-md-2">
                        <c:choose>
                            <c:when test="${thisUACSummary.restrictedAccessApprover}">
                                <input type="hidden" name="our_${thisUACSummary.id}" value="on"/>
                                <label><input type="checkbox" name="ur_${thisUACSummary.id}" checked="checked" /></label>
                            </c:when>
                            <c:otherwise>
                                <label><input type="checkbox" name="ur_${thisUACSummary.id}" /></label>
                            </c:otherwise>
                        </c:choose>
                    </div>
                    <div class="col-md-2">
                        <c:choose>
                            <c:when test="${thisUACSummary.historyViewer}">
                                <input type="hidden" name="ouh_${thisUACSummary.id}" value="on"/>
                                <label><input type="checkbox" name="uh_${thisUACSummary.id}" checked="checked" /></label>
                            </c:when>
                            <c:otherwise>
                                <label><input type="checkbox" name="uh_${thisUACSummary.id}" /></label>
                            </c:otherwise>
                        </c:choose>
                    </div>
                </div>
            </c:forEach>
        </c:otherwise>
    </c:choose>

    <hr />

    <div class="row">
        <div class="col-md-8 col-md-offset-4">
            <button type="submit" class="btn btn-primary">Apply All Rules</button>
        </div>
    </div>
</form>
</body>
</html>