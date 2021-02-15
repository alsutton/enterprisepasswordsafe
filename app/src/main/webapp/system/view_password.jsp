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
<head><title>View Password</title></head>
<body>

<span id="timeout" class="hidden">
    <c:choose>
        <c:when test="${requestScope.password_timeout > 0}">${requestScope.password_timeout}</c:when>
        <c:otherwise>0</c:otherwise>
    </c:choose>
</span>

<c:if test="${not empty requestScope.timepoint_hr}">
<div class="row">
    <div class="col-md-12">
        Details shown for <c:out value="${requestScope.timepoint_hr}" />
    </div>
</div>
</c:if>

<c:choose>
	<c:when test="${empty requestScope.password}">
		<c:choose>
			<c:when test="${empty requestScope.dt}">
				<div class="alert alert-error text-center">A password entry is not available for the password.</div>
			</c:when>
			<c:otherwise>
				<div class="alert alert-error text-center">History recording for the password was not enabled at that time.</div>
			</c:otherwise>
		</c:choose>
	</c:when>
	<c:otherwise>
        <div class="row">
            <div class="col-md-12">
                <h4>
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
                </h4>
            </div>
        </div>
		<div class="row">
			<div class="col-sm-12">
                <table class="table">
                    <tbody class="unbordered">
                    <tr>
                        <td class="text-right">Password :</td>
                        <td>
                            <c:choose>
                                <c:when test="${requestScope.display}">
                                    <c:choose>
                                        <c:when test="${requestScope.password_displayType == 'i'}">
                                            <c:choose>
                                                <c:when test="${empty requestScope.dt}">
                                                    <c:url var="image_url" value="/system/ViewPasswordImage">
                                                        <c:param name="id" value="${requestScope.password.id}" />
                                                    </c:url>
                                                </c:when>
                                                <c:otherwise>
                                                    <c:url var="image_url" value="/system/ViewPasswordImage">
                                                        <c:param name="id" value="${requestScope.password.id}" />
                                                        <c:param name="dt" value="${requestScope.dt}" />
                                                    </c:url>
                                                </c:otherwise>
                                            </c:choose>
                                            <img	id="passworddisplay"
                                                    alt="The Password"
                                                    src="${image_url}" />
                                        </c:when>

                                        <c:when test="${requestScope.password_displayType == 't'}">
                                            <c:out value="${requestScope.password.password}"/>
                                            <input type="hidden" id="passworddisplay" value="<c:out value='${requestScope.password.password}'/>" />
                                        </c:when>
                                    </c:choose>

                                    <form	action="<c:url value='/system/ViewPassword'/>"
                                            name="passwordshowhideform" method="POST" accept-charset="ISO-8859-1"
                                            class="form-inline" role="form">
                                        <input type="hidden" name="display" value="false" />
                                        <input type="hidden" name="otid" value="${requestScope.nextOtid}" />
                                        <input type="hidden" name="id" value="${requestScope.password.id}" />
                                        <c:if test="${not empty requestScope.reason}"><input  type="hidden" name="reason" value="<c:out value='${requestScope.reason}' />"></c:if>
                                        <c:if test="${not empty requestScope.dt}"><input type="hidden" name="dt" value="<c:out value='${requestScope.dt}' />" /></c:if>
                                        <button type="submit" class="btn btn-xs btn-default">Hide Password</button>
                                    </form>
                                </c:when>
                                <c:otherwise>
                                    <form action="<c:url value='/system/ViewPassword'/>"
                                          name="passwordshowhideform" method="POST" accept-charset="ISO-8859-1"
                                          class="form-inline" role="form">
                                    <input type="hidden" name="otid" value="${requestScope.nextOtid}">
                                    <input type="hidden" name="id" value="${requestScope.password.id}" />
                                    <input type="hidden" name="display" value="true"  />
                                    <c:if test="${not empty requestScope.reason}"><input  type="hidden" name="reason" value="<c:out value='${requestScope.reason}'/>"></c:if>
                                    <c:if test="${not empty requestScope.dt}"><input type="hidden" name="dt" value="${requestScope.dt}" /></c:if>
                                    <button type="submit" class="btn btn-xs btn-default">Show Password</button>
                                    </form>
                                </c:otherwise>
                            </c:choose>

                            <c:if test="${requestScope.scripts}">
                                <c:if test="${requestScope.password.modifiable}">
                                    <c:url var="randomize_url" value="/system/RandomizePassword">
                                        <c:param name="id" value="${requestScope.password.id}" />
                                    </c:url>
                                    <a href="${randomize_url}" class="btn btn-xs btn-default">Randomize</a>
                                </c:if>
                            </c:if>
                        </td>
                    </tr>
                    <tr>
                        <td class="text-right">Expires :</td>
                        <td id="expiry">
                            <c:choose>
                                <c:when test="${empty requestScope.password.expiryInHumanForm}">Never</c:when>
                                <c:otherwise><c:out value="${requestScope.password.expiryInHumanForm}"/></c:otherwise>
                            </c:choose>
                        </td>
                    </tr>
                    <c:if test="${empty requestScope.dt}">
                        <c:if test="${not empty sessionScope.user_is_subadmin}">
                            <tr>
                                <td class="text-right">Status :</td>
                                <td>
                                    <c:choose>
                                        <c:when test="${requestScope.password.enabled}">Enabled</c:when>
                                        <c:otherwise>Disabled</c:otherwise>
                                    </c:choose>
                                </td>
                            </tr>
                        </c:if>
                    </c:if>
                    <c:forEach var="thisEntry" items="${requestScope.cfields}">
                        <tr>
                            <td class="text-right"><c:out value="${thisEntry.key}" />:</td>
                            <td><c:out value="${thisEntry.value}" /></td>
                        </tr>
                    </c:forEach>
                    <tr>
                        <td class="text-right">Notes :</td>
                        <td><c:out value="${requestScope.password.notes}" /></td>
                    </tr>
                    </tbody>
                </table>
            </div>
        </div>

		<div class="row">
            <div class="col-sm-12 text-center">
                <c:if test="${empty requestScope.dt}">
                    <c:if test="${requestScope.password.modifiable}">
                        <c:url var="edit_url" value="/system/EditPassword">
                            <c:param name="id" value="${requestScope.password.id}" />
                        </c:url>
                        <a href="${edit_url}" class="btn btn-default">Edit details</a>
                        <c:if test="${requestScope.password.passwordType == 0}">
                            <c:if test="${not empty sessionScope.user_is_subadmin}">
                                <c:url var="alter_access_url" value="/subadmin/AlterAccess">
                                    <c:param name="id" value="${requestScope.password.id}" />
                                </c:url>
                                <a href="${alter_access_url}" class="btn btn-default">Alter access</a>
                            </c:if>
                        </c:if>
                    </c:if>

                    <c:if test="${not empty sessionScope.user_is_admin}">
                        <c:if test="${requestScope.password.passwordType == 0}">
                            <c:url var="alter_integration_url" value="/admin/AlterIntegrationScript">
                                <c:param name="id" value="${requestScope.password.id}" />
                            </c:url>
                            <a href="${alter_integration_url}" class="btn btn-default">Alter integration</a>
                        </c:if>
                    </c:if>
                    <c:if test="${requestScope.password.passwordType == 1}">
                        <c:url var="delete_url" value="/system/DeletePassword">
                            <c:param name="id" value="${requestScope.password.id}" />
                        </c:url>
                        <a href="${delete_url}" name="deletepassword" class="btn btn-default">Delete</a>
                    </c:if>
                </c:if>

                <c:if test="${requestScope.showHistoryOption}">
                    <c:url var="view_events_url" value="/system/ViewObjectEvents">
                        <c:param name="id" value="${requestScope.password.id}" />
                    </c:url>
                    <a href="${view_events_url}" class="btn btn-default">View History</a>
                </c:if>
            </div>
        </div>
	</c:otherwise>
</c:choose>
<script src="<c:url value='/js/viewtimeout.js'/>"></script>
</body>
</html>