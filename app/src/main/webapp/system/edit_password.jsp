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
<!-- TODO: Combine with new_password -->
<html lang="en">
<head>
    <link rel="StyleSheet" href="<c:url value='/css/datepicker.css'/>" type="text/css">
    <title>Update password</title>
</head>
<body>
<div class="modal fade" id="generatorModal" tabindex="-1" role="dialog" aria-labelledby="generatorModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                <h4 class="modal-title">Generated Password</h4>
            </div>
            <div class="modal-body">
                The generated password is <span id="generatedPassword"></span>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" id="useGeneratedPassword">Use</button>
            </div>
        </div>
    </div>
</div>

<form action="<c:url value='/system/ChangePassword'/>" method="POST" accept-charset="ISO-8859-1" name="editform"
      id="editform" role="form" class="form-horizontal">
<input type="hidden" name="token" value="<c:out value='${sessionScope.csrfToken}' />"/>
<c:if test="${not empty requestScope.password_id}"><input type="hidden" name="id" value="${password_id}" /></c:if>

<div class="form-group">
    <label for="username" class="col-md-2 control-label">Username :</label>
    <div class="col-md-10">
        <input type="text" id="username" name="username" value="<c:out value='${requestScope.username}'/>" class="form-control"/>
    </div>
</div>

<div class="form-group">
    <label for="location_text" class="col-md-2 control-label">System Name :</label>
    <div class="col-md-10">
        <!-- TODO: Autocomplete location using locations_set -->
        <input type="text" id="location_text" name="location_text" value="<c:out value='${requestScope.location_text}'/>" class="form-control"/>
    </div>
</div>

<c:if test="${not empty sessionScope.user_is_admin}">
    <div class="form-group">
        <label for="restriction_id" class="col-md-2 control-label">Password Restriction</label>
        <div class="col-md-10">
            <c:choose>
                <c:when test="${empty requestScope.restriction_list}"><i>None</i>
                    <input class="form-control" readonly="readonly" value="None" id="restriction_id"/>
                </c:when>
                <c:otherwise>
                    <select name="restriction_id" id="restriction_id" class="form-control">
                        <c:choose>
                            <c:when test="${empty requestScope.restriction_id}">
                                <option selected="selected" value="-2">None</option>
                            </c:when>
                            <c:otherwise>
                                <option selected="selected" value="${requestScope.restriction_id}"><c:out value='${requestScope.restriction_name}'/></option>
                                <option value="-2">None</option>
                            </c:otherwise>
                        </c:choose>
                        <c:forEach var="thisSummary" items="${requestScope.restriction_list}">
                            <option value="${thisSummary.id}"><c:out value="${thisSummary.name}" /></option>
                        </c:forEach>
                    </select>
                </c:otherwise>
            </c:choose>
        </div>
    </div>
</c:if>

<c:choose>
    <c:when test="${requestScope.passwordFieldType == 'password'}">
        <c:set var="passwordInputType" value="password" />
    </c:when>
    <c:otherwise>
        <c:set var="passwordInputType" value="text" />
    </c:otherwise>
</c:choose>

<div class="form-group">
    <label for="password_1" class="col-md-2 control-label">Password :</label>
    <div class="col-md-10">
        <input type="${passwordInputType}" id="password_1" name="password_1" value="<c:out value='${requestScope.password_1}'/>" class="form-control"/>
    </div>
</div>

<div class="form-group">
    <label for="password_2" class="col-md-2 control-label">Re-type Password :</label>
    <div class="col-md-10">
        <input type="${passwordInputType}" id="password_2" name="password_2" value="<c:out value='${requestScope.password_2}'/>" class="form-control"/>
    </div>
</div>
<div class="row">
    <div class="col-md-12 text-right">
        <div id="generatorButton" class="btn btn-xs btn-default">Generate New Password</div>
    </div>
</div>


<c:if test="${not empty sessionScope.user_is_subadmin}">
    <div class="form-group">
        <label class="col-md-2  control-label">Status :</label>
        <div class="col-md-10">
            <jsp:include page="/WEB-INF/includes/enabled_disabled_select.jsp">
                <jsp:param name="input_value" value="${requestScope.enabled}" />
                <jsp:param name="input_name" value="enabled" />
            </jsp:include>
        </div>
    </div>
</c:if>

<div class="form-group">
    <label for="expiryDate" class="col-md-2 control-label">Password Expires :</label>
    <div class="col-md-10">
        <c:choose>
            <c:when test="${requestScope.noExpiry eq 'Y'}"><c:set var="expiry" value=""/></c:when>
            <c:otherwise><c:set var="expiry" value="${requestScope.expiry}"/></c:otherwise>
        </c:choose>

        <input type="text" id="expiryDate" name="expiryDate" value="<c:out value='${expiry}'/>" class="form-control"
               placeholder="Empty means no expiry"/>
    </div>
</div>

<div class="spacer">&nbsp;</div>
<c:if test="${not empty sessionScope.user_is_subadmin}">
    <div class="form-group">
        <label class="col-md-2  control-label">Restricted Access :</label>
        <div class="col-md-10">
            <jsp:include page="/WEB-INF/includes/enabled_disabled_select.jsp">
                <jsp:param name="input_value" value="${requestScope.ra_enabled}" />
                <jsp:param name="input_name" value="ra_enabled" />
            </jsp:include>
        </div>
    </div>
    <div class="form-group">
        <label for="ra_approvers" class="col-md-2 control-label">RA approvers required :</label>
        <div class="col-md-10">
            <input type="text" id="ra_approvers" name="ra_approvers" value="<c:out value='${requestScope.ra_approvers}'/>" class="form-control"/>
        </div>
    </div>
    <div class="form-group">
        <label for="ra_blockers" class="col-md-2 control-label">RA blockers required :</label>
        <div class="col-md-10">
            <input type="text" id="ra_blockers" name="ra_blockers" value="<c:out value='${requestScope.ra_blockers}'/>" class="form-control"/>
        </div>
    </div>
</c:if>

<div class="form-group">
    <label for="audit" class="col-md-2 control-label">Audit Level :</label>
    <div class="col-md-10">
        <c:choose>
            <c:when test="${requestScope.password_audit == 'C'}">
                <select class="form-control" name="audit" id="audit">
                    <c:choose>
                        <c:when test="${requestScope.audit == 'F'}">
                            <option value="F" selected="selected">Alert and Log</option>
                            <option value="L">Log only</option>
                            <option value="N">Do Nothing</option>
                        </c:when>
                        <c:when test="${requestScope.audit == 'L'}">
                            <option value="F">Alert and Log</option>
                            <option value="L" selected="selected">Log only</option>
                            <option value="N">Do Nothing</option>
                        </c:when>
                        <c:when test="${requestScope.audit == 'N'}">
                            <option value="F">Alert and Log</option>
                            <option value="L">Log only</option>
                            <option value="N" selected="selected">Do Nothing</option>
                        </c:when>
                    </c:choose>
                </select>
            </c:when>
            <c:when test="${requestScope.password_audit == 'F'}">
                <input type="hidden" name="audit" value="F" />
                <input type="text" id="audit" class="form-control" readonly="readonly" value="Alert and Log" />
            </c:when>
            <c:when test="${requestScope.password_audit == 'L'}">
                <input type="hidden" name="audit" value="L" />
                <input type="text" id="audit" class="form-control" readonly="readonly" value="Log Only" />
            </c:when>
            <c:otherwise>
                <input type="hidden" name="audit" value="N" />
                <input type="text" id="audit" class="form-control" readonly="readonly" value="None" />
            </c:otherwise>
        </c:choose>
    </div>
</div>

<div class="form-group">
    <label for="history" class="col-md-2 control-label">History Retained :</label>
    <div class="col-md-10">
        <c:choose>
            <c:when test="${requestScope.password_history == 'C'}">
                <c:choose>
                    <c:when test="${requestScope.history == 'y'}">
                        <label class="radio-inline">
                            <input type="radio" name="history" value="y" checked="checked" /> Yes
                        </label>&nbsp;&nbsp;<label class="radio-inline">
                        <input type="radio" name="history" value="n" /> No
                        </label>
                    </c:when>
                    <c:otherwise>
                        <label class="radio-inline">
                            <input type="radio" name="history" value="y" /> Yes
                        </label>&nbsp;&nbsp;<label class="radio-inline">
                        <input type="radio" name="history" value="n" checked="checked" /> No
                        </label>
                    </c:otherwise>
                </c:choose>
            </c:when>
            <c:when test="${requestScope.password_history == 'F'}">
                <input id="history" class="form-control" readonly="readonly" value="Yes" />
            </c:when>
            <c:otherwise>
                <input id="history" class="form-control" readonly="readonly" value="No" />
            </c:otherwise>
        </c:choose>
    </div>
</div>

<div class="row">
    <label class="col-md-2 control-label">Custom Fields :</label>
    <div class="col-md-10">
        <c:choose>
            <c:when test="${not empty requestScope.cfields}">
                <div class="row">
                    <div class="col-md-2">Name</div>
                    <div class="col-md-7">Value</div>
                    <div class="col-md-offset11 col-md-1"><span class="glyphicon glyphicon-trash"></span></div>
                </div>
                <c:forEach var="thisField" varStatus="status" items="${requestScope.cfields}">
                    <c:set var="customFieldIdx" value="${status.count -1}" />
                    <input  type="hidden" name="cfok_${customFieldIdx}" value="Y"/>
                    <div class="row">
                        <div class="col-md-2">
                            <label for="cfn_${customFieldIdx}"></label>
                            <input	type="text" id="cfn_${customFieldIdx}" name="cfn_${customFieldIdx}" value="${thisField.key}" class="form-control" />&nbsp;
                        </div>
                        <div class="col-md-7">
                            <label for="cfv_${customFieldIdx}"></label>
                            <input	type="text" id="cfv_${customFieldIdx}" name="cfv_${customFieldIdx}" value="${thisField.value}" class="form-control" />
                        </div>
                        <div class="col-md-1">
                            <label for="cfd_${customFieldIdx}"></label>
                            <input	type="checkbox" id="cfd_${customFieldIdx}" name="cfd_${customFieldIdx}" />
                        </div>
                    </div>
                </c:forEach>
            </c:when>
            <c:otherwise>
                <p class="help-block">None</p>
            </c:otherwise>
        </c:choose>
    </div>
</div>

<div class="row">
    <div class="col-md-12 text-right">
        <button type="submit" class="btn btn-xs btn-default" name="newCF" id="newCF" value="true">Add New Custom Field</button>
    </div>
</div>

<div class="spacer">&nbsp;</div>

<div class="form-group">
    <label for="notes" class="col-md-2 control-label">Notes :</label>
    <div class="col-md-10">
        <textarea id="notes" name="notes" rows='10' class="form-control"><c:out value="${requestScope.notes}"/></textarea>
    </div>
</div>

<div class="row">
    <div class="col-md-10 col-md-offset-2">
        <button type="submit" class="btn btn-primary" name="update">OK</button>
    </div>
</div>
</form>

<script src="<c:url value='/js/passwordgenerator.js'/>"></script>
<script src="<c:url value='/js/bootstrap-datepicker.js' />"></script>
<script src="<c:url value='/js/expirydatepicker.js'/>"></script>
</body>
</html>