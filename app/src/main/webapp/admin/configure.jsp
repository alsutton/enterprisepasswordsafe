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
<head><title>Configuration Options</title></head>
<body>

<form action="<c:url value='/admin/Configure'/>" name="configurationform"
      method="POST" accept-charset="UTF-8">
<fieldset>

<div class="row">
    <div class="col-md-12"><h3>Email Settings</h3></div>
</div>

<div class="form-group">
    <label for="smtphost">SMTP Host :</label>
    <input type="text" name="smtphost" id="smtphost" class="form-control"
           value="<c:out value='${requestScope.smtphost}'/>" placeholder="smtp.somewhere.com"/>
</div>

<div class="form-group">
    <label for="smtpfrom">From Address :</label>
    <input type="text" name="smtpfrom" id="smtpfrom" class="form-control"
           value="<c:out value='${requestScope.smtpfrom}'/>" placeholder="someone@your.com"/>
</div>


<div class="row">
    <div class="col-md-12"><h3>User Logins and Sessions</h3></div>
</div>

<div class="form-group">
    <label for="user.login_attempts">Max. failed logins :</label>
    <input type="text" name="user.login_attempts" id="user.login_attempts" class="form-control"
           value="<c:out value='${requestScope.user_loginAttempts}'/>" placeholder="someone@your.com"/>
</div>

<div class="form-group">
    <label for="user.login_access">Access from unknown network (Warning : <i>No</i> can lock out the user <i>admin</i>) :</label>
    <select name="user.login_access" id="user.login_access" class="form-control">
        <c:choose>
            <c:when test="${requestScope.user_loginAccess == 'N'}">
                <option value="Y">Yes</option>
                <option value="N" selected="selected">No</option>
            </c:when>
            <c:otherwise>
                <option value="Y" selected="selected">Yes</option>
                <option value="N">No</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="form-group">
    <label for="session.timeout">Auto-logout (mins) :</label>
    <input type="text" name="session.timeout" id="session.timeout" class="form-control"
           value="<c:out value='${requestScope.session_timeout}'/>"/>
</div>

<div class="form-group">
    <label for="user.default_auth_source">Default Authentication Source :</label>
    <select name="user.default_auth_source" id="user.default_auth_source" class="form-control">
        <c:choose>
            <c:when test="${requestScope.user_defaultAuthSource == '0'}">
                <option value="0" selected="selected">The EPS</option>
            </c:when>
            <c:otherwise>
                <option value="<c:out value='${requestScope.user_defaultAuthSource}'/>" selected="selected"><c:out
                        value="${requestScope.user_defaultAuthSourceName}"/></option>
                <option value="0">The EPS</option>
            </c:otherwise>
        </c:choose>
        <c:forEach var="thisSource" items="${requestScope.auth_list}">
            <option value="<c:out value='${thisSource.sourceId}'/>"><c:out value="${thisSource.name}"/></option>
        </c:forEach>
    </select>
</div>

<div class="row">
    <div class="col-md-12"><h3>Permissions</h3></div>
</div>

<div class="form-group">
    <label for="perms.precendece">Permission Precedence :</label>
    <select name="perms.precendece" id="perms.precendece" class="form-control">
        <c:choose>
            <c:when test="${requestScope.perms_precendece == 'U'}">
                <option value="U" selected="selected">User Permissions</option>
                <option value="G">Group Permissions</option>
            </c:when>
            <c:otherwise>
                <option value="U">User Permissions</option>
                <option value="G" selected="selected">Group Permissions</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="row">
    <div class="col-md-12"><h3>Password Hierarchy</h3></div>
</div>

<div class="form-group">
    <label for="hierarchy.hide_empty">Hide empty folders :</label>
    <select name="hierarchy.hide_empty" id="hierarchy.hide_empty" class="form-control">
        <c:choose>
            <c:when test="${requestScope.hierarchy_hideEmpty == 'Y'}">
                <option value="Y" selected="selected">Yes</option>
                <option value="N">No</option>
            </c:when>
            <c:otherwise>
                <option value="Y">Yes</option>
                <option value="N" selected="selected">No</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="form-group">
    <label for="hierarchy.default_rule">Default access rule :</label>
    <select name="hierarchy.default_rule" id="hierarchy.default_rule" class="form-control">
        <c:choose>
            <c:when test="${requestScope.hierarchy_defaultRule == 'A'}">
                <option value="A" selected="selected">Allow All</option>
                <option value="D">Deny All</option>
            </c:when>
            <c:otherwise>
                <option value="A">Allow All</option>
                <option value="D" selected="selected">Deny All</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="form-group">
    <label for="hierarchy.edit_userlevel">Password admins can edit the hierarchy :</label>
    <select name="hierarchy.edit_userlevel" id="hierarchy.edit_userlevel" class="form-control">
        <c:choose>
            <c:when test="${requestScope.hierarchy_editUserlevel == 'S'}">
                <option value="S" selected="selected">Yes</option>
                <option value="A">No</option>
            </c:when>
            <c:otherwise>
                <option value="S">Yes</option>
                <option value="A" selected="selected">No</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>


<div class="row">
    <div class="col-md-12"><h3>Password Display</h3></div>
</div>

<div class="form-group">
    <label for="rarLifetime">Restricted access request lifetime (mins) :</label>
    <input type="text" name="rarLifetime" id="rarLifetime" class="form-control"
           value="<c:out value='${requestScope.rarLifetime}'/>"/>
</div>

<div class="form-group">
    <label for="server_base_url">Base URL for restricted access request voting :</label>
    <input type="text" name="server_base_url" id="server_base_url" class="form-control"
           value="<c:out value='${requestScope.serverBaseUrl}'/>"
            placeholder="System Generated" />
</div>

<div class="form-group">
    <label for="rarSelfVote">RA approvers can self-vote :</label>
    <select name="rarSelfVote" id="rarSelfVote" class="form-control">
        <c:choose>
            <c:when test="${requestScope.rarSelfVote == 'n'}">
                <option value="y">Yes</option>
                <option value="n" selected="selected">No</option>
            </c:when>
            <c:otherwise>
                <option value="y" selected="selected">Yes</option>
                <option value="n">No</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="form-group">
    <label for="password.reasonrequired">All passwords required a reason to view them:</label>
    <select name="password.reasonrequired" id="password.reasonrequired" class="form-control">
        <c:choose>
            <c:when test="${requestScope.password_reasonrequired == 'n'}">
                <option value="y">Yes</option>
                <option value="n" selected="selected">No</option>
            </c:when>
            <c:otherwise>
                <option value="y" selected="selected">Yes</option>
                <option value="n">No</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="form-group">
    <label for="password.hidesystems">Don't show list of know locations :</label>
    <select name="password.hidesystems" id="password.hidesystems" class="form-control">
        <c:choose>
            <c:when test="${requestScope.password_hidesystems == 'n'}">
                <option value="y">Yes</option>
                <option value="n" selected="selected">No</option>
            </c:when>
            <c:otherwise>
                <option value="y" selected="selected">Yes</option>
                <option value="n">No</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="form-group">
    <label for="password.defaultdisplay">Passwords are initially :</label>
    <select name="password.defaultdisplay" id="password.defaultdisplay" class="form-control">
        <c:choose>
            <c:when test="${requestScope.password_defaultdisplay == 's'}">
                <option value="h">Hidden</option>
                <option value="s" selected="selected">Visible</option>
            </c:when>
            <c:otherwise>
                <option value="h" selected="selected">Hidden</option>
                <option value="s">Visible</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="form-group">
    <label for="password.displaytype">Passwords shown as :</label>
    <select name="password.displaytype" id="password.displaytype" class="form-control">
        <c:choose>
            <c:when test="${requestScope.password_displaytype == 't'}">
                <option value="i">Images</option>
                <option value="t" selected="selected">Text</option>
            </c:when>
            <c:otherwise>
                <option value="i" selected="selected">Images</option>
                <option value="t">Text</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="form-group">
    <label for="password.onscreen">Visibility timeout (requires JavaScript) :</label>
    <input type="text" name="password.onscreen" id="password.onscreen" class="form-control"
           value="<c:out value='${requestScope.password_onscreen}'/>"/>
</div>

<div class="form-group">
    <label for="password.back_to_password_allowed">Allow back button to be used :</label>
    <select name="password.back_to_password_allowed" id="password.back_to_password_allowed" class="form-control">
        <c:choose>
            <c:when test="${requestScope.password_backToPasswordAllowed}">
                <option value="true" selected="selected">Yes</option>
                <option value="false">No</option>
            </c:when>
            <c:otherwise>
                <option value="true">Yes</option>
                <option value="false" selected="selected">No</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="form-group">
    <label for="subadmin.access_history">Password admins can view logs :</label>
    <select name="subadmin.access_history" id="subadmin.access_history" class="form-control">
        <c:choose>
            <c:when test="${requestScope.subadmin_accessHistory == 'Y'}">
                <option value="Y" selected="selected">Yes</option>
                <option value="N">No</option>
            </c:when>
            <c:otherwise>
                <option value="Y">Yes</option>
                <option value="N" selected="selected">No</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>


<div class="row">
    <div class="col-md-12"><h3>Password Editing</h3></div>
</div>

<div class="form-group">
    <label for="expiry.max_distance">Max expiry distance (days, 0 means no limit) :</label>
    <input type="text" name="expiry.max_distance" id="expiry.max_distance" class="form-control"
           value="<c:out value='${requestScope.expiry_maxDistance}'/>"/>
</div>

<div class="form-group">
    <label for="password.entry_hidden">Hide password :</label>
    <select name="password.entry_hidden" id="password.entry_hidden" class="form-control">
        <c:choose>
            <c:when test="${requestScope.password_entryHidden}">
                <option value="true" selected="selected">Yes</option>
                <option value="false">No</option>
            </c:when>
            <c:otherwise>
                <option value="true">Yes</option>
                <option value="false" selected="selected">No</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="form-group">
    <label for="expiry.allow_historical">Reject past expiry dates :</label>
    <select name="expiry.allow_historical" id="expiry.allow_historical" class="form-control">
        <c:choose>
            <c:when test="${requestScope.expiry_allowHistorical == 'N'}">
                <option value="Y">Yes</option>
                <option value="N" selected="selected">No</option>
            </c:when>
            <c:otherwise>
                <option value="Y" selected="selected">Yes</option>
                <option value="N">No</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>


<div class="row">
    <div class="col-md-12"><h3>Password Retention and Auditing</h3></div>
</div>

<div class="form-group">
    <label for="password.history">Password History Retention :</label>
    <select name="password.history" id="password.history" class="form-control">
        <c:choose>
            <c:when test="${requestScope.password_history == 'C'}">
                <option value="C" selected="selected">Choose when password is created</option>
                <option value="F">Always</option>
                <option value="L">Never</option>
            </c:when>
            <c:when test="${requestScope.password_history == 'F'}">
                <option value="C">Choose when password is created</option>
                <option value="F" selected="selected">Always</option>
                <option value="L">Never</option>
            </c:when>
            <c:when test="${requestScope.password_history == 'L'}">
                <option value="C">Choose when password is created</option>
                <option value="F">Always</option>
                <option value="L" selected="selected">Never</option>
            </c:when>
            <c:otherwise>
                <option value="C">Choose when password is created</option>
                <option value="F">Always</option>
                <option value="L">Never</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>

<div class="form-group">
    <label for="password.audit">Password Auditing Level :</label>
    <select name="password.audit" id="password.audit" class="form-control">
        <c:choose>
            <c:when test="${requestScope.password_audit == 'C'}">
                <option value="C" selected="selected">Configurable</option>
                <option value="F">Always Alert and Log</option>
                <option value="L">Always Log</option>
                <option value="N">Do nothing</option>
            </c:when>
            <c:when test="${requestScope.password_audit == 'F'}">
                <option value="C">Configurable</option>
                <option value="F" selected="selected">Always Alert and Log</option>
                <option value="L">Always Log</option>
                <option value="N">Do nothing</option>
            </c:when>
            <c:when test="${requestScope.password_audit == 'L'}">
                <option value="C">Configurable</option>
                <option value="F">Always Alert and Log</option>
                <option value="L" selected="selected">Always Log</option>
                <option value="N">Do nothing</option>
            </c:when>
            <c:when test="${requestScope.password_audit == 'N'}">
                <option value="C">Configurable</option>
                <option value="F">Always Alert and Log</option>
                <option value="L">Always Log</option>
                <option value="N" selected="selected">Do nothing</option>
            </c:when>
            <c:otherwise>
                <option value="C">Configurable</option>
                <option value="F">Always Alert and Log</option>
                <option value="L">Always Log</option>
                <option value="N">Do nothing</option>
            </c:otherwise>
        </c:choose>
    </select>
</div>


<div class="row">
    <div class="col-md-12"><h3>Miscellaneous</h3></div>
</div>

<div class="form-group">
    <label for="report.separator">Separator for reports :</label>
    <input type="text" name="report.separator" id="report.separator" class="form-control"
           value="<c:out value='${requestScope.report_separator}'/>"/>
</div>

<button type="submit" class="btn btn-primary">Update settings</button>

</fieldset>
</form>
</body>
</html>
