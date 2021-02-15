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
<head>
    <title>Event Email Settings</title>
</head>
<body>
<form action="<c:url value='/admin/ConfigureEmail'/>" method="POST" accept-charset="utf-8" name="configurationform" role="form">
    <fieldset>
        <div class="row"><div class="span12"><h3>Email Settings</h3></div></div>

        <div class="form-group">
            <label for="smtpto">Emails will go to <i>(separate each address with a semicolon ';')</i></label>
            <input name="smtpto" id="smtpto" type="text" class="form-control" value="<c:out value='${requestScope.smtpto}'/>" placeholder="x@y.com ; y@x.com" />
        </div>

        <div class="spacer">&nbsp;</div>

        <jsp:include page="/WEB-INF/includes/yes_no_select.jsp">
            <jsp:param name="input_label" value="Include user on audit emails" />
            <jsp:param name="input_value" value="${requestScope.audit_emailUser eq 'Y'}" />
            <jsp:param name="input_name" value="audit.email_user" />
        </jsp:include>

        <div class="row"><div class="span12"><h3>Events Creating Alerts</h3></div></div>

        <jsp:include page="/WEB-INF/includes/yes_no_select.jsp">
            <jsp:param name="input_label" value="Operations on passwords" />
            <jsp:param name="input_value" value="${requestScope.smtp_enabled_objectManipulation eq 'Y'}" />
            <jsp:param name="input_name" value="smtp.enabled.object_manipulation" />
        </jsp:include>

        <jsp:include page="/WEB-INF/includes/yes_no_select.jsp">
            <jsp:param name="input_label" value="Operations on users" />
            <jsp:param name="input_value" value="${requestScope.smtp_enabled_userManipulation eq 'Y'}" />
            <jsp:param name="input_name" value="smtp.enabled.user_manipulation" />
        </jsp:include>

        <jsp:include page="/WEB-INF/includes/yes_no_select.jsp">
            <jsp:param name="input_label" value="Operations on groups" />
            <jsp:param name="input_value" value="${requestScope.smtp_enabled_groupManipulation eq 'Y'}" />
            <jsp:param name="input_name" value="smtp.enabled.group_manipulation" />
        </jsp:include>

        <jsp:include page="/WEB-INF/includes/yes_no_select.jsp">
            <jsp:param name="input_label" value="Operations on the hierarchy" />
            <jsp:param name="input_value" value="${requestScope.smtp_enabled_hierarchyManipulation eq 'Y'}" />
            <jsp:param name="input_name" value="smtp.enabled.hierarchy_manipulation" />
        </jsp:include>

        <jsp:include page="/WEB-INF/includes/yes_no_select.jsp">
            <jsp:param name="input_label" value="User authentication problems" />
            <jsp:param name="input_value" value="${requestScope.smtp_enabled_authentication eq 'Y'}" />
            <jsp:param name="input_name" value="smtp.enabled.authentication" />
        </jsp:include>

        <jsp:include page="/WEB-INF/includes/yes_no_select.jsp">
            <jsp:param name="input_label" value="Report Downloads" />
            <jsp:param name="input_value" value="${requestScope.smtp_enabled_reports eq 'Y'}" />
            <jsp:param name="input_name" value="smtp.enabled.reports" />
        </jsp:include>

        <jsp:include page="/WEB-INF/includes/yes_no_select.jsp">
            <jsp:param name="input_label" value="Configuration changes" />
            <jsp:param name="input_value" value="${requestScope.smtp_enabled_configuration eq 'Y'}" />
            <jsp:param name="input_name" value="smtp.enabled.configuration" />
        </jsp:include>

        <button type="submit" class="btn btn-primary">Update Settings</button>
    </fieldset>
</form>
</body>
</html>
