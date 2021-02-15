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
<head><title>Import Passwords</title></head>
<body>

<div class="row">
    <div class="col-md-12">
        <p>The import file should contain one password per line with the information represented the following format;</p>
        <pre>System Name, Username, Password, Notes[, Auditing, Record History, CF:Custom Field, CF:Custom Field[,...]]][, Permission[, Permission[,...]]]</pre>
        <p>Where; </p>
        <dl class="dl-horizontal">
            <dt>Auditing</dt>
            <dd>One of <code>full</code> to send alerts and log events, <code>log</code> to log events, or <code>none</code>
                (to do nothing). The default value is <code>full</code>.</dd>
            <dt>Record History</dt>
            <dd>Determines if the password history should be recorded. This can be
                either <code>true</code> or <code>false</code>, the default value is <code>true</code> which will record the password history.</dd>
            <dt>Custom Field</dt>
            <dd>A custom field definition. It must be prefixed by CF: (in upper case), and
                consists of a field name followed by an equals and the field value. You can include multiple custom fields
                separated by commas. For example; <code>CF:field1=value1, CF:field2=value2</code> will create two custom fields
                called field1 and field2 with the values of value1 and value2.</dd>
            <dt>Permission</dt>
            <dd>Consists of either a <code>G</code> for Group, or <code>U</code> for User, followed by a <code>V</code> for View
                or <code>M</code> for View and Modify, followed by a colon (<code>:</code>), and then the name of the group or user.</dd>
        </dl>
        <p>For example the following entry;</p>
        <pre>example software package, user, pass, some notes, full, true, UV:alice, GV:group1, UM:bob, GM:group2</pre>
        <p>Would create a password with the username <i>user</i> and password <i>pass</i> for the system called  <i>example software package</i>
            with the notes field set to read <i>some notes</i>. Any audit events would cause an alert to be sent and logged,
            and any changes to the password would be logged as part of the password history. The user alice and anyone in the group
            group1 would be allowed to view the password, and the user bob and anyone in the group called group2 would be allowed
            to view and modify the password.</p>

    </div>
</div>


<form   action="<c:url value='/subadmin/ImportPasswords'/>"
        method="post" enctype="multipart/form-data"
	    accept-charset="ISO-8859-1"
        name="importform"
        role="form">
<fieldset>
    <div class="form-group">
        <label for="file"><strong>File To Import</strong></label>
        <input id="file" name="file" type="file">
    </div>
    <button type="submit" class="btn btn-primary">Import Password File</button>
</fieldset>
</form>
</body>
</html>