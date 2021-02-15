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
<head><title>Profile</title></head>
<body>

<div class="spacer">&nbsp;</div>

<form action="<c:url value='/system/Profile'/>"  method="POST" accept-charset="ISO-8859-1"
      name="passwordchange" class="form-horizontal" role="form">
    <input type="hidden" name="token" value="<c:out value='${sessionScope.csrfToken}' />"/>
    <fieldset>
        <div class="form-group">
            <label for="user" class="col-md-2 control-label">User :</label>
            <div class="col-md-10">
                <input type="text" class="form-control" name="user" id="user" readonly="readonly" value="${sessionScope.user_name}"/>
            </div>
        </div>
        <div class="form-group">
            <label for="currentpassword" class="col-md-2 control-label">Current Password :</label>
            <div class="col-md-10">
                <input type="password" class="form-control" name="currentpassword" id="currentpassword"/>
            </div>
        </div>
        <div class="form-group">
            <label for="password1" class="col-md-2 control-label">New Password :</label>
            <div class="col-md-10">
                <input type="password" class="form-control" name="password1" id="password1"/>
            </div>
        </div>
        <div class="form-group">
            <label for="password2" class="col-md-2 control-label">Re-type New :</label>
            <div class="col-md-10">
                <input type="password" class="form-control" name="password2" id="password2"/>
            </div>
        </div>
        <div class="row">
            <div class="col-md-offset-2 col-md-10">
                <button type="submit" class="btn btn-primary">Update login password</button>
            </div>
        </div>
    </fieldset>
</form>


<div class="spacer">&nbsp;</div>
<div class="row">
    <div class="col-md-12">Please enter your old and new password to change your login details. <c:out value="${requestScope.control_text}" /></div>
</div>

</body>
</html>