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
<title>EPS: Synchronize Passwords</title>
</head>
<body>

<div class="row">
    <div class="col-md-12">
        <h3>Synchronize Passwords</h3>
    </div>
</div>

<div class="row">
    <div class="col-md-12">
        <p>Your EPS password is different from the password stored in the remote system your EPS
            administrator has configured the EPS to check against. Please enter your EPS password
            and your external login password to synchronize the two.</p>
        <p>If you have changed your desktop login password recently you may find your EPS password is your
            old desktop password and your Login password is your new desktop password. If you are a new user
            your EPS password will be given to you by your system administrator, security administrator,
            or help desk.</p>
    </div>
</div>

<div class="spacer">&nbsp;</div>

<form action="<c:url value='/SyncPasswords'/>" method="POST" accept-charset="ISO-8859-1" role="form" class="form-horizontal">
    <input type="hidden" name="userId" value="${requestScope.userId}">

    <div class="form-group">
        <label for="internalPassword" class="col-md-4 control-label">EPS Password</label>
        <div class="col-md-8">
            <input type="password" id="internalPassword" class="form-control" name="internalpass" size="30" />
        </div>
    </div>

    <div class="spacer">&nbsp;</div>

    <div class="form-group">
        <label for="externalPassword" class="col-md-4 control-label">External Password</label>
        <div class="col-md-8">
            <input type="password" id="externalPassword" class="form-control" name="externalpass" size="30" />
        </div>
    </div>

    <div class="spacer">&nbsp;</div>

    <div class="row">
        <div class="col-md-offset-4">
            <button type="submit" class="btn btn-primary">Synchronize</button>
        </div>
    </div>
</form>
</body>
