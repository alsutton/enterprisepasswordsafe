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
<head><title>Import Users</title></head>
<body>

<div class="row">
    <div class="col-md-12">
        <p>The import file should contain one user per line with the information represented the following format;</p>

        <pre>Username, Full Name, Email<i>, User Type, Password</i></pre>

        <p>Where;</p>

        <dl class="dl-horizontal">
            <dt>Username</dt>
            <dd>The username for the user to log in with.</dd>
            <dt>Full Name</dt>
            <dd>The full name for the user.</dd>
            <dt>Email</dt>
            <dd>The email address for the user.</dd>
            <dt>User Type (optional)</dt>
            <dd>One of the following; <code>N</code> for Normal, <code>P</code> for Password Administrator, <code>E</code> for EPS Administrator.</dd>
            <dt>Password (optional)</dt>
            <dd>The users login password. If a password is not specified, one will be created</dd>
        </dl>

        <p>For example the following entry;</p>
        <pre>user1, A new user, user@myco.com, P, 1234</pre>
        <p>Would create a new password administrator level user with the username <i>user1</i>, the full name
            <i>A new user</i>, the email address <i>user@myco.com</i> and their login password would be
            <i>1234</i></p>
    </div>
</div>

<form action="<c:url value='/admin/ImportUsers'/>" name="importform" method="post"
      enctype="multipart/form-data" role="form">
    <fieldset>
        <div class="form-group">
            <label for="file">File To Import</label>
            <input name="file" type="file" id="file"/>
        </div>
        <button type="submit" class="btn btn-primary">Import</button>
    </fieldset>
</form>
</body>
</html>
