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
<head><title>Restricted access password - Enter reason for viewing</title></head>
<body>
<div class="row">
    <div class="col-md-12">
        <h4>Restricted Access Password</h4>
    </div>
</div>

<div class="row">
    <div class="col-md-12">
        <p>The password you have attempted to view requires the approval of one or more other users.</p>
        <p>Please enter your reason for viewing the password (your reason will be distributed to users
            who can approve your request to the view the password).</p>
    </div>
</div>

<form action="<c:url value='/system/ViewRAPassword'/>" method="POST"
      accept-charset="ISO-8859-1" name="rareason" class="form-horizontal" role="form">
    <input	type="hidden" name="id" value="${requestScope.id}">
    <input	type="hidden" name="otid" value="${requestScope.nextOtid}">

    <div class="form-group">
        <label for="reason" class="col-md-2 control-label">Reason for access :</label>
        <div class="col-md-10">
            <textarea class="form-control" id="reason" name="reason" rows="10"></textarea>
        </div>
    </div>
    <div class="row">
        <div class="col-md-10 col-md-offset-2">
            <button type="submit" class="btn btn-primary">Continue...</button>
        </div>
    </div>
</form>
</body>
</html>