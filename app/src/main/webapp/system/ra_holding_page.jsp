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
    <meta http-equiv="refresh" content="20;url=<c:url value='${requestScope.ra_refresh_url}'/>&amp;otid=${requestScope.nextOtid}">
    <title>Awaiting restricted access approval</title>
</head>
<body>
<div class="row">
    <div class="col-md-12">
        <h4>Request Awaiting Approval</h4>
        <p>Your attempt to view the password is awaiting approval. This page should refresh approximately every 20
            seconds, and when you have been granted access the password will be displayed. If you wish to discuss
            this request with the relevant restricted access approvers please quote the ID ${requestScope.rarId}.</p>
        <p>If this page does not refresh please <a href="<c:url value='${requestScope.ra_refresh_url}'/>&amp;otid=${requestScope.nextOtid}">click here</a> to check if
            your request has been approved.</p>
        <p>Last refresh : <i>${requestScope.ra_last_refresh}</i></p>
    </div>
</div>
</body>
</html>