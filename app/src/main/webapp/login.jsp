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
<title>EPS: Login</title>
</head>
<body>
<jsp:useBean id="userId" scope="session" class="java.lang.String"/>
<c:if test="${not empty userId}">
<div class="alert alert-danger">
    <a class="close" href="#">x</a><strong>WARNING: You appear to be already logged in. Logging in again will change all sessions you have open in this browser.</strong>
</div>
</c:if>

<p>&nbsp;</p>
<p>&nbsp;</p>
<p>&nbsp;</p>
<form class="form-signin" name="logindetails" action="<c:url value='/VerifyLogin'/>" method="POST" accept-charset="UTF-8">
    <label for="username"></label>
    <input type="text" id="username" name="username" class="form-control" placeholder="Username"/>
    <label for="password"></label>
    <input type="password" id="password" name="password" class="form-control" placeholder="Password"/>
    <button type="submit" class="btn btn-lg btn-primary btn-block">Login</button>
</form>

</body>
