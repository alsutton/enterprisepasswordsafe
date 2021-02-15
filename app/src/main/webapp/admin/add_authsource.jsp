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
<head><title>Add authentication source</title></head>
<body>

<div class="row">
    <div class="col-md-12"><h4>Select external authentication system type</h4></div>
</div>

<div class="spacer">&nbsp;</div>

<div class="row">
    <c:url var="link" value="/admin/AddAuthSourceStage2">
        <c:param name="type" value="AD_DOMAIN"/>
    </c:url>
    <a href="${link}" class="btn btn-default col-md-4 col-md-offset-4">Active Directory (using Domains)</a>
</div>

<div class="spacer">&nbsp;</div>

<div class="row">
    <c:url var="link" value="/admin/AddAuthSourceStage2">
        <c:param name="type" value="LDAPBind"/>
    </c:url>
    <a href="${link}" class="btn btn-default col-md-4 col-md-offset-4">Bind-Only LDAP</a>
</div>

<div class="spacer">&nbsp;</div>

<div class="row">
    <c:url var="link" value="/admin/AddAuthSourceStage2">
        <c:param name="type" value="LDAPSandB"/>
    </c:url>
    <a href="${link}" class="btn btn-default col-md-4 col-md-offset-4">Search and Bind LDAP</a>
</div>

<div class="spacer">&nbsp;</div>

<c:if test="${hasJndiLoginModule}">
    <div class="row">
        <c:url var="link" value="/admin/AddAuthSourceStage2">
                <c:param name="type" value="RFC2307"/>
        </c:url>
        <a href="${link}" class="btn btn-default col-md-4 col-md-offset-4">RFC2307 LDAP</a>
    </div>
</c:if>

</body>
</html>
