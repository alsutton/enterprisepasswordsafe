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
<head><title>Script Editor</title></head>
<body>

<div class="row">
    <div class="col-md-12">This is a script for the module &quot;<c:out value='${requestScope.module.name}'/>&quot;</div>
</div>

<form name="editForm"  method="POST" accept-charset="ISO-8859-1" action="<c:url value='/admin/StoreIMScript'/>">
    <input	type="hidden" name="scriptid" value="${requestScope.scriptobj.id}" />

    <div class="form-group">
        <label for="name">Script Name :</label>
        <input id="name" name="name" type="text" size="40" value="<c:out value='${requestScope.scriptobj.name}'/>" />
    </div>

    <div class="spacer">&nbsp;</div>

    <div class="row">
        <div class="col-md-12"><h4>Module settings for this script</h4></div>
    </div>

    <c:forEach var="thisProperty" items="${requestScope.properties}">
        <div class="form-group">
            <label  for="mc_<c:out value='${thisProperty.internalName}'/>"><c:out value="${thisProperty.displayName}"/> :</label>
            <input  type="text"
                    id="mc_<c:out value='${thisProperty.internalName}'/>"
                    name="mc_<c:out value='${thisProperty.internalName}'/>"
                    value="<c:out value='${thisProperty.currentValue}'/>"/>
        </div>
    </c:forEach>

    <div class="form-group">
        <label  for="script">Script :</label>
        <textarea name="script" id="script" cols="60" rows="15"><c:out value="${requestScope.scriptobj.script}"/></textarea>
    </div>

    <div class="form-group">
        <button type="submit">Store Script</button>
    </div>
</form>
</body>
</html>
