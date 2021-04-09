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
<head><title>Confirm Script Removal</title></head>
<body>
<div class="row">
    <div class="col-md-12">
        The module you are uninstalling is in use. Please confirm you wish to remove it and all <br/>
        configuration module associated with it.
    </div>
</div>

<form action="<c:url value='/admin/DeleteIMScriptStage2'/>" method="POST"
      accept-charset="ISO-8859-1" role="form">
    <fieldset>
        <input type="hidden" name="scriptid" value="<c:out value='${requestScope.scriptid}'/>"/>
        <button type="submit" class="btn btn-primary">Confirm</button>
    </fieldset>
</form>
</body>
</html>
