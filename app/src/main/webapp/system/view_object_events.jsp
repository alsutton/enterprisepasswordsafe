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
<title>View Events</title>
</head>
<body>
<form action="<c:url value='/system/ViewObjectEvents' />"  method="POST" accept-charset="ISO-8859-1"
        class="form-inline" role="form">
    <input type="hidden" name="id" value="${requestScope.id}"/>
    <div class="form-group">
        <label class="sr-only" for="startdate">Dates :</label>
        <input type="text" name="startdate" id="startdate" />
    </div>
    <div class="form-group">
        <label class="sr-only" for="enddate">&nbsp;to&nbsp;</label>
        <input type="text" name="enddate" id="enddate" />
    </div>
</form>

<jsp:include page="/WEB-INF/includes/display_events.jsp" />
<script type="text/javascript" src="<c:url value='/js/eventviewer.js'/>"></script>
</body>
</html>