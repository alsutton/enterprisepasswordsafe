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
<head><title>Edit network zone</title></head>
<body>
<form action="<c:url value='/admin/StoreIPZone' />" method="POST" name="editzone"
      accept-charset="utf-8" role="form">
    <fieldset>
        <input type="hidden" name="zoneid" value="${ipzone.id}">

        <div class="form-group">
            <label for="zonename">Zone Name :</label>
            <input type="text" size="40" name="zonename" id="zonename" class="form-control"
                   value="<c:out value='${ipzone.name}' />"/>
        </div>

        <c:choose>
            <c:when test="${ipzone.ipVersion == 4}">
                <c:set var="ip4_selected" value="selected=\"selected\""/>
            </c:when>
            <c:otherwise>
                <c:set var="ip6_selected" value="selected=\"selected\""/>
            </c:otherwise>
        </c:choose>

        <div class="form-group">
            <label for="ip.version">Zone Type :</label>
            <select id="ip.version" name="ip.version" class="form-control">
                <option value="4" ${ip4_selected}>IP v4</option>
                <option value="6" ${ip6_selected}>IP v6</option>
            </select>
        </div>

        <div class="form-group">
            <label for="start">Start Address :</label>
            <input type="text" size="40" name="start" id="start" class="form-control" value="${ipzone.startIpText}" />
        </div>
        <div class="form-group">
            <label for="end">End Address :</label>
            <input type="text" size="40" name="end" id="end" class="form-control" value="${ipzone.endIpText}" />
        </div>

        <button type="submit" class="btn btn-primary">Update Zone</button>
    </fieldset>
</form>

</body>
</html>
