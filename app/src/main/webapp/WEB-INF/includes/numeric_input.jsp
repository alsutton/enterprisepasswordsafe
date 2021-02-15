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

<c:set var="input_name" value="${param.input_name}" />
<label for="${input_name}" class="col-md-4 control-label"><c:out value="${param.input_label}" /></label>
<div class="col-md-8">
    <c:choose>
        <c:when test="${empty param.input_value}">
            <c:choose>
                <c:when test="${empty param.default_value}"><c:set var="input_value" value="0" /></c:when>
                <c:otherwise><c:set var="input_value" value="${param.default_value}" /></c:otherwise>
            </c:choose>
        </c:when>
        <c:otherwise>
            <c:set var="input_value" value="${param.input_value}" />
        </c:otherwise>
    </c:choose>
    <input type="number"  name="${input_name}" id="${input_name}" class="form-control" value="${input_value}" />
</div>
