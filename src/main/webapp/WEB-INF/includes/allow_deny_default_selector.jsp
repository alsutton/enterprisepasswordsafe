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
<c:set var="input_value"   value="${param.input_value}" />

<c:choose>
    <c:when test="${input_value == 0}">
        <c:set var="zeroChecked" value="checked=\"checked\""/>
    </c:when>
    <c:when test="${input_value == 1}">
        <c:set var="oneChecked" value="checked=\"checked\""/>
    </c:when>
    <c:when test="${input_value == 2}">
        <c:set var="twoChecked" value="checked=\"checked\""/>
    </c:when>
</c:choose>
<input type="radio" id="${input_name}_2" name="${input_name}" value="2" ${twoChecked} />&nbsp;<label for="${input_name}_2">Allow</label>&nbsp;
<input type="radio" id="${input_name}_1" name="${input_name}" value="1" ${oneChecked} />&nbsp;<label for="${input_name}_1">Deny</label>&nbsp;
<input type="radio" id="${input_name}_0" name="${input_name}" value="0" ${zeroChecked} />&nbsp;<label for="${input_name}_0">Default</label>
