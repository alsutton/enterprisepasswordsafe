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
    <c:when test="${not empty param.parent_text}"><c:set var="default_text" value="${param.default_text}" /></c:when>
    <c:when test="${requestScope.node.nodeId eq '0'}"><c:set var="default_text" value="Default" /></c:when>
    <c:otherwise><c:set var="default_text" value="From Parent" /></c:otherwise>
</c:choose>
<c:set var="input_2_checked" value="" />
<c:set var="input_1_checked" value="" />
<c:set var="input_0_checked" value="" />
<c:choose>
    <c:when test="${input_value eq 'MODIFY'}"><c:set var="input_2_checked" value="checked=\"checked\"" /></c:when>
    <c:when test="${input_value eq 'READ'}"><c:set var="input_1_checked" value="checked=\"checked\"" /></c:when>
    <c:otherwise><c:set var="input_0_checked" value="checked=\"checked\"" /></c:otherwise>
</c:choose>

<input type="radio" name="${input_name}" id="${input_name}_2" value="2" ${input_2_checked} />&nbsp;<label for="${input_name}_2">Modify</label>&nbsp;
<input type="radio" name="${input_name}" id="${input_name}_1" value="1" ${input_1_checked} />&nbsp;<label for="${input_name}_1">Read</label>&nbsp;
<input type="radio" name="${input_name}" id="${input_name}_0" value="0" ${input_0_checked} />&nbsp;<label for="${input_name}_0">${default_text}</label>
