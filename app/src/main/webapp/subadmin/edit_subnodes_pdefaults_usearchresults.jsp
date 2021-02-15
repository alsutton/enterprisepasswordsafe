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
<table class="table">
    <tbody class="table-striped">
        <c:forEach var="thisPermission" items="${requestScope.results}" varStatus="status">
            <tr>
                <td><c:out value="${thisPermission.user.name}"/></td>
                <td>
                    <jsp:include page="/WEB-INF/includes/modify_read_default_selector.jsp">
                        <jsp:param name="input_name" value="gperm_${thisPermission.user.id}" />
                        <jsp:param name="input_value" value="${thisPermission.permission}"/>
                    </jsp:include>
                </td>
            </tr>
        </c:forEach>
    </tbody>
</table>
