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
<head><title>Integration Modules</title></head>
<body>
<div class="row">
    <div class="col-md-12">
        <a href="<c:url value='/admin/im_install_stage1.jsp'/>" class="btn btn-xs btn-default">Install new integration module</a>
    </div>
</div>

<c:choose>
	<c:when test="${empty requestScope.intmod_list}">
        <div class="row">
            <div class="col-md-12">
                No modules have been installed
            </div>
        </div>
	</c:when>
	<c:otherwise>
		<c:forEach var="thisModule" items="${requestScope.intmod_list}">
            <c:url var="uninstallLink" value="/admin/UninstallIntegrationModule">
                <c:param name="modid" value="${thisModule.id}"/>
            </c:url>
            <c:url var="scriptsLink" value="/admin/IntegrationModuleScripts">
                <c:param name="imid" value="${thisModule.id}"/>
            </c:url>
            <div class="row">
                <div class="col-md-12">
                    <a href="${uninstallLink}"><span class="glyphicon glyphicon-trash">&nbsp;</span></a>&nbsp;
                    <a href="${scriptsLink}"><span class="glyphicon glyphicon-list-alt">&nbsp;</span></a>&nbsp;
                    <c:out value="${thisModule.name}"/>
                </div>
            </div>
		</c:forEach>
	</c:otherwise>
</c:choose>
</body>
</html>
