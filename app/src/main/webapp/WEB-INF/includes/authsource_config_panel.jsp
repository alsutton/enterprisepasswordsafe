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

<div class="form-group">
  <label class="col-md-4 control-label" for="name">Source Name</label>
  <div class="col-md-8">
      <input type="text" name="name" id="name" value="<c:out value='${requestScope.name}'/>" class="form-control" />
  </div>
</div>

<div class="spacer">&nbsp;</div>

<c:forEach var="thisParameter" items="${requestScope.parameters}">
    <div class="form-group">
        <label class="col-md-4 control-label" for="auth_<c:out value='${thisParameter.internalName}'/>"><c:out value="${thisParameter.displayName}"/></label>
        <div class="col-md-8"><c:choose>
            <c:when test="${thisParameter.optionType == 't'}">
                <input	type="text"
                        class="form-control"
                        name="auth_<c:out value='${thisParameter.internalName}'/>"
                        id="auth_<c:out value='${thisParameter.internalName}'/>"
                        value="<c:out value='${thisParameter.value}'/>"/>
            </c:when>
            <c:when test="${thisParameter.optionType == 'p'}">
                <input	type="password"
                        class="form-control"
                        name="auth_<c:out value='${thisParameter.internalName}'/>"
                        id="auth_<c:out value='${thisParameter.internalName}'/>"
                        value="<c:out value='${thisParameter.value}'/>"/>
            </c:when>
            <c:when test="${thisParameter.optionType == 'r'}">
                <jsp:include page="/WEB-INF/includes/yes_no_radio.jsp">
                    <jsp:param name="input_name" value="auth_${thisParameter.internalName}" />
                    <jsp:param name="input_value" value="${thisParameter.value}" />
                </jsp:include>
            </c:when>
        </c:choose>
        </div>
    </div>
</c:forEach>

<div class="spacer">&nbsp;</div>

<div class="row">
    <div class="col-md-12">
        <c:out value="${requestScope.notes}"/>
    </div>
</div>

<div class="spacer">&nbsp;</div>

<div class="form-group">
    <div class="col-md-offset-4 col-md-8">
        <button type="submit" class="btn btn-primary">Store configuration</button>
    </div>
</div>

<input type="hidden" name="type" value="<c:out value='${requestScope.type}'/>"/>

<c:if test="${not empty requestScope.id}">
    <input type="hidden" name="id" value="${requestScope.id}'/>"/>
</c:if>

