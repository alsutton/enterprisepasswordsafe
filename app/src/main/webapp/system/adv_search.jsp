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
<head><title>Password Search</title></head>
<body>
<form action="<c:url value='/system/Search'/>"  method="POST" accept-charset="ISO-8859-1"
        class="form-horizontal" role="form" name="search_form">
<fieldset>
    <div class="form-group">
        <label for="username" class="col-md-2 control-label">Username :</label>
        <div class="col-md-10">
            <input type="text" class="form-control" name="username" id="username" value="<c:out value='${requestScope.username}' />" />
        </div>
    </div>

    <div class="form-group">
        <label for="system" class="col-md-2 control-label">System :</label>
        <div class="col-md-10">
            <input type="text" class="form-control" name="system" id="system" value="<c:out value='${requestScope.system}' />"/>
        </div>
    </div>

    <div class="form-group">
        <label for="notes" class="col-md-2 control-label">Notes :</label>
        <div class="col-md-10">
            <input type="text" class="form-control" name="notes" id="notes" value="<c:out value='${requestScope.notes}' />"/>
        </div>
    </div>

    <div class="form-group">
         <div class="col-md-offset-2 col-md-10">
             <c:if test="${not empty requestScope.searchAll}">
                 <c:set var="search_all_checked" value="checked=\"checked\"" />
             </c:if>
             <div class="checkbox">
                 <label>
                     <input type="checkbox" name="searchAll" ${search_all_checked} />
                     Search from Top Level
                 </label>
             </div>
         </div>
    </div>

    <div class="row">
        <div class="col-md-offset-2 col-md-10">
            <button type="submit" class="btn btn-primary">Search</button>
        </div>
    </div>
</fieldset>
</form>

<c:if test="${not empty requestScope.passwordmap}">
    <hr />
    <div class="row">
        <div class="col-md-12">Number of matches : <c:out value="${requestScope.resultcount}"/></div>
    </div>

    <ul>
        <c:forEach var="thisLocation" items="${requestScope.passwordmap}">
            <c:forEach var="thisPassword" items="${thisLocation.value}">
                <c:url var="viewLink" value="/system/ViewPassword">
                    <c:param name="id" value="${thisPassword.id}"/>
                    <c:param name="otid" value="${requestScope.nextOtid}"/>
                </c:url>
                <c:url var="explorerLink" value="/system/Explorer">
                    <c:param name="nodeId" value="${thisLocation.key.id}"/>
                </c:url>
                <li>
                    <a href="${viewLink}"><c:out value="${thisPassword}"/></a>
                    &nbsp;in&nbsp;
                    <a href="${explorerLink}"><c:out value="${thisLocation.key.parentage}"/></a>
                </li>
            </c:forEach>
        </c:forEach>
    </ul>
</c:if>
</body>
</html>