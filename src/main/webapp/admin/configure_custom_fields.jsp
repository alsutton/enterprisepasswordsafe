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
<head><title>Default custom fields</title></head>
<body>

<div class="row">
    <div class="col-md-12">
        <h3>Custom Fields</h3>
    </div>
</div>

<form action="<c:url value='/admin/StoreCustomFields'/>" name="customfields" 
		method="POST" accept-charset="ISO-8859-1" class="form-horizontal"
        role="form">
<fieldset>
    <c:choose>
        <c:when test="${empty requestScope.cfields}">
            <div class="row">
                <div class="col-md-12">
                    <i>No fields have been defined.</i>
                </div>
            </div>
            <div class="spacer">&nbsp;</div>
            <div class="form-group">
                <div class="col-md-offset-4 col-md-8">
                    <button type="submit" class="btn btn-primary" name="action" id="addButton" value="add">Add new field</button>
                </div>
            </div>
        </c:when>
        <c:otherwise>
            <div class="row">
                <div class="col-md-4 text-right">
                    <h6>Field Name</h6>
                </div>
                <div class="col-md-6">
                    <h6>Default Value</h6>
                </div>
                <div class="col-md-1">
                    <h6><span class="glyphicon glyphicon-trash"></span></h6>
                </div>
            </div>
            <c:forEach var="thisEntry" varStatus="status" items="${requestScope.cfields}">
                <label for="fn_${status.count - 1}"></label>
                <label for="fv_${status.count - 1}"></label>
                <div class="row">
                  <div class="col-md-4 text-right">
                      <input type="text" id="fn_${status.count - 1}" name="fn_${status.count - 1}" value="<c:out value='${thisEntry.key}'/>" class="form-control" />
                  </div>
                  <div class="col-md-6">
                      <input type="text" name="fv_${status.count - 1}" id="fv_${status.count - 1}" value="<c:out value='${thisEntry.value}'/>" class="form-control" />
                  </div>
                  <div class="col-md-1">
                      <label for="fdel_${status.count - 1}">
                      <input type="checkbox" id="fdel_${status.count - 1}" name="fdel_${status.count - 1}"/></label>
                  </div>
                </div>
            </c:forEach>

            <div class="spacer">&nbsp;</div>

            <div class="form-group">
                <div class="col-md-offset-4 col-md-8">
                    <button type="submit" class="btn btn-primary" name="action" id="addButton" value="add">Add new field</button>
                    <button type="submit" class="btn btn-primary" name="action" id="storeButton">Store &amp; Exit</button>
                    </div>
                </div>
        </c:otherwise>
    </c:choose>
</fieldset>
</form>
</body>
</html>
