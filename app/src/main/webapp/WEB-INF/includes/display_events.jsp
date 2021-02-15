<%@ page language="java" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
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
<div class="spacer">&nbsp;</div>
<c:choose>
	<c:when test="${empty requestScope.events}">
        <div class="row">
            <div class="col-md-12 text-center">
                <c:choose>
                    <c:when test="${requestScope.isNotQuery}">
                        <p>Please select the criteria for your search.</p>
                    </c:when>
                    <c:otherwise>
                        <p>There are no events for the given criteria</p>
                    </c:otherwise>
                </c:choose>
            </div>
        </div>
	</c:when>
	<c:otherwise>
		<c:forEach var="eventsForDay" items="${requestScope.events}">
            <div class="row">
                <div class="col-md-12">
                    <h3><fmt:formatDate pattern="dd-MMM-yyyy" value="${thisEvent.date}" /></h3>
                </div>
            </div>
            <c:forEach var="thisEvent" items="${pageScope.eventsForDay.events}" varStatus="status">
                <div class="row alternatingRow${status.index % 2}">
                    <div class="col-md-1">
                        <fmt:formatDate pattern="HH:mm:ss" value="${thisEvent.date}" />
                    </div>
                    <div class="col-md-2">
                        <c:choose>
                            <c:when test="${empty thisEvent.username}"><i>Unknown</i></c:when>
                            <c:otherwise><c:out value="${thisEvent.username}" /></c:otherwise>
                        </c:choose>
                    </div>
                    <div class="col-md-3">
                        <c:if test="${not empty thisEvent.itemId}">
                            <c:choose>
                                <c:when test="${thisEvent.historyStored}">
                                    <c:url var="historyLink" value="/system/ViewPassword">
                                        <c:param name="id" value="${thisEvent.itemId}"/>
                                        <c:param name="dt" value="${thisEvent.dateTime}"/>
                                        <c:param name="otid" value="${requestScope.nextOtid}"/>
                                    </c:url>
                                    <a href="${historyLink}"><c:out value="${thisEvent.item}" /></a>
                                </c:when>
                                <c:otherwise>
                                    <c:out value="${thisEvent.item}" />
                                </c:otherwise>
                            </c:choose>
                        </c:if>
                    </div>
                    <div class="col-md-5">
                        <c:out value="${thisEvent.humanReadableMessage}" />
                    </div>
                    <div class="col-md-1">
                        <c:choose>
                            <c:when test="${thisEvent.tamperstampStatus == -1}"><c:set var="tamperstampClass" value="tamperstampUnknown" /></c:when>
                            <c:when test="${thisEvent.tamperstampStatus == 0}"><c:set var="tamperstampClass" value="tamperstampOk" /></c:when>
                            <c:when test="${thisEvent.tamperstampStatus == 1}"><c:set var="tamperstampClass" value="tamperstampBad" /></c:when>
                        </c:choose>
                        <div class="${tamperstampClass}"><span class="glyphicon glyphicon-link"></span></div>
                    </div>
                </div>
            </c:forEach>
        </c:forEach>
	</c:otherwise>
</c:choose>
