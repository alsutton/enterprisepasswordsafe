<!DOCTYPE html>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://www.opensymphony.com/sitemesh/decorator" prefix="decorator" %>
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
<%
    response.setHeader("Cache-Control", "no-cache"); //HTTP 1.1
    response.setHeader("Pragma", "no-cache"); //HTTP 1.0
    response.setHeader("Expires", "0"); //prevents caching at the proxy server
%>
<html lang="en">
<head>
    <link rel="StyleSheet" href="<c:url value='/css/bootstrap.min.css'/>" type="text/css">
    <link rel="StyleSheet" href="<c:url value='/css/bootstrap-theme.min.css'/>" type="text/css">
    <link rel="StyleSheet" href="<c:url value='/css/eps.css'/>" type="text/css">
    <script src="<c:url value='/js/jquery-1.11.1.min.js'/>"></script>

    <decorator:head/>
    <title>EPS : <decorator:title/></title>
</head>
<body onunload="">
<div id="wrap">
    <div class="navbar navbar-default navbar-fixed-top">
        <div class="container">
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="<c:url value='/'/>">Enterprise Password Safe</a>
            </div>
            <div class="navbar-collapse collapse">
                <ul class="nav navbar-nav">
                    <li><a href="<c:url value='/Logout'/>">Logout</a></li>
                </ul>
            </div>
        </div>
    </div>
    <div class="container" id="maincontent">
        <div class="row">
            <div class="col-md-12">
                <div class="alert alert-danger text-center">This is a development version of the EPS and may contain
                    bugs, unfinished features, and an incomplete user interface
                </div>
            </div>
        </div>

        <c:if test="${not empty sessionScope.error}">
            <div class="alert alert-danger text-center">
                <button type="button" class="close" aria-hidden="true">&times;</button>
                <span id="errormessage"><strong><c:out value="${sessionScope.error}"/></strong></span>
            </div>
        </c:if>

        <c:if test="${not empty sessionScope.message}">
            <div class="alert alert-success text-center">
                <button type="button" class="close" aria-hidden="true">&times;</button>
                <span id="statusmessage"><strong><c:out value="${sessionScope.message}"/></strong></span>
            </div>
        </c:if>

        <div class="row">
            <div class="col-md-12"><h2><decorator:title/></h2></div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <decorator:body/>
                <div class="spacer">&nbsp;</div>
            </div>
        </div>
    </div>
</div>
<div id="footer">
    <div class="container text-center">
        <p class="text-muted credit">The Enterprise Password Safe is <a
                href="https://github.com/carbonsecurity/enterprisepasswordsafe" target="_blank">Open Source Software</a>.</p>
    </div>
</div>
<c:remove var="error" scope="session"/>
<c:remove var="message" scope="session"/>

<script src="<c:url value='/js/bootstrap.min.js'/>"></script>
</body>
</html>
