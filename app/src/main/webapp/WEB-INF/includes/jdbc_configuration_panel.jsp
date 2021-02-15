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
    <tbody>
        <tr>
            <td aling="right">Database Type</td>
            <td><c:out value='${requestScope.jdbcConfig.dbType}' default='[Not Set]'/></td>
        </tr>

        <tr>
            <td colspan="2" aling="center">
            You will need to ensure that the JDBC drivers for your database have been correctly
            installed before the EPS will be able to talk to the database.
            </td>
        </tr>

        <tr>
            <td aling="right">JDBC Driver</td>
            <td><c:out value='${requestScope.jdbcConfig.driver}' default='[Not Set]'/></td>
        </tr>

        <tr>
            <td aling="right">JDBC URL</td>
            <td><c:out value='${requestScope.jdbcConfig.url}' default='[Not Set]'/></td>
        </tr>

        <tr>
            <td aling="right">Database Username</td>
            <td><c:out value='${requestScope.jdbcConfig.username}' default='[Not Set]' /></td>
        </tr>

        <tr>
            <td aling="right">Database Password</td>
            <td>
                <c:choose>
                    <c:when test="${(requestScope.jdbcConfig != null) && (requestScope.jdbcConfig.password != null)}">************</c:when>
                    <c:otherwise>[Not Set]</c:otherwise>
                </c:choose>
            </td>
        </tr>
    </tbody>
</table>
