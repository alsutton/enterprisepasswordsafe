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

<li class="dropdown">
    <a href="#" class="dropdown-toggle" data-toggle="dropdown">Passwords <b class="caret"></b></a>
    <ul class="dropdown-menu">
        <li><a href="<c:url value='/system/Explorer'/>">View/Edit</a></li>
        <li><a href="<c:url value='/system/Search'/>">Search</a></li>
        <li><a href="<c:url value='/system/ExpiringPasswords'/>">Expiring</a></li>
        <li><a href="<c:url value='/system/ViewPersonalFolder'/>">Personal</a></li>
        <li><a href="<c:url value='/system/ViewRARequests'/>">RA Requests</a></li>
        <li><a href="<c:url value='/system/CreatePassword'/>">Create</a></li>
        <li><a href="<c:url value='/subadmin/ImportPasswordFile'/>">Import</a></li>
        <li><a href="<c:url value='/admin/PasswordRestrictions'/>">Types</a></li>
        <li class="divider"></li>
        <li class="dropdown-header">Reports</li>
        <li><a href="<c:url value='/admin/ViewEvents'/>">Event Log</a></li>
        <li><a href="<c:url value='/admin/Passwords.csv'/>" target="_blank">All Passwords</a></li>
        <li><a href="<c:url value='/admin/UserAccess.csv'/>" target="_blank">User Access</a></li>
    </ul>
</li>

<li class="dropdown">
    <a href="#" class="dropdown-toggle" data-toggle="dropdown">System <b class="caret"></b></a>
    <ul class="dropdown-menu">
        <li><a href="<c:url value='/admin/ViewUsers'/>">Users</a></li>
        <li><a href="<c:url value='/admin/ViewGroups'/>">Groups</a></li>
        <li class="divider"></li>
        <li><a href="<c:url value='/admin/ViewSystem'/>">About This Installation</a></li>
        <li><a href="<c:url value='/admin/CustomFields'/>">Custom Fields</a></li>
        <li><a href="<c:url value='/admin/Configure'/>">Configuration</a></li>
        <li><a href="<c:url value='/admin/SetupJDBCConfiguration'/>">Database</a></li>
        <li><a href="<c:url value='/admin/ConfigureEmail'/>">Event Log Settings</a></li>
        <li><a href="<c:url value='/admin/AuthSources'/>">External Authentication</a></li>
        <li><a href="<c:url value='/admin/IntegrationModules'/>">Integration Modules</a></li>
        <li><a href="<c:url value='/admin/EditIPZones'/>">Network Zones</a></li>
    </ul>
</li>
