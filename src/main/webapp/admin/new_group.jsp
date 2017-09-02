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
<head>
    <title>Create Group</title>
</head>
<body>

<div class="row">
    <div class="col-md-12">Please enter the name of the group you wish to create.</div>
</div>

<form action="<c:url value='/admin/CreateNewGroup'/>" method="POST" accept-charset="ISO-8859-1" name="newgroupdetails"
      class="form-horizontal">
    <fieldset>
        <div class="form-group">
            <label for="groupname">Group Name</label>
            <input type="text" name="groupname" id="groupname" class="form-control" />
        </div>
        <button type="submit" class="btn btn-primary">Create</button>
    </fieldset>
</form>
</body>
</html>
