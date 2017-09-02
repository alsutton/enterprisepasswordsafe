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
<head><title>Import Groups</title></head>
<body>
<div class="row">
    <div class="col-md-12">
        <p>The import file should contain one group per line with the group name followed by
            a comma (,) then each user to be part of the group separated by a comma.</p>

        <p>For example the following entry;</p>
        <pre>group1, user1, user2, user3</pre>
        <p>Would create a group with the name <i>group1</i>, and the users <i>user1</i>, <i>user2</i>, and
            <i>user3</i> would be made members of the new group.</p>
    </div>
</div>

<form action="<c:url value='/admin/ImportGroups'/>" method="post" name="importform"
      enctype="multipart/form-data" role="form">
    <fieldset>
        <div class="form-group">
            <label for="file">File To Import</label>
            <input name="file" type="file" id="file"/>
        </div>
        <button type="submit" class="btn btn-primary">Import</button>
    </fieldset>
</form>
</body>
</html>
