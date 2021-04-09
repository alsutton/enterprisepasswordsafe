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
    <label for="name">Name</label>
    <input type="text" name="name" id="name"
           class="form-control" value="<c:out value='${requestScope.permission.name}'/>" />
</div>
<div class="form-group">
    <label for="size_min">Minimum Length</label>
    <input type="text" name="size_min" id="size_min"
           class="form-control" value="<c:out value='${requestScope.permission.minLength}' default='8'/>" />
</div>
<div class="form-group">
    <label for="size_max">Maximum Length</label>
    <input type="text" name="size_max" id="size_max"
           class="form-control" value="<c:out value='${requestScope.permission.maxLength}' default='20'/>"/>
</div>
<div class="form-group">
    <label for="upper_min">Upper case letters</label>
    <input type="text" name="upper_min" id="upper_min"
           class="form-control" value="<c:out value='${requestScope.permission.minUpper}' default='0'/>"/>
</div>
<div class="form-group">
    <label for="lower_min">Lower case letters</label>
    <input type="text" name="lower_min" id="lower_min"
           class="form-control" value="<c:out value='${requestScope.permission.minLower}' default='0'/>"/>
</div>
<div class="form-group">
    <label for="numeric_min">Numerics</label>
    <input type="text" name="numeric_min" id="numeric_min"
           class="form-control" value="<c:out value='${requestScope.permission.minNumeric}' default='0'/>"/>
</div>
<div class="form-group">
    <label for="special_min">Non-alphanumeric characters</label>
    <input type="text" name="special_min" id="special_min"
           class="form-control" value="<c:out value='${requestScope.permission.minSpecial}' default='0'/>"/>
</div>
<div class="form-group">
    <label for="chars_special">Non-alphanumeric characters to use</label>
    <input type="text" name="chars_special" id="chars_special"
           class="form-control" value="<c:out value='${requestScope.permission.specialCharacters}' default='#!&.'/>"/>
</div>
<div class="form-group">
    <label for="lifetime">Default validity period<br/><i>(days, 0 means non-expiring)</i></label>
    <input type="text" name="lifetime" id="lifetime"
           class="form-control" value="<c:out value='${requestScope.permission.lifetime}' default='0'/>"/>
</div>
