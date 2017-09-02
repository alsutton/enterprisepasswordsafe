/*
 * Copyright (c)2003-2014 Funky Android Ltd., All Rights Reserved
 *
 * Redistribution of this source code or any compiled form of it is prohibited
 * except where allowed by a written agreement with Funky Android Ltd.
 */

$(function() {
    $( "#startdate" ).datepicker();
    $( "#startdate" ).datepicker( "option", "dateFormat", "d M, yy");
    $( "#enddate" ).datepicker();
    $( "#enddate" ).datepicker( "option", "dateFormat", "d M, yy");
});
