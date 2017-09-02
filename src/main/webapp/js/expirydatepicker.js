/*
 * Copyright (c)2003-2014 Funky Android Ltd., All Rights Reserved
 *
 * Redistribution of this source code or any compiled form of it is prohibited
 * except where allowed by a written agreement with Funky Android Ltd.
 */

if (top.location != location) {
    top.location.href = document.location.href ;
}
$(function(){
    window.prettyPrint && prettyPrint();
    $('#expiryDate').datepicker({
        format: 'dd-mmm-yyyy'
    });
});
