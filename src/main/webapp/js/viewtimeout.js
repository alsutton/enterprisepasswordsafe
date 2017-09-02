/*
 * Copyright (c)2003-2014 Funky Android Ltd., All Rights Reserved
 *
 * Redistribution of this source code or any compiled form of it is prohibited
 * except where allowed by a written agreement with Funky Android Ltd.
 */

function bounceViewer() {
    window.location = '../system/Explorer';
}

var timeout = $('#timeout').text();
$(document).ready(function() {
    setInterval(bounceViewer, timeout);
});
