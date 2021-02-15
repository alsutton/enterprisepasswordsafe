/*
 * Copyright (c)2003-2014 Funky Android Ltd., All Rights Reserved
 *
 * Redistribution of this source code or any compiled form of it is prohibited
 * except where allowed by a written agreement with Funky Android Ltd.
 */

$("#generatorButton").click(function() {
    var selectedIdx = $( "select#restriction_id" ).val();
    $.ajax({
        url : "../support/PasswordGenerator?rid="+selectedIdx,
        success :
            function(data)
            {
                $('#generatedPassword').text(data);
                $('#generatorModal').modal('show');
            }
    });
});

$("#useGeneratedPassword").click(function() {
    var newPassword = $('#generatedPassword').text();
    $('#password_1').val(newPassword);
    $('#password_2').val(newPassword);

    $('#generatorModal').modal('hide');
});