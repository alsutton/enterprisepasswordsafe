/*
 * Copyright (c)2003-2014 Funky Android Ltd., All Rights Reserved
 *
 * Redistribution of this source code or any compiled form of it is prohibited
 * except where allowed by a written agreement with Funky Android Ltd.
 */

var jdbcDrivers = [
    "org.apache.derby.jdbc.EmbeddedDriver",
    "com.ibm.db2.jcc.DB2Driver",
    "com.mysql.jdbc.Driver",
    "oracle.jdbc.driver.OracleDriver",
    "org.postgresql.Driver",
    "com.microsoft.sqlserver.jdbc.SQLServerDriver",
    ""
];

var jdbcUrls = [
    "jdbc:derby:[DATABASE_NAME]",
    "jdbc:db2://[MACHINE_NAME]:[PORT]/[DATABASE_NAME]",
    "jdbc:mysql://[MACHINE_NAME]/[DATABASE_NAME]",
    "jdbc:oracle:thin:@[MACHINE_NAME]:[PORT]:[SCHEMA_NAME]",
    "jdbc:postgresql://[MACHINE_NAME]/[DATABASE_NAME]",
    "jdbc:sqlserver://[MACHINE_NAME];DatabaseName=[DATABASE_NAME]",
    ""
];

$(document).ready(function() {
    $('#database').change(function() {
        var selectedIdx = $( "select#database").prop('selectedIndex');
        $('#jdbcdriver').val(jdbcDrivers[selectedIdx]);
        $('#jdbcurl').val(jdbcUrls[selectedIdx]);
        $('#jdbcusername').val('');
        $('#jdbcpassword').val('');
        displayDriverWarningIfNecessary();
    })
    displayDriverWarningIfNecessary();
})

function displayDriverWarningIfNecessary() {
    var selectedIdx = $( "select#database").prop('selectedIndex');
    if(selectedIdx > 3) {
        $('#driver_install_warning').show();
    } else {
        $('#driver_install_warning').hide();
    }
}
