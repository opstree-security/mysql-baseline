mysql_user  = attribute('mysqlUser', default: 'mysql', description: 'Name of mysql User')
mysql_password  = attribute('mysqlPassword', default: 'root', description: 'Password of mysql User')

control "mysql--log-error " do
    title "Ensure 'log_error' Is Enabled"
    desc "The error log contains information about events such as mysqld starting and stopping,
        when a table needs to be checked or repaired, and, depending on the host operating
        system, stack traces when mysqld fails."
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Open the MySQL configuration file ( my.cnf or my.ini ) and Set the log-error option to the path for the error log"
    ref 'Mysql Error Log', url: 'http://dev.mysql.com/doc/refman/5.6/en/error-log.html'
    describe mysql_session(mysql_user, mysql_password).query('SHOW variables LIKE \'log_error\';') do
        its('output') { should match(/var\/log\/mysql\/error.log/) }
      end
    end

control "mysql--log-warning " do
    title "Ensure 'log_warnings' Is Set to '2'"
    desc "The log_warnings system variable, enabled by default, provides additional information to
    the MySQL log. A value of 1 enables logging of warning messages, and higher integer values
    tend to enable more logging.
    This might help to detect malicious behavior by logging communication errors and aborted
    connections."
    impact 1.0
    tag Vulnerability: 'Low'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Open the MySQL configuration file ( my.cnf )
                Ensure the following line is found in the mysqld section
                i.e log-warnings = 2"
    ref 'Mysql log_warning levels', url: 'https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_log_warnings'
    describe mysql_session(mysql_user, mysql_password).query('SHOW GLOBAL VARIABLES LIKE \'log_warnings\';') do
        its('output') { should match(/2/) }
      end
    end

control "mysql--log-raw " do
    title "Ensure 'log-raw' Is Set to 'OFF'"
    desc "The log-raw MySQL option determines whether passwords are rewritten by the server so
    as not to appear in log files as plain text. If log-raw is enabled, then passwords are written
    to the various log files (general query log, slow query log, and binary log) in plain text."
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy: "Open the MySQL configuration file ( my.cnf )
        Find the log-raw entry and set it as follows
        log-raw = OFF"
    ref 'Mysql Log raw', url: 'http://dev.mysql.com/doc/refman/5.6/en/server-options.html#option_mysqld_log-raw'
    describe mysql_session(mysql_user, mysql_password).query('SHOW GLOBAL VARIABLES LIKE \'log_raw\';') do
        its('output') { should match(/OFF/) }
      end
    end

control "mysql--connection policy " do
    title "Ensure audit_log_connection_policy is not set to 'NONE'"
    desc "The audit_log_connection_policy offers three options: NONE , ERRORS , and ALL . Each
    option determines whether connection events are logged and the type of connection events
    that are logged. Setting a non 'NONE' value for audit_log_connection_policy ensures at a
    minimum, failed connection events are being logged. The ERRORS setting will log failed
    connection events and the ALL setting will log all connection events. For MySQL versions =>
    5.6.20, the audit_log_policy variable can override the audit_log_connection_policy ,
    potentially invalidating this benchmark recommendation, therefore enforcing a setting for
    audit_log_connection_policy ensures the integrity of this recommendation."
    impact 1.0
    tag Vulnerability: 'Low'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy: "To remediate this configuration setting, execute one of the following SQL statements:
    set global audit_log_connection_policy = ERRORS"
    ref 'Mysql Audit Log connection Policy', url: 'https://dev.mysql.com/doc/refman/5.6/en/audit-log-plugin-options-variables.html#sysvar_audit_log_connection_policy'
    describe mysql_session(mysql_user, mysql_password).query('show variables like \'%audit_log_connection_policy%\';') do
        its('output') { should_not match(/NONE/) }
      end
    end

control "mysql--log_exclude_accounts " do
    title "Ensure audit_log_exclude_accounts is set to NULL"
    desc "The audit_log_exclude_accounts variable has two permitted values, either NULL or a list
    of MySQL accounts. Setting this variable correctly ensures no single user is able to
    unintentionally evade being logged. Particular attention should be made to privileged
    accounts, as such accounts will generally be bestowed with more privileges than normal
    users, and should not be listed against this variable."
    impact 1.0
    tag Vulnerability: 'Low'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy: "To remediate this configuration setting, execute the following SQL statement
        SET GLOBAL audit_log_exclude_accounts = NULL"
    ref 'Mysql audit Log exclude accounts', url: 'https://dev.mysql.com/doc/refman/5.6/en/audit-log-plugin-options-variables.html#sysvar_audit_log_exclude_accounts'
    describe mysql_session(mysql_user, mysql_password).query('SHOW VARIABLES LIKE \'%audit_log_exclude_accounts%\';') do
        its('output') { should match(/NULL|/) }
      end
    end

control "mysql--log_include_accounts " do
    title "Ensure audit_log_include_accounts is set to NULL"
    desc "The audit_log_include_accounts variable has two permitted values, either NULL or a list
    of MySQL accounts.If a user or a list of users are set as the values for audit_log_include_accounts , these
    user(s) will ONLY be logged. Other users permitted to access the MySQL Server but not
    listed under the audit_log_include_accounts variable will avoid being logged in the audit
    log. Setting audit_log_include_accounts to NULL ensures no MySQL users excluded from
    the audit log."
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy: "To remediate this configuration setting, execute the following SQL statement
    SET GLOBAL audit_log_include_accounts = NULL"
    ref 'Mysql audit Log include accounts', url: 'https://dev.mysql.com/doc/refman/5.6/en/audit-log-plugin-options-variables.html#sysvar_audit_log_include_accounts'
    describe mysql_session(mysql_user, mysql_password).query('SHOW VARIABLES LIKE \'%audit_log_include_accounts%\';') do
        its('output') { should  match(/NULL|/) }
      end
    end
control "mysql--audit-log_policy " do
    title "Ensure audit_log_policy is set to log logins"
    desc "With the audit_log_policy setting the amount of information which is sent to the audit log
    is controlled. It must be set to log logins or ALL"
    impact 1.0
    tag Vulnerability: 'Low'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy: "Set audit_log_policy='ALL' in the MySQL configuration file and activate the setting by
    restarting the server or executing SET GLOBAL audit_log_policy='ALL';"
    ref 'Mysql audit Log policy', url: 'https://dev.mysql.com/doc/refman/5.6/en/audit-log-plugin-options-variables.html#sysvar_audit_log_policy'
    describe mysql_session(mysql_user, mysql_password).query('SHOW GLOBAL VARIABLES LIKE \'audit_log_policy\';') do
        its('output') { should  match(/LOGINS|ALL|/) }
      end
    end

control "mysql--audit-log_policy-connection " do
    title "Ensure audit_log_policy is set to log logins and connections"
    desc "With the audit_log_policy setting the amount of information which is sent to the audit log
    is controlled. It must be set to log logins and connections."
    impact 1.0
    tag Vulnerability: 'Low'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy: "Set audit_log_policy='ALL' in the MySQL configuration file and activate the setting by
    restarting the server or executing SET GLOBAL audit_log_policy='ALL';"
    ref 'Mysql audit Log policy', url: 'https://dev.mysql.com/doc/refman/5.6/en/audit-log-plugin-options-variables.html#sysvar_audit_log_policy'
    describe mysql_session(mysql_user, mysql_password).query('SHOW GLOBAL VARIABLES LIKE \'audit_log_policy\';') do
        its('output') { should  match(/ALL/) }
      end
    end

control "mysql--audit-log_strategy " do
    title "Set audit_log_strategy to SYNCHRONOUS or SEMISYNCRONOUS"
    desc "This setting controls how information is written to the audit log. It can be set to SYNCHRONOUS to make it fully durable or other settings which are less durable but have less performance overhead.
    ASYNCHRONOUS: Log asynchronously. Wait for space in the output buffer.
    PERFORMANCE: Log asynchronously. Drop requests for which there is insufficient space in the output buffer.
    SEMISYNCHRONOUS: Log synchronously. Permit caching by the operating system.
    SYNCHRONOUS: Log synchronously. Call sync() after each request."
    impact 1.0
    tag Vulnerability: 'Low'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy: "Set audit_log_strategy='SEMISYNCHRONOUS' (or SYNCHRONOUS )"
    ref 'Mysql audit Log strategy', url: 'https://dev.mysql.com/doc/refman/5.6/en/audit-log-plugin-options-variables.html#sysvar_audit_log_strategy'
    describe mysql_session(mysql_user, mysql_password).query('SHOW GLOBAL VARIABLES LIKE \'audit_log_strategy\';') do
        its('output') { should  match(/SYNCHRONOUS|SEMISYNCHRONOUS/) }
      end
    end

control "mysql--audit-plugin " do
    title "Make sure the audit plugin can't be unloaded"
    desc "This makes disables unloading on the plugin.
    If someone can unload the plugin it would be possible to perform actions on the database
    without audit events being logged to the audit log. If the audit log plugin can be unloaded
    the audit log can be temporarily or permanently disabled.
    "
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy: "Ensure the following line to make  in the mysqld section audit_log = 'FORCE_PLUS_PERMANENT"
    ref 'Mysql audit Log', url: 'https://dev.mysql.com/doc/refman/5.6/en/audit-log-plugin-options-variables.html#option_mysqld_audit-log'
    describe mysql_session(mysql_user, mysql_password).query('SELECT LOAD_OPTION FROM information_schema.plugins WHERE PLUGIN_NAME=\'audit_log\';') do
        its('output') { should  match(/FORCE_PLUS_PERMANENT/) }
      end
    end
    