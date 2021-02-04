mysql_user  = attribute('mysqlUser', default: 'mysql', description: 'Name of mysql User')
mysql_password  = attribute('mysqlPassword', default: 'root', description: 'Password of mysql User')
mysql_ipAddress  = attribute('mysqlAddress', default: '127.0.0.1', description: 'Ip address of mysql')


control "mysql--admin-priviledge-file_priv " do
    title "Ensure 'file_priv' Is Not Set to 'Y' for Non-Administrative Users"
    desc "The File_priv privilege found in the mysql.user table is used to allow or disallow a user
    from reading and writing files on the server host. Any user with the File_priv right
    granted has the ability to:
    Read files from the local file system that are readable by the MySQL server (this
    includes world-readable files)
    Write files to the local file system where the MySQL server has write access"
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"For each user, issue the following SQL statement (replace \"<user>\" with the non-
    administrative user:
    REVOKE FILE ON *.* FROM '<user>';"
    ref 'Mysql file_priv', url: 'http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_file'
    describe mysql_session(mysql_user, mysql_password, mysql_ipAddress).query('select user  from mysql.user where File_priv = \'Y\';') do
        its(:stdout) { should cmp "root" }
      end
    end

control "mysql--admin-priviledge-process_priv " do
    title "Ensure 'process_priv' Is Not Set to 'Y' for Non-Administrative Users"
    desc "The PROCESS privilege found in the mysql.user table determines whether a given user can
    see statement execution information for all sessions.
    The PROCESS privilege allows principals to view currently executing MySQL statements
    beyond their own, including statements used to manage passwords. This may be leveraged
    by an attacker to compromise MySQL or to gain access to potentially sensitive data.
    "
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"For each user, issue the following SQL statement (replace \"<user>\" with the non-
    administrative user:
    REVOKE PROCESS ON *.* FROM '<user>';"
    ref 'Mysql process_priv', url: 'http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_process'
    describe mysql_session(mysql_user, mysql_password, mysql_ipAddress).query('select user  from mysql.user where Process_priv = \'Y\';') do
        its(:stdout) { should cmp "root" }
      end
    end

control "mysql--admin-priviledge-super_priv " do
    title "Ensure 'super_priv' Is Not Set to 'Y' for Non-Administrative Users"
    desc "The SUPER privilege allows principals to perform many actions, including view and
    terminate currently executing MySQL statements (including statements used to manage
    passwords). This privilege also provides the ability to configure MySQL, such as
    enable/disable logging, alter data, disable/enable features. Limiting the accounts that have
    the SUPER privilege reduces the chances that an attacker can exploit these capabilities.
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"For each user, issue the following SQL statement (replace \"<user>\" with the non-
    administrative user:
    REVOKE SUPER ON *.* FROM '<user>';"
    ref 'Mysql super_priv', url: 'http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_super'
    describe mysql_session(mysql_user, mysql_password, mysql_ipAddress).query('select user  from mysql.user where Super_priv = \'Y\';') do
        its(:stdout) { should cmp "root" }
      end
    end


control "mysql--admin-priviledge-shutdown_priv " do
    title "Ensure 'shutdown_priv' Is Not Set to 'Y' for Non-Administrative Users"
    desc "The SHUTDOWN privilege simply enables use of the shutdown option to the mysqladmin
    command, which allows a user with the SHUTDOWN privilege the ability to shut down the
    MySQL server.
    The SHUTDOWN privilege allows principals to shutdown MySQL. This may be leveraged by an
    attacker to negatively impact the availability of MySQL.
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"For each user, issue the following SQL statement (replace \"<user>\" with the non-
    administrative user:
    REVOKE SHUTDOWN ON *.* FROM '<user>';"
    ref 'Mysql shutdown_priv', url: 'http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_shutdown'
    describe mysql_session(mysql_user, mysql_password, mysql_ipAddress).query('select user  from mysql.user where Shutdown_priv = \'Y\';') do
        its(:stdout) { should cmp "root" }
      end
    end


control "mysql--admin-priviledge-create_user_priv " do
    title "Ensure 'create_user_priv' Is Not Set to 'Y' for Non-AdministrativeUsers"
    desc "The CREATE USER privilege governs the right of a given user to add or remove users,
    change existing users' names, or revoke existing users' privileges.
    Reducing the number of users granted the CREATE USER right minimizes the number of
    users able to add/drop users, alter existing users' names, and manipulate existing users'
    privileges.
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"For each user, issue the following SQL statement (replace \"<user>\" with the non-
    administrative user:
    REVOKE CREATE USER ON *.* FROM '<user>';"
    ref 'Mysql privilege', url: 'http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html'
    describe mysql_session(mysql_user, mysql_password, mysql_ipAddress).query('select user  from mysql.user where Create_user_priv = \'Y\';') do
        its(:stdout) { should cmp "root" }
      end
    end


control "mysql--admin-priviledge-grant_priv " do
    title "Ensure 'grant_priv' Is Not Set to 'Y' for Non-Administrative Users"
    desc "The GRANT OPTION privilege exists in different contexts ( mysql.user , mysql.db) for the
    purpose of governing the ability of a privileged user to manipulate the privileges of other
    users.
    The GRANT privilege allows a principal to grant other principals additional privileges. This
    may be used by an attacker to compromise MySQL.
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"For each user, issue the following SQL statement (replace \"<user>\" with the non-
    administrative user:
    REVOKE GRANT OPTION ON *.* FROM '<user>';"
    ref 'Mysql grant_priv', url: 'http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_grant-option'
    describe mysql_session(mysql_user, mysql_password, mysql_ipAddress).query('select user  from mysql.user where Grant_priv = \'Y\';') do
        its(:stdout) { should cmp "root" }
      end
    end

control "mysql--admin-priviledge-grant_priv " do
    title "Ensure 'grant_priv' Is Not Set to 'Y' for Non-Administrative Users"
    desc "The GRANT OPTION privilege exists in different contexts ( mysql.user , mysql.db) for the
    purpose of governing the ability of a privileged user to manipulate the privileges of other
    users.
    The GRANT privilege allows a principal to grant other principals additional privileges. This
    may be used by an attacker to compromise MySQL.
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"For each user, issue the following SQL statement (replace \"<user>\" with the non-
    administrative user:
    REVOKE GRANT OPTION ON *.* FROM '<user>';"
    ref 'Mysql grant_priv', url: 'http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_grant-option'
    describe mysql_session(mysql_user, mysql_password, mysql_ipAddress).query('select user  from mysql.user where Grant_priv = \'Y\';') do
        its(:stdout) { should cmp "root" }
      end
    end

control "mysql--admin-priviledge-replication " do
    title "Ensure 'repl_slave_priv' Is Not Set to 'Y' for Non-Slave Users"
    desc "The REPLICATION SLAVE privilege governs whether a given user (in the context of the
    master server) can request updates that have been made on the master server.
    The REPLICATION SLAVE privilege allows a principal to fetch binlog files containing all data
    changing statements and/or changes in table data from the master. This may be used by an
    attacker to read/fetch sensitive data from MySQL.
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"For each user, issue the following SQL statement (replace \"<user>\" with the non-
    administrative user:
    REVOKE REPLICATION SLAVE ON *.* FROM '<user>';"
    ref 'Mysql replication_priv', url: 'http://dev.mysql.com/doc/refman/5.6/en/privileges-provided.html#priv_replication-slave'
    describe mysql_session(mysql_user, mysql_password, mysql_ipAddress).query('select user from mysql.user where Repl_slave_priv = \'Y\';') do
        its(:stdout) { should cmp "root" }
      end
    end
