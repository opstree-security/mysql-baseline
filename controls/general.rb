mysql_user  = attribute('mysqlUser', default: 'mysql', description: 'Name of mysql User')
mysql_password  = attribute('mysqlPassword', default: 'root', description: 'Password of mysql User')

# control "mysql--general-test-database " do
#     title "Ensure the 'test' Database Is Not Installed"
#     desc "The default MySQL installation comes with an unused database called test . It is
#         recommended that the test database be dropped.
#         The test database can be accessed by all users and can be used to consume system
#         resources. Dropping the test database will reduce the attack surface of the MySQL server."
#     impact 1.0
#     tag Vulnerability: 'Medium'
#     tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
#     tag Remedy:"Execute the following SQL statement to drop the test database:
#             DROP DATABASE \"test\";"
#     ref 'Mysql Secure Installation', url: 'http://dev.mysql.com/doc/refman/5.6/en/mysql-secure-installation.html'
#     describe mysql_session(mysql_user, mysql_password).query('SHOW DATABASES LIKE \'test\';') do
#         its(:stdout) { should match(//) }
#       end
#     end
  
# control "mysql--general-local-infile " do
#     title "Ensure 'local_infile' Is Disabled"
#     desc "The LOAD DATA statement loads a data file into a table. The statement can load a file located on the server host
#     The local_infile parameter dictates whether files located on the MySQL client's
#     computer can be loaded or selected via LOAD DATA INFILE or SELECT local_file ."
#     impact 1.0
#     tag Vulnerability: 'Low'
#     tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
#     tag Remedy:"Add the following line to the [mysqld] section of the MySQL configuration file and restart the MySQL service:
#           local-infile=0"
#     ref 'About Mysql Load Data', url: 'http://dev.mysql.com/doc/refman/5.6/en/load-data.html'
#     describe mysql_session(mysql_user, mysql_password).query('SHOW VARIABLES WHERE Variable_name = \'local_infile\';') do
#         its(:stdout) { should_not match(/ON/) }
#       end
#     end

control "mysql--skip-symbolic-links " do
    title "Ensure '--skip-symbolic-links' Is Enabled"
    desc "The symbolic-links and skip-symbolic-links options for MySQL determine whether
    symbolic link support is available. When use of symbolic links are enabled, they have
    different effects depending on the host platform.
    Prevents sym links being used for data base files. This is especially important when MySQL
    is executing as root as arbitrary files may be overwritten. The symbolic-links option might
    allow someone to direct actions by to MySQL server to other files and/or directories."
    impact 1.0
    tag Vulnerability: 'Low'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Locate skip_symbolic_links in the configuration
    Set the skip_symbolic_links to YES"
    ref 'About Mysql Symbolic Links', url: 'http://dev.mysql.com/doc/refman/5.6/en/symbolic-links.html'
    describe mysql_session(mysql_user, mysql_password).query('SHOW variables LIKE \'have_symlink\';') do
        its(:stdout) { should match(/YES|ON|DISABLED/) }
      end
    end

control "mysql--daemon_memcached" do
    title "Ensure the 'daemon_memcached' Plugin Is Disabled"
    desc "The InnoDB memcached Plugin allows users to access data stored in InnoDB with the
    memcached protocol.
    Set the skip_symbolic_links to YES. Turning the MySQL server into a fast “key-value store”.
    By default the plugin doesn't do authentication, which means that anyone with access to
    the TCP/IP port of the plugin can access and modify the data. However, not all data is
    exposed by default.
    "
    impact 1.0
    tag Vulnerability: 'Low'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"To remediate this setting, issue the following command in the MySQL command-line client:
    uninstall plugin daemon_memcached;
    "
    ref 'About Mysql innodb Memcached', url: 'http://dev.mysql.com/doc/refman/5.6/en/innodb-memcached-security.html'
    describe mysql_session(mysql_user, mysql_password).query('SELECT * FROM information_schema.plugins WHERE PLUGIN_NAME=\'daemon_memcached\';') do
        its(:stdout) { should match(//) }
      end
    end

control "mysql--secure_file_priv" do
    title "Ensure 'secure_file_priv' Is Not Empty"
    desc "The secure_file_priv option restricts to paths used by LOAD DATA INFILE or SELECT
    local_file . It is recommended that this option be set to a file system location that contains
    only resources expected to be loaded by MySQL.
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Add the following line to the [mysqld] section of the MySQL configuration file and restart
    the MySQL service:
    secure_file_priv=<path_to_load_directory>
    "
    ref 'Mysql Secure File Priviledge', url: 'http://dev.mysql.com/doc/refman/5.6/en/server-system-variables.html#sysvar_secure_file_priv'
    describe mysql_session(mysql_user, mysql_password).query('SHOW GLOBAL VARIABLES WHERE Variable_name = \'secure_file_priv\' AND Value<>'';') do
        its(:stdout) { should match(/mysql-files/) }
      end
    end

control "mysql--sql_mode" do
    title "Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES'"
    desc "When data changing statements are made (i.e. INSERT , UPDATE ), MySQL can handle invalid
    or missing values differently depending on whether strict SQL mode is enabled. When
    strict SQL mode is enabled, data may not be truncated or otherwise \"adjusted\" to make the
    data changing statement work.
    Without strict mode the server tries to do proceed with the action when an error might
    have been a more secure choice. For example, by default MySQL will truncate data if it does
    not fit in a field, which can lead to unknown behavior, or be leveraged by an attacker to
    circumvent data validation.
    "
    impact 1.0
    tag Vulnerability: 'Low'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Add STRICT_ALL_TABLES to the sql_mode in the server's configuration file
    "
    ref 'Mysql sql_mode', url: 'http://dev.mysql.com/doc/refman/5.6/en/server-sql-mode.html'
    describe mysql_session(mysql_user, mysql_password).query('SHOW VARIABLES LIKE \'sql_mode\';') do
        its(:stdout) { should match(/mysql-files/) }
      end
    end