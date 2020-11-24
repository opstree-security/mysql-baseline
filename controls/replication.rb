mysql_user  = attribute('mysqlUser', default: 'mysql', description: 'Name of mysql User')
mysql_password  = attribute('mysqlPassword', default: 'root', description: 'Password of mysql User')

control "mysql-replication-master-info " do
    title "Ensure 'master_info_repository' Is Set to 'TABLE'"
    desc "The master_info_repository setting determines to where a slave logs master status and
    connection information. The options are FILE or TABLE . Note also that this setting is
    associated with the sync_master_info setting as well."
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"In my.cnf file set the master_info_repository value to TABLE"
    ref 'Mysql master-slave info', url: 'http://dev.mysql.com/doc/refman/5.6/en/replication-options-slave.html#sysvar_master_info_repository'
    describe mysql_session(mysql_user, mysql_password).query('SHOW GLOBAL VARIABLES LIKE \'master_info_repository\';') do
        its('output') { should match(/TABLE/) }
      end
    end

control "mysql-replication-wildcard " do
    title "Ensure No Replication Users Have Wildcard Hostnames"
    desc "MySQL can make use of host wildcards when granting permissions to users on specific
    databases. For example, you may grant a given privilege to '<user>'@'%' .
    Avoiding the use of wildcards within hostnames helps control the specific locations from
    which a given user may connect to and interact with the database.
    "
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Either ALTER the user's host to be specific or DROP the user"
    ref 'Mysql Replication', url: 'http://dev.mysql.com/doc/refman/5.6/en/replication-options-slave.html'
    describe mysql_session(mysql_user, mysql_password).query('SELECT user, host FROM mysql.user WHERE user=\'repl\' AND host = '%';') do
        its('output') { should match(//) }
      end
    end

control "mysql-super_priv" do
    title "Ensure 'super_priv' Is Not Set to 'Y' for Replication Users"
    desc "Replication user should not have super_priv.
    The SUPER privilege allows principals to perform many actions, including view and
    terminate currently executing MySQL statements (including statements used to manage
    passwords). This privilege also provides the ability to configure MySQL, such as
    enable/disable logging, alter data, disable/enable features. Limiting the accounts that have
    the SUPER privilege reduces the chances that an attacker can exploit these capabilities.
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Execute REVOKE SUPER ON *.* FROM 'repl';"
    ref 'Mysql Replication', url: 'http://dev.mysql.com/doc/refman/5.6/en/replication-options-slave.html'
    describe mysql_session(mysql_user, mysql_password).query('select user, host from mysql.user where user=\'repl\' and Super_priv = \'Y\';') do
        its('output') { should match(//) }
      end
    end