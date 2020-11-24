mysql_user  = attribute('mysqlUser', default: 'mysql', description: 'Name of mysql User')
mysql_password  = attribute('mysqlPassword', default: 'root', description: 'Password of mysql User')

control "mysql--network-ssl " do
    title "Ensure 'have_ssl' Is Set to 'YES'"
    desc "All network traffic must use SSL/TLS when traveling over untrusted networks.
    Enabling SSL will allow clients to encrypt network traffic and verify the identity of the
    server. This could have impact on network traffic inspection."
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Set ssl for your mysql"
    ref 'Mysql SSL CONNECTION', url: 'http://dev.mysql.com/doc/refman/5.6/en/ssl-connections.html'
    describe mysql_session(mysql_user, mysql_password).query('SHOW variables WHERE variable_name = \'have_ssl\';') do
        its('output') { should match(/YES/) }
      end
    end

control "mysql--network-ssl_type " do
    title "Ensure 'ssl_type' Is Set to 'ANY', 'X509', or 'SPECIFIED' for All Remote Users (Scored)"
    desc "All network traffic must use SSL/TLS when traveling over untrusted networks.
    SSL/TLS should be enforced on a per-user basis for users which enter the system through
    the network."
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Use the GRANT statement to require the use of SSL:
    GRANT USAGE ON *.* TO 'user'@'app1.example.com' REQUIRE SSL;"
    ref 'Mysql SSL CONNECTION', url: 'http://dev.mysql.com/doc/refman/5.6/en/ssl-connections.html'
    describe mysql_session(mysql_user, mysql_password).query('SELECT user, host, ssl_type FROM mysql.user WHERE NOT HOST IN (\'::1\', \'127.0.0.1\', \'localhost\');') do
        its('output') { should match(/SSL|ALL|x509|SPECIFIED/) }
      end
    end