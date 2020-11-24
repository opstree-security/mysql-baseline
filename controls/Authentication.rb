mysql_user  = attribute('mysqlUser', default: 'mysql', description: 'Name of mysql User')
mysql_password  = attribute('mysqlPassword', default: 'root', description: 'Password of mysql User')

control "mysql--authentication-old_password " do
    title "Ensure 'old_passwords' Is Not Set to '1' or 'ON'"
    desc "This variable controls the password hashing method used by the PASSWORD() function and
    for the IDENTIFIED BY clause of the CREATE USER and GRANT statements.
    When old_passwords is set to 1 the PASSWORD() function will create password hashes
    with a very weak hashing algorithm which might be easy to break if captured by an
    attacker.
        0 - authenticate with the mysql_native_password plugin
        1 - authenticate with the mysql_old_password plugin
        2 - authenticate with the sha256_password plugin
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Configure mysql to leverage the mysql_native_password or sha256_password plugin"
    ref 'About Mysql Old Password', url: 'http://dev.mysql.com/doc/refman/5.6/en/server-system-variables.html#sysvar_old_passwords'
    describe command("mysql -u#{mysql_user} -p#{mysql_password} -sN -e SHOW VARIABLES WHERE Variable_name = \'old_passwords\';'") do
        its(:stdout) { should_not match(/1|ON/) }
    end
    describe mysql_session(mysql_user, mysql_password).query('SHOW VARIABLES WHERE Variable_name = \'old_passwords\';') do
        its(:stdout) { should_not match /1|ON/ }
      end
    end

control "mysql--authentication-secure-auth" do
    title "Ensure 'old_passwords' Is Not Set to '1' or 'ON'"
    desc "This option dictates whether the server will deny connections by clients that attempt to use
    accounts that have their password stored in the mysql_old_password format.
    Accounts having credentials stored using the old password format will be unable to login.
    "
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Add the following line to [mysqld] portions of the MySQL option file to establish the
    recommended state:
    secure_auth=ON"
    ref 'About Mysql secure auth', url: 'http://dev.mysql.com/doc/refman/5.6/en/server-options.html#option_mysqld_secure-auth'
    describe mysql_session(mysql_user, mysql_password).query('show variables like \'secure_auth\';;') do
        its('output') { should  match /ON/ }
      end
    end


control "mysql--authentication-auto-create-user" do
    title "Ensure 'sql_mode' Contains 'NO_AUTO_CREATE_USER'"
    desc "NO_AUTO_CREATE_USER is an option for sql_mode that prevents a GRANT statement from
    automatically creating a user when authentication information is not provided.
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Find the sql_mode setting in the [mysqld] area and add the NO_AUTO_CREATE_USER to the sql_mode setting"
    ref 'See mysql sql mode and no_audo_create_user', url: 'https://dev.mysql.com/doc/refman/5.7/en/sql-mode.html'
    describe mysql_session(mysql_user, mysql_password).query('SELECT @@global.sql_mode;') do
        its('output') { should  match /NO_AUTO_CREATE_USER/ }
    end
    describe mysql_session(mysql_user, mysql_password).query('SELECT @@session.sql_mode;') do
        its('output') { should  match /NO_AUTO_CREATE_USER/ }
    end    
end

control "mysql--authentication-passwordPolicy" do
    title "Ensure Password Policy Is in Place"
    desc "Password complexity includes password characteristics such as length, case, length, and
    character sets.
    Complex passwords help mitigate dictionary, brute forcing, and other password
    attacks. This recommendation prevents users from choosing weak passwords which can
    easily be guessed.
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Add to the global configuration:
    plugin-load=validate_password.so
    validate-password=FORCE_PLUS_PERMANENT
    validate_password_length=14
    validate_password_mixed_case_count=1
    validate_password_number_count=1
    validate_password_special_char_count=1
    validate_password_policy=MEDIUM"
    ref 'See mysql Validate Password Plugin', url: 'http://dev.mysql.com/doc/refman/5.6/en/validate-password-plugin.html'
    describe mysql_session(mysql_user, mysql_password).query('SHOW VARIABLES LIKE \'validate_password%\';') do
        its('output') { should  match(/validate_password_length/) }
        its('output') { should  match(/validate_password_number_count/) }
        its('output') { should  match(/validate_password_special_char_count/) }
        its('output') { should  match(/validate_password_policy/) }
        its('output') { should  match(/validate_password_length/) }
    end
end

control "mysql--authentication-hostname" do
    title "Ensure No Users Have Wildcard Hostnames"
    desc "MySQL can make use of host wildcards when granting permissions to users on specific
    databases. For example, you may grant a given privilege to '<user>'@'%' .
    Avoiding the use of wildcards within hostnames helps control the specific locations from
    which a given user may connect to and interact with the database.
    "
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Either ALTER the user's host to be specific or DROP the user"
    ref 'See mysql Hostnames', url: 'https://dev.mysql.com/doc/refman/5.7/en/account-names.html'
    describe mysql_session(mysql_user, mysql_password).query('SELECT user, host FROM mysql.user WHERE host = '%';') do
        its('output') { should  match(//) }
    end
end

control "mysql--authentication-Anonymous" do
    title "Ensure No Anonymous Accounts Exist"
    desc "Anonymous accounts are users with empty usernames (''). Anonymous accounts have no
    passwords, so anyone can use them to connect to the MySQL server.
    Removing anonymous accounts will help ensure that only identified and trusted principals
    are capable of interacting with MySQL.
    "
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"For each anonymous user, DROP or assign them a name"
    ref 'See how to remove anonymous user', url: 'https://www.networkinghowtos.com/howto/remove-anonymous-user-from-mysql/#:~:text=MySQL%20includes%20an%20anonymous%20user,put%20into%20a%20production%20environment.'
    describe mysql_session(mysql_user, mysql_password).query('SELECT user,host FROM mysql.user WHERE user = '';') do
        its('output') { should  match(//) }
    end
end
