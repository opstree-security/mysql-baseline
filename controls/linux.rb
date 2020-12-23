control 'mysql-linux-service' do
    impact 1.0
    title 'Mysql should be running and enabled(Not Scored)'
    desc 'Mysql should be running and enabled. When system restarts apruptly mysql should be started and loaded automatically'
    tag Vulnerability: 'High'
    tag Version: 'CIS NGINX Benchmark v1.0.0 - 02-28-2019'
    describe service(mysql.service) do
      it { should be_installed }
      it { should be_running }
      it { should be_enabled }
    end
end

control "mysql--linux-mysql-account " do
  title "Use Dedicated Least Privileged Account for MySQL Daemon/Service"
  desc "As with any service installed on a host, it can be provided with its own user
  context. Providing a dedicated user to the service provides the ability to precisely
  constrain the service within the larger host context.
  Utilizing a least privilege account for MySQL to execute as may reduce the impact of a
  MySQL-born vulnerability. A restricted account will be unable to access resources
  unrelated to MySQL, such as operating system configurations."
  impact 1.0
  tag Vulnerability: 'High'
  tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
  tag Remedy:"Create a user which is only used for running MySQL and directly related processes. This
  user must not have administrative rights to the system."
  ref 'Changing mysql User', url: 'http://dev.mysql.com/doc/refman/5.6/en/changing-mysql-user.html'
  describe user('mysql') do
    it { should exist }
  end
end

control "mysql--command-Line " do
  title "Disable MySQL Command History"
  desc "On Linux/UNIX, the MySQL client logs statements executed interactively to a history
  file. By default, this file is named .mysql_history in the user's home directory. Most
  interactive commands run in the MySQL client application are saved to a history file. The
  MySQL command history should be disabled.
  Disabling the MySQL command history reduces the probability of exposing sensitive
  information, such as passwords and encryption keys."
  impact 1.0
  tag Vulnerability: 'Medium'
  tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
  tag Remedy:"Create $HOME/.mysql_history as a symbolic to /dev/null ."
  ref 'Mysql Logging', url: 'http://dev.mysql.com/doc/refman/5.6/en/mysql-logging.html'
  describe command("sudo find /home -name  \".mysql_history\" -type f | wc -l ") do
    its(:stdout) { should match /^0/ }
  end
end

control "mysql--MYSQL_PWD environment" do
  title "Verify That the MYSQL_PWD Environment Variables Is Not In Use"
  desc "MySQL can read a default database password from an environment variable called
  MYSQL_PWD .
  The use of the MYSQL_PWD environment variable implies the clear text storage of MySQL
  credentials. Avoiding this may increase assurance that the confidentiality of MySQL
  credentials is preserved.
  "
  impact 1.0
  tag Vulnerability: 'Low'
  tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
  tag Remedy:"Remove this variable and use some secured way"
  ref 'Mysql Environment Variables', url: 'http://dev.mysql.com/doc/refman/5.6/en/environment-variables.html'
  describe command("grep MYSQL_PWD /etc/environment | wc -l") do
    its(:stdout) { should match /^0/ }
  end
end

control "mysql--linux-mysql-login " do
  title "Disable Interactive Login"
  desc "When created, the MySQL user may have interactive access to the operating system, which
  means that the MySQL user could login to the host as any other user would.
  Preventing the MySQL user from logging in interactively may reduce the impact of a
  compromised MySQL account. There is also more accountability as accessing the operating
  system where the MySQL server lies will require the user's own account. Interactive access
  by the MySQL user is unnecessary and should be disabled.
  "
  impact 1.0
  tag Vulnerability: 'High'
  tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
  tag Remedy:"Create a user which is only used for running MySQL and directly related processes. This
  user must not have administrative rights to the system."
  ref 'Changing mysql User', url: 'http://dev.mysql.com/doc/refman/5.6/en/changing-mysql-user.html'
  describe user('mysql') do
    its('shell') { should eq '/bin/false' }
  end
end

control "mysql--linux-MYSQL_PWD -all users profile " do
  title "Verify That 'MYSQL_PWD' Is Not Set In Users' Profiles"
  desc "The use of the MYSQL_PWD environment variable implies the clear text storage of MySQL
  credentials. Avoiding this may increase assurance that the confidentiality of MySQL
  credentials is preserved.
  It should not be used in .bashrc, .profile etc
  "
  impact 1.0
  tag Vulnerability: 'Low'
  tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
  tag Remedy:"Check which users and/or scripts are setting MYSQL_PWD and change them to use a more
  secure method."
  ref 'Mysql Environment Variables', url: 'http://dev.mysql.com/doc/refman/5.6/en/environment-variables.html'
  describe user('mysql') do
    its('shell') { should eq '/bin/false' }
  end
end