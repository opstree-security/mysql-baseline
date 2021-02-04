mysql_data_directory  = attribute('mysqlDirectory', default: '/var/lib/mysql', description: 'Path to the mysql data directory')
mysql_log_directory  = attribute('mysqlLog', default: '/var/log/mysql', description: 'Path to the mysql log directory')
mysql_plugin_directory  = attribute('mysqlPlugin', default: '/usr/lib/mysql/plugin/', description: 'Path to the mysql plugin directory')
mysql_ssl_key  = attribute('mysqlSsl', default: '/var/lib/mysql/server-key.pem', description: 'Path to the mysql ssl key ')


control "mysql-file-Data Directory Owner" do
    title "Ensure datadir Has appropriate owner"
    desc "Information managed by the MySQL server is stored under a directory known as the data directory
          It's owner and group should be mysql.. "

    impact 1.0
    tag Vulnerability: 'Critical'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Execute following commands to handle permission
                chown mysql:mysql <datadir>"
    ref 'About Mysql Data Directory', url: 'https://dev.mysql.com/doc/refman/8.0/en/data-directory.html'
    describe file(mysql_data_directory) do
        it { should be_directory }
        its('group') { should eq 'mysql' }
        its('owner') { should eq 'mysql' }
      end
    end

control "mysql-file-Data Directory Permission" do
    title "Ensure datadir Has appropriate permission"
    desc "Information managed by the MySQL server is stored under a directory known as the data directory
          It's permission should be 700... If this directory permission has allowed other
          user to read or may write then anyone can exploit mysql and breach several critical information which is stored here.  "
    impact 1.0
    tag Vulnerability: 'Critical'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Execute following commands to handle permission
                chown mysql:mysql <datadir>"
    ref 'About Mysql Data Directory', url: 'https://dev.mysql.com/doc/refman/8.0/en/data-directory.html'
    describe file(mysql_data_directory) do
        it { should be_directory }
        its('mode') { should cmp '0700' }
        it { should be_readable.by('owner') }
        it { should be_writable.by('owner') }
        it { should_not  be_readable.by('group') }
        it { should_not  be_writable.by('group') }
        it { should_not be_readable.by('other') }
        it { should_not be_writable.by('other') }
      end
    end

# control "mysql-file-Bin log Permission" do
#     title "Ensure log_bin_basename Files Have Appropriate Permissions"
#     desc "The binary log contains events that describe database changes such as table creation operations or changes to table data.
#         These binary logs contain events in binary form. Anyone having these logs can re-execute .
#     "
#     impact 1.0
#     tag Vulnerability: 'High'
#     tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
#     tag Remedy:"Execute following commands to handle permission
#                 chmod 660 <log file>"
#     ref 'About Mysql Binary Log', url: 'https://dev.mysql.com/doc/refman/8.0/en/binary-log.html'
#     describe file("/var/lib/mysql/ib_logfile0") do
#         its('mode') { should cmp '0640' }
#         it { should be_readable.by('owner') }
#         it { should be_writable.by('owner') }
#         it { should  be_readable.by('group') }
#         it { should_not be_readable.by('other') }
#         it { should_not be_writable.by('other') }
#       end
#     end


control "mysql-audit-log-file" do
  title "Ensure 'audit_log_file' has Appropriate Permissions"
  desc "The MySQL server calls the audit log plugin to write an audit record to its log file whenever an auditable event occurs. \n
  Typically the first audit record written after plugin startup contains the server description and startup options. Elements following that one represent events such as client connect and disconnect events, executed SQL statements
  Limiting the accessibility of these objects will protect the confidentiality, integrity, and
  availability of the MySQL logs.
  "
  impact 1.0
  tag Vulnerability: 'Medium'
  tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
  tag Remedy:"Execute the following command for the audit_log_file discovered in the audit procedure:
    chmod 660 <audit_log_file>
    chown mysql:mysql <audit_log_file>"
  ref 'About Audit Log File', url: 'https://dev.mysql.com/doc/refman/8.0/en/audit-log-file-formats.html'
  describe file(mysql_data_directory) do
      it { should exist }
      it { should_not be_writable.by('other') }
    end
  end

control "mysql-plugin" do
    title "Ensure log_bin_basename Files Have Appropriate Permissions"
    desc "The plugin directory is the location of the MySQL plugins. Plugins are storage engines or
    user defined functions (UDFs). It's permission should be restricted"
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"To remediate this setting, execute the following commands at a terminal prompt using the
    plugin_dir Value from the audit procedure.
    chmod 775 <plugin_dir Value> (or use 755)"
    ref 'About Mysql Plugin', url: 'http://dev.mysql.com/doc/refman/5.6/en/install-plugin.html'
    describe file(mysql_plugin_directory) do 
      it { should be_directory }
      it { should be_readable.by('owner') }
      it { should be_writable.by('owner') }
      it { should  be_readable.by('group') }
      it { should_not be_writable.by('other') }
    end
end

control "mysql-ssl-key-permission" do
  title "Ensure SSL Key Files Have Appropriate Permissions"
  desc "When configured to use SSL/TLS, MySQL relies on key files, which are stored on the host's
  filesystem. These key files are subject to the host's permissions structure.
  If the contents of the SSL key file is known to an attacker he or she might impersonate the
  server. This can be used for a man-in-the-middle attack.
  Depending on the SSL cipher suite the key might also be used to decipher previously
  captured network traffic.
  "
  impact 1.0
  tag Vulnerability: 'High'
  tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
  tag Remedy:"Execute the following commands at a terminal prompt to remediate this setting using the
  Value from the audit procedure:
  chmod 400 <ssl_key Value>"
  ref 'Mysql ssh connections', url: 'http://dev.mysql.com/doc/refman/5.6/en/ssl-connections.html'
  describe command("sudo stat -c %a #{mysql_ssl_key} | grep \"400\" | wc -l") do
    its(:stdout) { should_not match /^0/ }
  end
end


control "mysql-file-log_error-file-permission" do
    title "Ensure log_bin_basename Files Have Appropriate Permissions"
    desc "The error log contains a record of mysqld startup and shutdown times.
     It also contains diagnostic messages such as errors, warnings, and notes that occur during server startup and shutdown, and while the server is running.
     For example, if mysqld notices that a table needs to be automatically checked or repaired, it writes a message to the error log.
     Limiting the accessibility of these objects will protect the confidentiality, integrity, and
     availability of the MySQL logs."
    impact 1.0
    tag Vulnerability: 'High'
    tag Version: 'CIS_Oracle_MySQL_Enterprise_Edition_5.6_Benchmark_v1.1.0'
    tag Remedy:"Execute the following command for each log file location requiring corrected permissions:
    chmod 660 <log file>
    chown mysql:mysql <log file>"
    ref 'About Mysql Binary Log', url: 'https://dev.mysql.com/doc/refman/8.0/en/binary-log.html'
    describe file("#{mysql_log_directory}/error.log") do
        it { should be_file }
        it { should_not be_readable.by('other') }
        it { should_not be_writable.by('other') }
      end
    end
    