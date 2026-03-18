#### Небольшая справка
Эта уязвимость позволяет читать файлы на машине. При этой уязвимости приложение возвращает ввод пользователя.

### LOW
Тут все просто, без автоматизации

- http://127.0.0.1:42001/vulnerabilities/fi/?page=/etc/passwd
И мы прочитали системный файл. Передали параметру маршрут файла. Даже можно код не смотреть
### MEDIUM

Средний уровень так же возвращает файл по такой же ссылке, это странно
http://127.0.0.1:42001/vulnerabilities/fi/?page=/etc/passwd

Я залез в код и увидел фильтрацию 

```php
$file = str_replace( array( "http://", "https://" ), "", $file );
$file = str_replace( array( "../", "..\\" ), "", $file );
```

Видимо они расчитывали, что мы будем перемещаться сначала вниз к корневой папке через ../../../../, но и так возвращается /etc/passwd, давайте попробуем именно обойти фильтрацию

Мы можем учитывая фильтрацию обойти ее. Каждый **`../`** заменятся пустотой. Если использовать **`....//`**, то после замены это превратится в **`../`** - как раз то что нам нужно.
Перебираем и по ссылке:
- http://127.0.0.1:42001/vulnerabilities/fi/?page=....//....//....//....//....//....//etc/passwd
Получаем LFI

### HARD
По аналогии с заданиями другого типа, можно предположить, что тут так же используется фильтрация, скорее всего на имя файла.

И да! получаем содержимое файла /etc/passwd по такой ссылке:
- http://127.0.0.1:42001/vulnerabilities/fi/?page=file/../../../../../../etc/passwd

```php
<?php  
  
// The page we wish to display  
$file = $_GET[ 'page' ];  
  
// Input validation  
if( !fnmatch( "file*", $file ) && $file != "include.php" ) {  
       // This isn't the page we want!  
       echo "ERROR: File not found!";  
       exit;  
}  
  
?>
```

Простая фильтрация, этого недостаточно.

Самый оптимальный вариант использовать белый лист с именами файлов

```php
<?php

// The page we wish to display
$file = $_GET[ 'page' ];

// Only allow include.php or file{1..3}.php
$configFileNames = [
    'include.php',
    'file1.php',
    'file2.php',
    'file3.php',
];

if( !in_array($file, $configFileNames) ) {
    // This isn't the page we want!
    echo "ERROR: File not found!";
    exit;
}

?>

```


