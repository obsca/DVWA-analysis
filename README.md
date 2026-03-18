- Pentest
- CTF
- AppSec
## О чем?
В этом репозитории я разбираю уязвимости **DVWA**, всех уровней сложности. Я буду стараться использовать автоматизированные утилиты, что бы показывать реальный процесс пентеста. Так же я буду анализировать код самого приложения. Этот репозиторий предполагает, что вы уже знакомы с основными уязвимостями, хотя бы с определениями. Данный материал будет полезен начинающим спецам и тем, у кого нет навыков эксплуатации и автоматизации поиска уязвимостей.
### Категории уязвимостей
Рекомендую читать именно в таком порядке:
- [SQL injection](https://github.com/obsca/DVWA-analysis/blob/main/SQL%20injection.md)
- [XSS (Rreflected)](https://github.com/obsca/DVWA-analysis/blob/main/XSS%20(Rreflected).md)
- [XSS (Stored)](https://github.com/obsca/DVWA-analysis/blob/main/XSS%20(Stored).md)
- [XSS (DOM)](https://github.com/obsca/DVWA-analysis/blob/main/XSS%20(DOM).md)
- [Command injection](https://github.com/obsca/DVWA-analysis/blob/main/Command%20injection.md)
- [File Inclusion](https://github.com/obsca/DVWA-analysis/blob/main/File%20Inclusion.md)
- soon...


	Если вы используете Linux, и установили **DVWA** через **`sudo apt install dvwa`**, то весь код DVWA будет лежать в директории **`/usr/share/dvwa/`** В директории **`./vulnerabilities`** будут все фрагменты уязвимого кода, остальное лучше не трогать, рискуете сломать все приложение.
