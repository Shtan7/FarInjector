В данном репозитории представлен код загрузчика, способного
загрузить в 32-битное приложение 64-битный код в виде длл.

Проект активно использует механизм, позволяющий на лету
изменять режим работы процессора из обычного защищенного в длинный.
Возможно это благодаря far переходу на другой сегмент, во флагах которого
присутствует бит длинного режима.



В WOW64 приложениях присутствует 64-битная версия ntdll.dll, адрес
которой возможно получить через LDR таблицу. С помощью LdrLoadDll происходит
загрузка 64-битной kernel32.dll, а далее через LoadLibrary загрузка необходимой нам
библиотеки.

К сожалению, kernel32 и kernelbase загружаются не на свои фиксированные
системой базовые адреса. Происходит это из-за 0xC0000018 ntstatus кода, возвращаемого
ZwMapViewOfSection, при попытке замапить библиотеку на её базовый адрес.
Данное обстоятельство делает невозможным использование большей части
экспорта kernel32 и kernelbase. 

В более ранних версиях Windows подобное поведение достигалось за счет зарезервированных страниц, 
находящися на базовых адресах библиотек. В актуальной версии Windows используется другой, 
неизвестный мне, механизм.

Код протестирован на версии Windows 20h2 19042.1052

========================================================================

This repository contains a loader code that can load a x64 code into an
x32 application.

The project uses a processor feature that allows you to change the operating
mode from normal protected to long on the fly. This is possible due to far calls\jmps 
to another segment in the flags of which the long mode bit is set.



All WOW64 applications have a x64 bit version of ntdll.dll. We can get
its address with LDR table. With LdrLoadDll we load x64 kernel32.dll and
then LoadLibrary loads the target library. 

Unfortunately, kernel32 and kernelbase are not loaded at base addresses.
All because of 0xC0000018 ntstatus code which is returned from ZwMapViewOfSection.
Therefore you cannot use most of the kernel32 and kernelbase functions.

In earlier versions of Windows this was achieved by using reserved pages at
base addresses of libraries. The current version of Windows uses a mechanism unknown to me.

Code tested on Windows 20h2 19042.1052
