# Реверс-инжиниринг драйвера сканера отпечатка пальцев Goodix 51C0 (SPI)

## Настройка драйвера `spidev`

Сначала проверьте что устройство действительно отображается в sysfs:
```shell
ls /sys/bus/spi/devices/
# > spi0.0  spi-GDIX51C0:00
```
Если устройство `spi-GDIX51C0:00` присутствует, выполните шаг за шагом:
```shell
sudo su
modprobe spidev

# проверить, что spidev загружен:
lsmod | grep spidev
# > spidev                 28672  0

# подсоединение устройства spi-GDIX51C0:00 к драйверу spidev
# взято отсюда https://docs.kernel.org/spi/spidev.html
echo spidev > /sys/bus/spi/devices/spi-GDIX51C0:00/driver_override
echo spi-GDIX51C0:00 > /sys/bus/spi/drivers/spidev/bind

# проверить, что устройство spidev появилось в /dev:
ls /dev/spidev*
# > /dev/spidev1.0
```

## Настройка виртуального окружения
Прежде чем выполнять шаги, необходимо чтобы у вас был установлен Python 3 с установленным `virtualenv`.

В корневой папке проекта создайте виртуальное окружение:
```shell
virtualenv venv
```

Активируйте его
```shell
source ./venv/bin/activate
```

Установите зависимости
```shell
pip install -r requirements.txt
```

Для того чтобы у python был доступ к SPI и GPIO устройствам, его нужно запускать из под root-пользователя.

Чтобы не запрашивать пароль каждый раз или при запуске из IDE, создайте в виртуальном окружении скрипт для запуска
интерпретатора python из под root-пользователя:
```shell
cat << EOF > ./venv/bin/python-sudo
#!/bin/bash
sudo $(pwd)/venv/bin/python "\$@"
EOF
chmod +x ./venv/bin/python-sudo
```

Чтобы не было запроса пароля, создайте файл `/etc/sudoers.d/venv-python` со следующим содержанием:
```
user_name machine_name = (root) NOPASSWD: /path/to/project/venv/bin/python
```
Например, так:
```
akimov huawei-rlefxx = (root) NOPASSWD: /home/akimov/desktop/gdix51c0-spi-reversing/venv/bin/python
```

Теперь в виртуальном окружении можно запускать python из под root пользователя без запроса пароля: 
вместо `python` используйте команду `python-sudo`.

Проверка, что все было настроено правильно:
```
(venv) [akimov@huawei-rlefxx gdix51c0-spi-reversing]$ python-sudo 
Python 3.11.6 (main, Nov 14 2023, 09:36:21) [GCC 13.2.1 20230801] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import getpass
>>> getpass.getuser()
'root'
>>> exit()
```

## Запуск скрипта

```shell
sudo python protocol_interaction.py
# or
python-sudo protocol_interaction.py
```

## Отладка в IDE
Для отладки можно запускать скрипт в среде разработки (например PyCharm или Intellij IDEA с установленным плагинов Python)

### Настройка
- в Intellij IDEA зайдите в меню `File -> Project Structure`, затем в `SDKs -> Add new SDK -> Add Python SDK`
- на вкладке `Virtual environment -> Existing environment -> Interpreter ...` и выберите файл `[project path]/venv/bin/python-sudo`
Все будет выглядеть примерно так:

<p align="center">
<img src="images/ide-interpreter-setup.png" alt="images/ide-interpreter-setup.png" width="700">
</p>

- нажмите `Apply`
- перейдите на вкладку `Project`
- выберите в выпадающем списке SDK созданный интерпретатор
- нажмите OK

### Отладка
Запуск отладки через клик ПКМ на [protocol_interaction.py](protocol_interaction.py) -> `Debug 'protocol_interaction.py'`.