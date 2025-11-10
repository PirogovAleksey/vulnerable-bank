# Швидке встановлення Vulnerable Bank

## Передумови

Перед початком роботи переконайтеся, що у вас встановлено:

- **Docker Desktop** (Windows/Mac) або **Docker Engine** (Linux)
- **Docker Compose** (зазвичай входить до складу Docker Desktop)

### Перевірка встановлення Docker

```bash
docker --version
docker-compose --version
```

## Швидкий старт

### 1. Клонування репозиторію

```bash
git clone https://github.com/YOUR_USERNAME/vulnerable-bank.git
cd vulnerable-bank
```

### 2. Запуск проекту

```bash
docker-compose up --build
```

Ця команда:
- Завантажить необхідні Docker образи
- Створить базу даних MySQL
- Запустить Flask веб-додаток
-Ініціалізує базу даних тестовими даними

### 3. Доступ до системи

Після успішного запуску:
- Веб-інтерфейс: **http://localhost:5000**
- База даних MySQL: **localhost:3306**

### 4. Тестові акаунти

| Логін | Пароль | Роль | Баланс |
|-------|---------|------|--------|
| admin | admin123 | Адміністратор | ₴1,000,000 |
| john | password | Користувач | ₴5,000 |
| jane | 123456 | Користувач | ₴10,000 |
| alice | letmein | Касир | ₴15,000 |

## Корисні команди

### Зупинка проекту

```bash
docker-compose down
```

### Зупинка з видаленням даних

```bash
docker-compose down -v
```

### Перегляд логів

```bash
# Усі логи
docker-compose logs

# Тільки логи веб-додатку
docker-compose logs webapp

# Тільки логи бази даних
docker-compose logs db

# Слідкувати за логами в реальному часі
docker-compose logs -f
```

### Перезапуск окремого сервісу

```bash
# Перезапуск веб-додатку
docker-compose restart webapp

# Перезапуск бази даних
docker-compose restart db
```

### Доступ до контейнера

```bash
# Доступ до веб-додатку
docker exec -it vulnerable_bank_web bash

# Доступ до бази даних
docker exec -it vulnerable_bank_db bash
```

### Підключення до MySQL

```bash
# З хост-системи
mysql -h 127.0.0.1 -u bankuser -p vulnerable_bank
# Пароль: weak_password_123

# З контейнера
docker exec -it vulnerable_bank_db mysql -u bankuser -p vulnerable_bank
```

## Вирішення проблем

### Порт 5000 зайнятий

Якщо порт 5000 вже використовується:

```yaml
# У файлі docker-compose.yml змініть:
webapp:
  ports:
    - "8080:5000"  # Використовуйте порт 8080 замість 5000
```

### Порт 3306 зайнятий

Якщо порт MySQL вже використовується:

```yaml
# У файлі docker-compose.yml змініть:
db:
  ports:
    - "3307:3306"  # Використовуйте порт 3307 замість 3306
```

### База даних не ініціалізується

```bash
# Видаліть том бази даних і перезапустіть:
docker-compose down -v
docker-compose up --build
```

### Помилка "Cannot connect to database"

Почекайте 10-15 секунд після запуску docker-compose. MySQL потребує часу для ініціалізації.

## Режим розробки

Для розробки з автоматичним перезавантаженням:

```yaml
# У docker-compose.yml додайте:
webapp:
  volumes:
    - ./webapp:/app
  environment:
    - FLASK_ENV=development
    - FLASK_DEBUG=1
```

Після цього зміни у файлах автоматично застосовуватимуться без перезбірки образу.

## Очищення системи

Видалення всіх контейнерів, образів та томів:

```bash
docker-compose down -v --rmi all
```

## Наступні кроки

Після успішного запуску:

1. Прочитайте **README.md** для ознайомлення з завданням
2. Перегляньте **VULNERABILITIES.md** (тільки для викладачів)
3. Почніть виконувати завдання з етапу 1: Розвідка

## Додаткові ресурси

- [Документація Docker](https://docs.docker.com/)
- [Flask документація](https://flask.palletsprojects.com/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Security Academy](https://portswigger.net/web-security)

## Підтримка

Якщо виникли проблеми:
1. Перевірте логи: `docker-compose logs`
2. Переконайтеся, що Docker запущено
3. Спробуйте повністю перезібрати: `docker-compose down -v && docker-compose up --build`
4. Зверніться до викладача або створіть issue в репозиторії
