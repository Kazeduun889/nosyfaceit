# Инструкция по переезду на Render.com (Бесплатно + Надежно)

Render — это крутой хостинг, но он удаляет все файлы при перезагрузке (как на школьном компьютере). Поэтому базу данных нужно хранить отдельно.

Мы используем связку: **Render (Сайт)** + **Neon (База данных)**. Оба сервиса имеют бесплатные тарифы.

## Шаг 1: Создание Базы Данных (Neon.tech)
1.  Зайдите на [neon.tech](https://neon.tech) -> Sign Up (можно через Google/GitHub).
2.  Создайте проект (Create Project):
    *   Name: `facevosait-db`
    *   Region: Frankfurt (ближе к нам).
3.  После создания вам покажут **Connection String** (строка подключения).
    *   Она выглядит так: `postgres://neondb_owner:AbC123...@ep-icy-....aws.neon.tech/neondb?sslmode=require`
    *   **Скопируйте её и сохраните!** Это ключ к вашей базе.

## Шаг 2: Подготовка кода (Я уже сделал)
Я добавил файл `render.yaml` и обновил `requirements.txt` для работы с PostgreSQL (вместо SQLite).

Вам нужно:
1.  Загрузить этот код на **GitHub**. (Если у вас нет GitHub, зарегистрируйтесь там и создайте репозиторий, затем загрузите туда все файлы проекта).

## Шаг 3: Запуск на Render.com
1.  Зайдите на [render.com](https://render.com) -> Sign Up.
2.  Нажмите **New +** -> **Web Service**.
3.  Выберите **Build and deploy from a Git repository**.
4.  Подключите свой GitHub и выберите репозиторий `facevosait`.
5.  Настройки:
    *   **Name:** `facevosait`
    *   **Region:** Frankfurt (Germany).
    *   **Branch:** `main` (или `master`).
    *   **Runtime:** Python 3.
    *   **Build Command:** `pip install -r requirements.txt`
    *   **Start Command:** `gunicorn web.app:app`
    *   **Plan:** Free ($0/month).
6.  **Самое важное:** Пролистайте вниз до **Environment Variables** (Переменные окружения) и добавьте:
    *   Key: `DATABASE_URL`
    *   Value: Вставьте ту строку из Neon (`postgres://...`).
7.  Нажмите **Create Web Service**.

## Итог
Через 2-3 минуты сайт будет доступен по адресу `https://facevosait.onrender.com`.
Он будет работать у всех (Render редко блокируют), а данные будут надежно храниться в Neon.
