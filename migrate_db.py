# migrate_db_final.py
from app import app, db
from sqlalchemy import inspect, text
import os


def migrate_database():
    """Add all new columns to existing database"""
    with app.app_context():
        try:
            # Проверяем существование базы данных
            db_path = os.path.join('instance', 'kildear.db')
            if not os.path.exists(db_path):
                print("❌ База данных не найдена. Сначала запустите приложение.")
                return

            inspector = inspect(db.engine)

            # 1. МИГРАЦИЯ ТАБЛИЦЫ USER
            print("\n📊 Проверка таблицы user...")
            user_columns = [col['name'] for col in inspector.get_columns('user')]
            print("Текущие колонки:", user_columns)

            # Добавляем is_online если нет
            if 'is_online' not in user_columns:
                print("➕ Добавление is_online...")
                db.session.execute(text('ALTER TABLE user ADD COLUMN is_online BOOLEAN DEFAULT 0'))

            # Добавляем last_seen если нет
            if 'last_seen' not in user_columns:
                print("➕ Добавление last_seen...")
                db.session.execute(text('ALTER TABLE user ADD COLUMN last_seen DATETIME'))

            # Обновляем значения
            db.session.execute(text('UPDATE user SET is_online = 0 WHERE is_online IS NULL'))

            # 2. МИГРАЦИЯ ТАБЛИЦЫ MESSAGE
            print("\n📊 Проверка таблицы message...")
            msg_columns = [col['name'] for col in inspector.get_columns('message')]
            print("Текущие колонки:", msg_columns)

            if 'is_deleted' not in msg_columns:
                print("➕ Добавление is_deleted...")
                db.session.execute(text('ALTER TABLE message ADD COLUMN is_deleted BOOLEAN DEFAULT 0'))

            if 'reply_to_id' not in msg_columns:
                print("➕ Добавление reply_to_id...")
                db.session.execute(text('ALTER TABLE message ADD COLUMN reply_to_id INTEGER'))

            db.session.execute(text('UPDATE message SET is_deleted = 0 WHERE is_deleted IS NULL'))

            # 3. МИГРАЦИЯ ТАБЛИЦЫ NOTIFICATION
            print("\n📊 Проверка таблицы notification...")
            notif_columns = [col['name'] for col in inspector.get_columns('notification')]
            print("Текущие колонки:", notif_columns)

            if 'call_id' not in notif_columns:
                print("➕ Добавление call_id...")
                db.session.execute(text('ALTER TABLE notification ADD COLUMN call_id INTEGER'))

            # 4. СОЗДАНИЕ НОВЫХ ТАБЛИЦ
            tables = inspector.get_table_names()
            print("\n📊 Существующие таблицы:", tables)

            # Таблица blocks
            if 'blocks' not in tables:
                print("➕ Создание таблицы blocks...")
                db.session.execute(text('''
                    CREATE TABLE blocks (
                        blocker_id INTEGER NOT NULL,
                        blocked_id INTEGER NOT NULL,
                        PRIMARY KEY (blocker_id, blocked_id),
                        FOREIGN KEY(blocker_id) REFERENCES user (id),
                        FOREIGN KEY(blocked_id) REFERENCES user (id)
                    )
                '''))
                print("✅ Таблица blocks создана")

            # Таблица call
            if 'call' not in tables:
                print("➕ Создание таблицы call...")
                db.session.execute(text('''
                    CREATE TABLE call (
                        id INTEGER NOT NULL,
                        caller_id INTEGER NOT NULL,
                        callee_id INTEGER NOT NULL,
                        call_type VARCHAR(10) NOT NULL,
                        status VARCHAR(20) DEFAULT 'missed',
                        duration INTEGER DEFAULT 0,
                        started_at DATETIME,
                        ended_at DATETIME,
                        PRIMARY KEY (id),
                        FOREIGN KEY(caller_id) REFERENCES user (id),
                        FOREIGN KEY(callee_id) REFERENCES user (id)
                    )
                '''))
                print("✅ Таблица call создана")

            db.session.commit()
            print("\n✅ Все миграции успешно завершены!")

            # Показываем итоговые структуры
            print("\n📊 Итоговая структура таблицы user:")
            user_columns = [col['name'] for col in inspector.get_columns('user')]
            print(user_columns)

            print("\n📊 Итоговая структура таблицы message:")
            msg_columns = [col['name'] for col in inspector.get_columns('message')]
            print(msg_columns)

            print("\n📊 Итоговая структура таблицы notification:")
            notif_columns = [col['name'] for col in inspector.get_columns('notification')]
            print(notif_columns)

        except Exception as e:
            print(f"❌ Ошибка при миграции: {e}")
            db.session.rollback()


if __name__ == "__main__":
    print("🚀 Запуск миграции базы данных...")
    migrate_database()