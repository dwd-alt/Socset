# migrate_db.py
from app import app, db
from sqlalchemy import inspect, text
import os


def migrate_database():
    """Add new columns to existing database"""
    with app.app_context():
        try:
            # Проверяем существование базы данных
            db_path = os.path.join('instance', 'kildear.db')
            if not os.path.exists(db_path):
                print("❌ База данных не найдена. Сначала запустите приложение.")
                return

            inspector = inspect(db.engine)

            # Проверяем колонки в таблице user
            columns = [col['name'] for col in inspector.get_columns('user')]
            print("📊 Текущие колонки в таблице user:", columns)

            # Добавляем колонку is_admin если её нет
            if 'is_admin' not in columns:
                print("➕ Добавление колонки is_admin...")
                db.session.execute(text('ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0'))
                print("✅ Колонка is_admin добавлена")

            # Добавляем колонку two_factor_enabled если её нет
            if 'two_factor_enabled' not in columns:
                print("➕ Добавление колонки two_factor_enabled...")
                db.session.execute(text('ALTER TABLE user ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 0'))
                print("✅ Колонка two_factor_enabled добавлена")

            # Добавляем колонку two_factor_secret если её нет
            if 'two_factor_secret' not in columns:
                print("➕ Добавление колонки two_factor_secret...")
                db.session.execute(text('ALTER TABLE user ADD COLUMN two_factor_secret VARCHAR(32)'))
                print("✅ Колонка two_factor_secret добавлена")

            # Обновляем существующих пользователей
            db.session.execute(text('UPDATE user SET is_admin = 0 WHERE is_admin IS NULL'))
            db.session.execute(text('UPDATE user SET two_factor_enabled = 0 WHERE two_factor_enabled IS NULL'))
            db.session.commit()

            print("\n🎉 Миграция завершена успешно!")
            print("Новые колонки:",
                  [col for col in ['is_admin', 'two_factor_enabled', 'two_factor_secret'] if col not in columns])

        except Exception as e:
            print(f"❌ Ошибка при миграции: {e}")
            db.session.rollback()


if __name__ == "__main__":
    print("🚀 Запуск миграции базы данных...")
    migrate_database()