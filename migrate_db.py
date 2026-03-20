# migrate.py
"""
Скрипт для миграции базы данных
Запустите: python migrate.py
"""

from app import app, db
from sqlalchemy import inspect, text
import os
import sys


def run_full_migration():
    """Полная миграция базы данных"""
    with app.app_context():
        print("=" * 60)
        print("🚀 НАЧАЛО МИГРАЦИИ БАЗЫ ДАННЫХ")
        print("=" * 60)

        try:
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            print(f"\n📊 Существующие таблицы: {tables}")

            # =============================================================
            # 1. МИГРАЦИЯ ТАБЛИЦЫ USER
            # =============================================================
            print("\n📋 МИГРАЦИЯ ТАБЛИЦЫ USER")
            print("-" * 40)

            if 'user' in tables:
                columns = [col['name'] for col in inspector.get_columns('user')]
                print(f"Текущие колонки: {columns}")

                # Добавляем колонки для администратора
                if 'is_admin' not in columns:
                    print("➕ Добавление колонки is_admin...")
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN is_admin BOOLEAN DEFAULT 0'))
                    print("✅ Колонка is_admin добавлена")

                if 'two_factor_enabled' not in columns:
                    print("➕ Добавление колонки two_factor_enabled...")
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 0'))
                    print("✅ Колонка two_factor_enabled добавлена")

                if 'two_factor_secret' not in columns:
                    print("➕ Добавление колонки two_factor_secret...")
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN two_factor_secret VARCHAR(32)'))
                    print("✅ Колонка two_factor_secret добавлена")

                if 'is_online' not in columns:
                    print("➕ Добавление колонки is_online...")
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN is_online BOOLEAN DEFAULT 0'))
                    print("✅ Колонка is_online добавлена")

                if 'last_seen' not in columns:
                    print("➕ Добавление колонки last_seen...")
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN last_seen TIMESTAMP'))
                    print("✅ Колонка last_seen добавлена")

                if 'failed_logins' not in columns:
                    print("➕ Добавление колонки failed_logins...")
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN failed_logins INTEGER DEFAULT 0'))
                    print("✅ Колонка failed_logins добавлена")

                if 'locked_until' not in columns:
                    print("➕ Добавление колонки locked_until...")
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN locked_until TIMESTAMP'))
                    print("✅ Колонка locked_until добавлена")

                if 'avatar_data' not in columns:
                    print("➕ Добавление колонки avatar_data...")
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN avatar_data TEXT'))
                    print("✅ Колонка avatar_data добавлена")

                if 'avatar_mime' not in columns:
                    print("➕ Добавление колонки avatar_mime...")
                    db.session.execute(
                        text('ALTER TABLE "user" ADD COLUMN avatar_mime VARCHAR(50) DEFAULT "image/png"'))
                    print("✅ Колонка avatar_mime добавлена")

                if 'cover_data' not in columns:
                    print("➕ Добавление колонки cover_data...")
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN cover_data TEXT'))
                    print("✅ Колонка cover_data добавлена")

                if 'cover_mime' not in columns:
                    print("➕ Добавление колонки cover_mime...")
                    db.session.execute(
                        text('ALTER TABLE "user" ADD COLUMN cover_mime VARCHAR(50) DEFAULT "image/jpeg"'))
                    print("✅ Колонка cover_mime добавлена")

                db.session.commit()
                print("✅ Таблица user обновлена")
            else:
                print("⚠️ Таблица user не найдена, создаем...")
                db.create_all()
                print("✅ Таблица user создана")

            # =============================================================
            # 2. МИГРАЦИЯ ТАБЛИЦЫ LOGIN_HISTORY
            # =============================================================
            print("\n📋 МИГРАЦИЯ ТАБЛИЦЫ LOGIN_HISTORY")
            print("-" * 40)

            if 'login_history' in tables:
                # Проверяем структуру таблицы
                columns = [col['name'] for col in inspector.get_columns('login_history')]
                print(f"Текущие колонки: {columns}")

                # Для SQLite нужно пересоздать таблицу, чтобы изменить nullable
                if 'user_id' in columns:
                    # Проверяем, есть ли NOT NULL constraint
                    try:
                        # Создаем временную таблицу
                        print("🔄 Пересоздание таблицы login_history...")

                        # Создаем временную таблицу с правильной структурой
                        db.session.execute(text('''
                            CREATE TABLE IF NOT EXISTS login_history_new (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                user_id INTEGER,
                                ip_address VARCHAR(45) NOT NULL,
                                user_agent VARCHAR(200),
                                location VARCHAR(100),
                                success BOOLEAN DEFAULT 1,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                FOREIGN KEY(user_id) REFERENCES user(id)
                            )
                        '''))

                        # Копируем данные
                        db.session.execute(text('''
                            INSERT INTO login_history_new (id, user_id, ip_address, user_agent, location, success, created_at)
                            SELECT id, user_id, ip_address, user_agent, location, success, created_at 
                            FROM login_history
                        '''))

                        # Удаляем старую таблицу
                        db.session.execute(text('DROP TABLE login_history'))

                        # Переименовываем новую
                        db.session.execute(text('ALTER TABLE login_history_new RENAME TO login_history'))

                        db.session.commit()
                        print("✅ Таблица login_history пересоздана (user_id теперь может быть NULL)")

                    except Exception as e:
                        print(f"⚠️ Ошибка при пересоздании таблицы: {e}")
                        db.session.rollback()
            else:
                print("📝 Создание таблицы login_history...")
                db.create_all()
                print("✅ Таблица login_history создана")

            # =============================================================
            # 3. МИГРАЦИЯ ТАБЛИЦЫ POST
            # =============================================================
            print("\n📋 МИГРАЦИЯ ТАБЛИЦЫ POST")
            print("-" * 40)

            if 'post' in tables:
                columns = [col['name'] for col in inspector.get_columns('post')]
                print(f"Текущие колонки: {columns}")

                if 'media_data' not in columns:
                    print("➕ Добавление колонки media_data...")
                    db.session.execute(text('ALTER TABLE post ADD COLUMN media_data TEXT'))
                    print("✅ Колонка media_data добавлена")

                if 'media_mime' not in columns:
                    print("➕ Добавление колонки media_mime...")
                    db.session.execute(text('ALTER TABLE post ADD COLUMN media_mime VARCHAR(50)'))
                    print("✅ Колонка media_mime добавлена")

                db.session.commit()
                print("✅ Таблица post обновлена")

            # =============================================================
            # 4. МИГРАЦИЯ ТАБЛИЦЫ MESSAGE
            # =============================================================
            print("\n📋 МИГРАЦИЯ ТАБЛИЦЫ MESSAGE")
            print("-" * 40)

            if 'message' in tables:
                columns = [col['name'] for col in inspector.get_columns('message')]
                print(f"Текущие колонки: {columns}")

                if 'is_deleted' not in columns:
                    print("➕ Добавление колонки is_deleted...")
                    db.session.execute(text('ALTER TABLE message ADD COLUMN is_deleted BOOLEAN DEFAULT 0'))
                    print("✅ Колонка is_deleted добавлена")

                if 'reply_to_id' not in columns:
                    print("➕ Добавление колонки reply_to_id...")
                    db.session.execute(text('ALTER TABLE message ADD COLUMN reply_to_id INTEGER'))
                    print("✅ Колонка reply_to_id добавлена")

                if 'media_data' not in columns:
                    print("➕ Добавление колонки media_data...")
                    db.session.execute(text('ALTER TABLE message ADD COLUMN media_data TEXT'))
                    print("✅ Колонка media_data добавлена")

                if 'media_mime' not in columns:
                    print("➕ Добавление колонки media_mime...")
                    db.session.execute(text('ALTER TABLE message ADD COLUMN media_mime VARCHAR(50)'))
                    print("✅ Колонка media_mime добавлена")

                db.session.commit()
                print("✅ Таблица message обновлена")

            # =============================================================
            # 5. МИГРАЦИЯ ТАБЛИЦЫ VOICE_MESSAGE
            # =============================================================
            print("\n📋 МИГРАЦИЯ ТАБЛИЦЫ VOICE_MESSAGE")
            print("-" * 40)

            if 'voice_message' in tables:
                columns = [col['name'] for col in inspector.get_columns('voice_message')]
                print(f"Текущие колонки: {columns}")

                if 'audio_data' not in columns:
                    print("➕ Добавление колонки audio_data...")
                    db.session.execute(text('ALTER TABLE voice_message ADD COLUMN audio_data TEXT'))
                    print("✅ Колонка audio_data добавлена")

                if 'audio_mime' not in columns:
                    print("➕ Добавление колонки audio_mime...")
                    db.session.execute(
                        text('ALTER TABLE voice_message ADD COLUMN audio_mime VARCHAR(50) DEFAULT "audio/mpeg"'))
                    print("✅ Колонка audio_mime добавлена")

                db.session.commit()
                print("✅ Таблица voice_message обновлена")
            else:
                print("📝 Создание таблицы voice_message...")
                db.create_all()
                print("✅ Таблица voice_message создана")

            # =============================================================
            # 6. МИГРАЦИЯ ТАБЛИЦЫ CALL
            # =============================================================
            print("\n📋 МИГРАЦИЯ ТАБЛИЦЫ CALL")
            print("-" * 40)

            if 'call' not in tables:
                print("📝 Создание таблицы call...")
                db.create_all()
                print("✅ Таблица call создана")

            # =============================================================
            # 7. МИГРАЦИЯ ТАБЛИЦЫ REPORT
            # =============================================================
            print("\n📋 МИГРАЦИЯ ТАБЛИЦЫ REPORT")
            print("-" * 40)

            if 'report' not in tables:
                print("📝 Создание таблицы report...")
                db.create_all()
                print("✅ Таблица report создана")

            # =============================================================
            # 8. МИГРАЦИЯ ТАБЛИЦЫ NOTIFICATION
            # =============================================================
            print("\n📋 МИГРАЦИЯ ТАБЛИЦЫ NOTIFICATION")
            print("-" * 40)

            if 'notification' in tables:
                columns = [col['name'] for col in inspector.get_columns('notification')]
                print(f"Текущие колонки: {columns}")

                if 'call_id' not in columns:
                    print("➕ Добавление колонки call_id...")
                    db.session.execute(text('ALTER TABLE notification ADD COLUMN call_id INTEGER'))
                    print("✅ Колонка call_id добавлена")

                db.session.commit()
                print("✅ Таблица notification обновлена")

            # =============================================================
            # 9. МИГРАЦИЯ ТАБЛИЦЫ GROUP
            # =============================================================
            print("\n📋 МИГРАЦИЯ ТАБЛИЦЫ GROUP")
            print("-" * 40)

            if 'group' in tables:
                columns = [col['name'] for col in inspector.get_columns('group')]
                print(f"Текущие колонки: {columns}")

                if 'avatar_data' not in columns:
                    print("➕ Добавление колонки avatar_data...")
                    db.session.execute(text('ALTER TABLE "group" ADD COLUMN avatar_data TEXT'))
                    print("✅ Колонка avatar_data добавлена")

                if 'avatar_mime' not in columns:
                    print("➕ Добавление колонки avatar_mime...")
                    db.session.execute(
                        text('ALTER TABLE "group" ADD COLUMN avatar_mime VARCHAR(50) DEFAULT "image/png"'))
                    print("✅ Колонка avatar_mime добавлена")

                if 'cover_data' not in columns:
                    print("➕ Добавление колонки cover_data...")
                    db.session.execute(text('ALTER TABLE "group" ADD COLUMN cover_data TEXT'))
                    print("✅ Колонка cover_data добавлена")

                if 'cover_mime' not in columns:
                    print("➕ Добавление колонки cover_mime...")
                    db.session.execute(
                        text('ALTER TABLE "group" ADD COLUMN cover_mime VARCHAR(50) DEFAULT "image/jpeg"'))
                    print("✅ Колонка cover_mime добавлена")

                db.session.commit()
                print("✅ Таблица group обновлена")

            # =============================================================
            # 10. МИГРАЦИЯ ТАБЛИЦЫ CHANNEL
            # =============================================================
            print("\n📋 МИГРАЦИЯ ТАБЛИЦЫ CHANNEL")
            print("-" * 40)

            if 'channel' in tables:
                columns = [col['name'] for col in inspector.get_columns('channel')]
                print(f"Текущие колонки: {columns}")

                if 'avatar_data' not in columns:
                    print("➕ Добавление колонки avatar_data...")
                    db.session.execute(text('ALTER TABLE channel ADD COLUMN avatar_data TEXT'))
                    print("✅ Колонка avatar_data добавлена")

                if 'avatar_mime' not in columns:
                    print("➕ Добавление колонки avatar_mime...")
                    db.session.execute(
                        text('ALTER TABLE channel ADD COLUMN avatar_mime VARCHAR(50) DEFAULT "image/png"'))
                    print("✅ Колонка avatar_mime добавлена")

                if 'cover_data' not in columns:
                    print("➕ Добавление колонки cover_data...")
                    db.session.execute(text('ALTER TABLE channel ADD COLUMN cover_data TEXT'))
                    print("✅ Колонка cover_data добавлена")

                if 'cover_mime' not in columns:
                    print("➕ Добавление колонки cover_mime...")
                    db.session.execute(
                        text('ALTER TABLE channel ADD COLUMN cover_mime VARCHAR(50) DEFAULT "image/jpeg"'))
                    print("✅ Колонка cover_mime добавлена")

                db.session.commit()
                print("✅ Таблица channel обновлена")

            # =============================================================
            # 11. ОБНОВЛЕНИЕ СУЩЕСТВУЮЩИХ ДАННЫХ
            # =============================================================
            print("\n📋 ОБНОВЛЕНИЕ СУЩЕСТВУЮЩИХ ДАННЫХ")
            print("-" * 40)

            # Обновляем значения по умолчанию для user
            try:
                db.session.execute(text('UPDATE "user" SET is_admin = 0 WHERE is_admin IS NULL'))
                db.session.execute(text('UPDATE "user" SET two_factor_enabled = 0 WHERE two_factor_enabled IS NULL'))
                db.session.execute(text('UPDATE "user" SET is_online = 0 WHERE is_online IS NULL'))
                db.session.execute(text('UPDATE "user" SET failed_logins = 0 WHERE failed_logins IS NULL'))
                db.session.commit()
                print("✅ Значения по умолчанию для user установлены")
            except Exception as e:
                print(f"⚠️ Ошибка при обновлении user: {e}")

            # =============================================================
            # 12. СОЗДАНИЕ АДМИНИСТРАТОРА
            # =============================================================
            print("\n📋 СОЗДАНИЕ АДМИНИСТРАТОРА")
            print("-" * 40)

            from app import User
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                from werkzeug.security import generate_password_hash
                admin = User(
                    username='admin',
                    email='admin@kildear.com',
                    display_name='Administrator',
                    is_admin=True,
                    is_verified=True
                )
                admin.set_password('Admin123!')
                db.session.add(admin)
                db.session.commit()
                print("✅ Администратор создан")
                print("   Логин: admin")
                print("   Пароль: Admin123!")
            else:
                # Убеждаемся, что admin имеет права
                admin.is_admin = True
                admin.is_verified = True
                db.session.commit()
                print("✅ Администратор уже существует")

            print("\n" + "=" * 60)
            print("🎉 МИГРАЦИЯ ЗАВЕРШЕНА УСПЕШНО!")
            print("=" * 60)

        except Exception as e:
            print(f"\n❌ ОШИБКА ПРИ МИГРАЦИИ: {e}")
            db.session.rollback()
            sys.exit(1)


if __name__ == "__main__":
    run_full_migration()