# migrate_render.py
from app import app, db
from sqlalchemy import text
import os

def migrate():
    with app.app_context():
        try:
            # Проверяем существующие колонки
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('user')]
            
            print(f"📊 Текущие колонки: {columns}")
            
            # Добавляем недостающие колонки
            if 'is_admin' not in columns:
                db.session.execute(text('ALTER TABLE "user" ADD COLUMN is_admin BOOLEAN DEFAULT FALSE'))
                print("✅ Добавлена колонка is_admin")
            
            if 'two_factor_enabled' not in columns:
                db.session.execute(text('ALTER TABLE "user" ADD COLUMN two_factor_enabled BOOLEAN DEFAULT FALSE'))
                print("✅ Добавлена колонка two_factor_enabled")
            
            if 'two_factor_secret' not in columns:
                db.session.execute(text('ALTER TABLE "user" ADD COLUMN two_factor_secret VARCHAR(32)'))
                print("✅ Добавлена колонка two_factor_secret")
            
            db.session.commit()
            print("🎉 Миграция завершена успешно!")
            
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            db.session.rollback()

if __name__ == "__main__":
    migrate()
