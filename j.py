from app import app, db, User

with app.app_context():
    admin = User(
        username='kildear',
        email='kildear@kildear.com',
        display_name='Администратор Kildear',
        is_admin=True,
        is_verified=True
    )
    admin.set_password('Admin123!')
    db.session.add(admin)
    db.session.commit()
    print("✅ Администратор создан: kildear / Admin123!")