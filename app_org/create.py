from app import app, db

ctx = app.app_context()
ctx.push()

db.create_all()

ctx.pop()

print("DB CREATED")