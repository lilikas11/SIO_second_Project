from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app import app, db, Product, Order
  
ctx = app.app_context()
ctx.push()  

# Create an order with two products and add it to database

# Order 1
Order.add_order(1, "12345", "Jhon", "Doe", "123123123", "mail@ua.pt", "Rua universidade", "Aveiro", "Portugal", "Confirmed", "Multibanco")
Order.add_product(1,1,1)


ctx.pop()