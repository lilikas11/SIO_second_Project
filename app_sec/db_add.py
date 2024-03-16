from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app import app, db, Product
  
ctx = app.app_context()
ctx.push()  

    
# Product 1
Product.add_product(1, "DETI Pen", 800, 100, "The DETI blue ink pen is a sleek writing instrument with the DETI logo, combining style and branding in one elegant design.", "img/img1.png")
    
# Product 2
Product.add_product(2, "DETI Keyholder", 500, 50, "The DETI logo keyholder, made from premium stainless steel, combines sleek design with robust functionality, ensuring both style and security for your keys.", "img/img2.png")

# Product 3
Product.add_product(3, "DETI Water Bottle", 1200, 40, "The DETI water bottle is a sleek and eco-friendly hydration solution, designed for your on-the-go lifestyle. Stay refreshed and sustainable with the DETI logo proudly displayed.", "img/img3.png")

# Product 4
Product.add_product(4, "DETI Notebook", 1000, 100, "The DETI notebook is your creative canvas for jotting down ideas and notes. Featuring a stylish cover with the DETI logo, its a perfect blend of form and function.", "img/img4.png")

# Product 5
Product.add_product(5, "DETI Sweatpants", 1500, 30, "Stay comfortable and stylish with DETI sweatpants. Made from premium materials, they offer a cozy fit and showcase the DETI logo, making them ideal for relaxation and leisure.", "img/img5.png")

# Product 6
Product.add_product(6, "DETI Phone Case", 1000, 50, "Protect your phone in style with the DETI phone case. It features a durable design and the DETI logo, offering both security and brand representation.", "img/img6.png")

# Product 7
Product.add_product(7, "DETI Cap", 7000, 70, "The DETI cap is a fashionable accessory for any outfit. With the DETI logo embroidered, it adds a touch of class to your look while providing sun protection.", "img/img7.png")

# Product 8
Product.add_product(8, "DETI Holy water", 20000, 1000, "DETI holy water is a sacred symbol of spiritual connection. With blessings and the DETI logo, it offers a source of inspiration and devotion.", "img/img8.png")

# Product 9
Product.add_product(9, "DETI Mug", 1200, 60, "Sip your favorite beverages in the DETI mug. With the DETI logo, it adds a touch of sophistication to your coffee or tea time.", "img/img9.png")

# Product 10
Product.add_product(10, "DETI T-Shirt", 1600, 100, "The DETI t-shirt is a wardrobe essential. Crafted with soft, breathable fabric and showcasing the DETI logo, it combines comfort and style effortlessly.", "img/img10.png")

# Product 11
Product.add_product(11, "DETI Building", 0, 1, "It's just DETI.", "img/img11.png") ##"He's just Ken"

print("Products added")

ctx.pop()