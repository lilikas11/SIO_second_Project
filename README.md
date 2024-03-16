# SIO 2nd Project - DETI STORE

## Description

DETI Store is a made-up e-commerce store which specializes in selling DETI merchandising. It allows users to buy products, review them and even leave comments about their experience with the order. In adition to that, the user can check the details about the product they're intrested in buying and check if they are out of stock before putting an order.

For this project, we conducted an audit of the first project website and fixed the eight most critical issues found. Additionaly we implemented two features: Password strength evaluation and Encrypted database storage.

## Authors

* Joana Gomes, 104429
* Lia Cardoso, 107548
* Liliana Ribeiro, 108713
* Pedro Ponte, 98059

#

## Directory Structure

On the app_sec folder you can find the `secure version` of the website and on the app_org folder you can find the `original version`.

On the analysis folder you can find our `report` in markdown alongside recordings of the website interface.

```bash
├── app_org
│   ├── app.py
│   ├── instance
│   │   └── test.db
│   ├── static
│   │   ├── css
│   │   ├── img
│   ├── templates
│   │   ├── html
│   ├── README.md
├── app_sec
│   ├── app.py
│   ├── detishop_cryptography.py
│   ├── keys.csv
│   ├── instance
│   │   └── test.db
│   ├── static
│   │   ├── css
│   │   ├── img
│   ├── templates
│   │   ├── html
│   ├── README.md
├── docker-compose.yml
├── Dockerfile
├── README.md
├── analysis.md
│   ├── report.md
│   ├── img
│   ├── screenshots
│   └── videos
```
