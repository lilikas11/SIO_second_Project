# How to run:

1. Create a virtual enviorment:
```
python3 -m venv venv
```

2.  Activate the virtual enviorment:
```
source venv/bin/activate
```

3. Install / Upgrade pip
```
python -m pip install --upgrade pip
```

4. Install the requirements
```
pip install -r requirements.txt
```

5. Create a docker image
```
docker-compose build
```


### --- YOU ONLY NEED TO DO THE STEPS ABOVE ONCE ---

2.  Activate the virtual enviorment:
```
source venv/bin/activate
```

6. Run the docker image
```
docker-compose up
```

7. Access the website
```
http://localhost:5000/
```
