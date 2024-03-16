# How to run

1.Create a virtual enviorment:

```bash
python3 -m venv venv
```

2.Activate the virtual enviorment:

```bash
source venv/bin/activate
```

3.Install / Upgrade pip

```bash
python -m pip install --upgrade pip
```

4.Install the requirements

```bash
pip install -r requirements.txt
```

5.Create a docker image

```bash
docker-compose build
```


### --- YOU ONLY NEED TO DO THE STEPS ABOVE ONCE ---

2.Activate the virtual enviorment:

```bash
source venv/bin/activate
```

6.Run the docker image

```bash
docker-compose up
```

7.Access the website

```bash
http://localhost:5000/
```

### Run Local

```bash
flask run 
```

### Aceder à base de dados

```bash
sqlite3 instance/test.db
```
