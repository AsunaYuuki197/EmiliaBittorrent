# Emilia Bittorent
1. Emilia Client - Bittorrent Client for uploading - downloading - connecting others peers
2. Emilia Server - Bittorrent Tracker for sharing torrent file - finding peers


## How to Install and Run this project?

### Pre-Requisites:
1. Install Git Version Control
[ https://git-scm.com/ ]

2. Install Python Latest Version
[ https://www.python.org/downloads/ ]

3. Install Pip (Package Manager)
[ https://pip.pypa.io/en/stable/installation/ ]

Links for fixing some issues
[ https://stackoverflow.com/questions/23708898/pip-is-not-recognized-as-an-internal-or-external-command ]


### Installation
**1. Create a Folder where you want to save the project**

**2. Create a Virtual Environment and Activate**

Install Virtual Environment First
```
pip install virtualenv
```

Create Virtual Environment

For Windows
```
python -m venv venv
```
For Mac
```
python3 -m venv venv
```
For Linux
```
virtualenv .
```

Activate Virtual Environment

For Windows
```
venv\Scripts\activate
```

For Mac
```
source venv/bin/activate
```

For Linux
```
source bin/activate
```

**3. Clone this project**
```
git clone https://github.com/AsunaYuuki197/emilia-tracker.git
```


**4. What do you want to do?**

**4.1 Become client**

Then, Enter the project
```
cd EmiliaClient
```

Install Requirements from 'requirements.txt'

```python
pip install -r requirements.txt
```

Now, Run

Command for PC:
```python
$ python client.py
```

Command for Mac:
```python
$ python3 client.py
```

Command for Linux:
```python
$ python3 client.py
```

**4.2 Become server**

Add the hosts

- Got to settings.py file 
- Then, On allowed hosts, Use **[]** as your host. 
```python
ALLOWED_HOSTS = []
```
*You can create Render web service and add your host, then there are not much things to do (follow 5)*


*EmiliaServer uses Firebase storage, so you should config something (folllow next section)*


Install Requirements from 'requirements.txt'

```python
pip install -r requirements.txt
```

Run Server

Command for PC:
```python
$ python manage.py runserver
```

Command for Mac:
```python
$ python3 manage.py runserver
```

Command for Linux:
```python
$ python3 manage.py runserver
```

Login Credentials

Create Super User (Manager/Admin)

Command for PC:
```
$  python manage.py createsuperuser
```

Command for Mac:
```
$  python3 manage.py createsuperuser
```

Command for Linux:
```
$  python3 manage.py createsuperuser
```


Then Add Email and Password


**5. Connect to Render web service**

Open settings.py in your project’s main directory (e.g., mysite/settings.py).

Make the following modifications:

```python
# Import dj-database-url at the beginning of the file.
import dj_database_url
# Replace the SQLite DATABASES configuration with PostgreSQL:
DATABASES = {
    'default': dj_database_url.config(
        # Replace this value with your public or local database's connection string. (EmiliaServer choose to use postgreSQL from render)
        default='postgresql://postgres:postgres@localhost:5432/mysite',
        conn_max_age=600
    )
}
```

1. Create a new PostgreSQL database on Render. Copy its internal database URL for now—you’ll need it later.

2. Create a new web service on Render, pointing it to your project’s GitHub/GitLab/Bitbucket repository (give Render permission to access it if you haven’t already).

3. Select Python for the runtime and set the following properties (replace mysite with your project’s name):

```
Property	Value
Build Command	./build.sh
Start Command	python -m gunicorn mysite.asgi:application -k uvicorn.workers.UvicornWorker
```

4. Add the following environment variables under Advanced:

```
Key	Value
DATABASE_URL	The internal database URL for the database you created above
SECRET_KEY	Click Generate to get a secure random value
WEB_CONCURRENCY	4
That’s it! Save your web service to deploy your Django application on Render. It will be live on your .onrender.com URL as soon as the build finishes.
```

### Connect to Firebase Storage

**1. Install Django API for Google Cloud**

```
pip install django-storages[google]
```

**2. Get the Google Service Account**

- Create a Firebase and Register your web app [https://firebase.google.com/docs/web/setup?continue=https%3A%2F%2Ffirebase.google.com%2Flearn%2Fpathways%2Ffirebase-web%23article-https%3A%2F%2Ffirebase.google.com%2Fdocs%2Fweb%2Fsetup#create-firebase-project-and-app]

- Go to Storage options in Firebase and Get started

- Generate a private key file for your service account [https://firebase.google.com/docs/admin/setup#initialize_the_sdk_in_non-google_environments]


**3. Load Firebase credentials from service account**

```
from firebase_admin import credentials, storage
cred = credentials.Certificate(os.path.join(BASE_DIR, 'serviceAccountKey.json'))
firebase_admin.initialize_app(cred, {
    'storageBucket': 'your-storageBucket'
})
```

Your bucket name is 'storageBucket' value in Firebase JS SDK in project settings.
