# shining-brows-portal

## Supabase setup
- Create a Supabase project and open **Project Settings → Database → Connection string → SQLAlchemy**.
- Copy the `postgresql+psycopg2://...` URL (it already includes `sslmode=require`).
- Create a `.env` file based on `.env.example` and set `SUPABASE_DB_URL` to that URL plus a new `SECRET_KEY`.
- Install deps: `pip install -r requirements.txt`.
- Start the app: `flask run` (or `python main.py`). The first run will create the required tables in your Supabase database via SQLAlchemy.
