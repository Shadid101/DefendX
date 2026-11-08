"""Local account management; credentials are never hardcoded."""
import argparse
import getpass
from werkzeug.security import generate_password_hash
from defendx.storage import AUTH_DB, connect, initialize


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command', choices=['init','create-user','unblock-all'])
    args=parser.parse_args()
    initialize()
    if args.command == 'init':
        print('Databases initialized. Run: python manage.py create-user')
    elif args.command == 'create-user':
        username = input('Username (e.g. student): ').strip()
        if not username or len(username)>80:
            raise SystemExit('Provide a username (1-80 characters).')
        password=getpass.getpass('Password (at least 10 characters): ')
        confirm=getpass.getpass('Repeat password: ')
        if len(password)<10 or password!=confirm:
            raise SystemExit('Passwords must match and contain at least 10 characters.')
        with connect(AUTH_DB) as db:
            db.execute('INSERT INTO users(username,password_hash) VALUES (?,?)',
                       (username,generate_password_hash(password)))
        print('Account created.')
    else:
        with connect(AUTH_DB) as db:
            db.execute('DELETE FROM blocks')
            db.execute('DELETE FROM attempts')
        print('All demo login blocks cleared.')


if __name__=='__main__':
    main()
