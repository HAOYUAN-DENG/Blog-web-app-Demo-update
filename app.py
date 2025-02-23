from config import app, db
from flask import render_template
from accounts.api import api_accounts

@app.route('/')
def index():
    return render_template('home/index.html')

# # Register the accounts API blueprint
# app.register_blueprint(api_accounts)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This will create all tables defined by models
    app.run(debug=True) #ssl_context=('server.crt', 'server.key')))
