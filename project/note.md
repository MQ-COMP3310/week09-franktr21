This week, I fixed a SQL injection issue in the signup function.

Originally, the code used a raw SQL query like this:

db.session.execute(text('select * from user where email = "' + email +'"'))

This was unsafe because it could be tricked using inputs like `' OR '1'='1`.

I changed it to this safer version using SQLAlchemy:

User.query.filter_by(email=email).first()

I also added password hashing using:

generate_password_hash(password, method='pbkdf2:sha256')



