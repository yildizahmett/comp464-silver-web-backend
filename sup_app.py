import os
import functools
from itsdangerous import URLSafeTimedSerializer
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt,
    jwt_required,
    verify_jwt_in_request,
)
from modal import Image, Stub, wsgi_app, Mount
from mail_ops import send_mail

class Config(object):
    JWT_SECRET_KEY='83f1aa7c-90d0-4dbd-a635-c5dacf2fe028'
    SECRET_KEY='29aae8cb-40c3-4acd-8304-75a132fda5e8'
    SECURITY_PASSWORD_SALT='9b25e106-287d-4fa7-8e2d-c5f85c23fece'
    JWT_ACCESS_TOKEN_EXPIRES=18000
    SUPABASE_URL=''
    SUPABASE_KEY=''

image = Image.debian_slim(python_version="3.9").pip_install(
    "flask-cors",
    "Flask-JWT-Extended",
    "Flask-Cors",
    "flask-bcrypt",
    "flask",
    "supabase"
)
stub = Stub("comp-464-projects", image=image)

def admin_auth():
    def wrapper(f):
        @functools.wraps(f)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["sub"]["user_type"] != "admin":
                return {"message": "Invalid token [From Decorator]"}, 403
            return f(*args, **kwargs)

        return decorator

    return wrapper

def dealer_auth():
    def wrapper(f):
        @functools.wraps(f)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["sub"]["user_type"] != "dealer":
                return {"message": "Invalid token [From Decorator]"}, 403
            return f(*args, **kwargs)

        return decorator

    return wrapper

    
@stub.function(name="admin", 
               image=image)
@wsgi_app()
def admin():
    from supabase import create_client, Client
    from flask_cors import CORS
    from flask import Flask, jsonify, request
    from flask_bcrypt import Bcrypt

    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(app)

    bcrypt = Bcrypt(app)
    jwt = JWTManager(app)

    url: str = app.config["SUPABASE_URL"]
    key: str = app.config["SUPABASE_KEY"]
    supabase: Client = create_client(url, key)

    def generate_confirmation_token(email):
        try:
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
        except Exception as e:
            return -1
        
    def confirm_token(token, expiration=3600):
        try:
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            email = serializer.loads(
                token,
                salt=app.config['SECURITY_PASSWORD_SALT'],
                max_age=expiration
            )
            return email
        except Exception as e:
            return -1

    @app.post("/admin/login")
    def admin_login():
        try:
            data = request.get_json()
            
            admin = supabase.table("Admin").select("*").eq("email", data["email"]).execute()
            if len(admin.data) == 0:
                return {"message": "Invalid credentialssss"}, 401
            
            else:
                access_token = create_access_token(identity={"user_type": "admin", "id": admin.data[0]["id"]})
                return {"access_token": access_token}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/admin/change-password")
    @admin_auth()
    def admin_change_password():

            admin_id = get_jwt()["sub"]["id"]
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            data = request.get_json()
            if data["old_password"] != admin.data[0]["password"]:
                return {"message": "Invalid credentials"}, 401
            
            supabase.table("Admin").update({"password": data["new_password"]}).eq("id", int(admin_id)).execute()
            return {"message": "Password changed successfully"}, 200

        
    @app.post("/admin/add-categories")
    @admin_auth()
    def admin_add_categories():
        try:
            admin_id = get_jwt()["sub"]["id"]
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            data = request.get_json()
            if data["name"] == "":
                return {"message": "No category name found."}, 404
            
            supabase.table("category").insert(data).execute()
            return {"message": "Categories added successfully"}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get("/admin/categories")
    @admin_auth()
    def admin_add_product():
        try:
            admin_id = get_jwt()["sub"]["id"]
            admin = supabase.table("Admin").select("*").execute()

            if len(admin.data) == 0:
                return {"message": "Invalid credentials."}, 401
            
            categories = supabase.table("category").select("*").execute()
            return {"categories": categories.data}, 200
        
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/admin/product/add")
    @admin_auth()
    def admin_add_product_post():
        try:
            admin_id = get_jwt()["sub"]["id"]
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            data = request.get_json()
            if data["name"] == "" or data["description"] == "" or data["category_id"] == "":
                return {"message": "Invalid credentials"}, 401
            
            product = supabase.table("products").select("*").eq("name", data["name"]).eq("is_active", True).execute()
            if len(product.data) > 0:
                return {"message": "Product already exists"}, 401
            
            supabase.table("products").insert(data).execute()

            return {"message": "Product added successfully"}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get("/admin/product/<int:id>")
    @admin_auth()
    def admin_product_details(id):
        try:
            admin_id = get_jwt()["sub"]["id"]
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            product = supabase.table("products").select("*").eq("id", id).eq("is_active", True).execute()
            if len(product.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            return {"product": product.data[0]}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/admin/product/edit/<int:id>")
    @admin_auth()
    def admin_product_edit(id):
        try:
            admin_id = get_jwt()["sub"]["id"]
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            data = request.get_json()
            supabase.table("products").update(data).eq("id", id).eq("is_active", True).execute()
            return {"message": "Product updated successfully"}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get("/admin/product/delete/<int:id>")
    @admin_auth()
    def admin_product_delete(id):
        try:
            admin_id = get_jwt()["sub"]["id"]
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            product = supabase.table("products").select("*").eq("id", id).execute().data
            if len(product) == 0:
                return {"message": "Invalid credentials"}, 401
            
            supabase.table("products").update({"is_active": False}).eq("id", id).execute()
            return {"message": "Product deleted successfully"}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get("/admin/products")
    @admin_auth()
    def admin_products():
        try:
            admin_id = get_jwt()["sub"]["id"]
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            data = request.get_json()
            search = data["search"]
            categories = data["categories"]
            page_size = data["page_size"]

            query = supabase.table("products").select("id", count="exact").eq("is_active", True).ilike("name", f"%{search}%")

            if len(categories) > 0:
                query = query.in_("category_id", categories)
            
            products_count = query.execute()
            page_number = products_count.count // page_size + 1

            return {"page_number": page_number}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500

    @app.post("/admin/products/<int:page_number>")
    @admin_auth()
    def admin_products_post(page_number):
        try:
            admin_id = get_jwt()["sub"]["id"]
            admin = supabase.table("Admin").select("*").eq("id", admin_id).execute()
            if len(admin.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            data = request.get_json()
            search = data["search"]
            categories = data["categories"]
            page_size = data["page_size"]

            query = supabase.table("products").select("*").eq("is_active", True).ilike("name", f"%{search}%")

            if len(categories) > 0:
                query = query.in_("category_id", categories)
            
            products = query.limit(page_size).offset((page_number - 1) * (page_size)).execute()
            return {"products": products.data}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get("/admin/dealers")
    @admin_auth()
    def admin_dealers():
        try:
            admin_id = get_jwt()["sub"]["id"]
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            dealers = supabase.table("dealer").select("*").execute()
            return {"dealers": dealers.data}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post('/admin/orders/<int:page_number>')
    @admin_auth()
    def admin_orders(page_number):
        try:
            admin_id = get_jwt()['sub']['id']
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {'message': 'Invalid credentials'}, 401

            data = request.get_json()
            order_status = data['order_status']
            start_date = data['start_date']
            end_date = data['end_date']
            product_search = data['product_search']
            dealer_serach = data['dealer_search']
            page_size = data['page_size']

            query = supabase.table('order_details').select('''order_id, quantity, products!inner(name, price), orders!inner(dealer_id, order_status, description, cargo_brand, cargo_id, created_at, dealer!inner(email, name, address, city, country, phone))''', count='exact')
            query = query.eq('orders.order_status', order_status)

            if start_date != "" and end_date != "":
                query = query.gte('orders.created_at', start_date)
                query = query.lte('orders.created_at', end_date)

            if product_search != "":
                query = query.ilike('products.name', f'%{product_search}%')

            if dealer_serach != "":
                query = query.ilike('orders.dealer.email', f'%{dealer_serach}%')

            query = query.order('created_at', desc=True, foreign_table='orders')
            query = query.limit(page_size).offset((page_number - 1) * (page_size))

            orders = query.execute().data
            return jsonify({"orders": orders}), 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500

    @app.post('/admin/orders-max-page')
    @admin_auth()
    def admin_orders_get():
        try:
            admin_id = get_jwt()['sub']['id']
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {'message': 'Invalid credentials'}, 401

            data = request.get_json()
            order_status = data['order_status']
            start_date = data['start_date']
            end_date = data['end_date']
            product_search = data['product_search']
            dealer_serach = data['dealer_search']
            page_size = data['page_size']
            print(data)

            query = supabase.table('order_details').select('''order_id, quantity, products!inner(name, price), orders!inner(dealer_id, order_status, description, cargo_brand, cargo_id, created_at, dealer!inner(email, name, address, city, country, phone))''', count='exact')
            query = query.eq('orders.order_status', order_status)

            if start_date != "" and end_date != "":
                query = query.gte('orders.created_at', start_date)
                query = query.lte('orders.created_at', end_date)

            if product_search != "":
                query = query.ilike('products.name', f'%{product_search}%')

            if dealer_serach != "":
                query = query.ilike('orders.dealer.email', f'%{dealer_serach}%')

            number_of_orders = query.execute().count

            page_number = number_of_orders // page_size + 1

            return jsonify({"page_number": page_number}), 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post('/admin/orders/accept-order')
    @admin_auth()
    def admin_accept_order():
        try:
            admin_id = get_jwt()['sub']['id']
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {'message': 'Invalid credentials'}, 401

            data = request.get_json()
            order_ids = data['order_ids']
            print(order_ids)

            for order_id in order_ids:
                supabase.table('orders').update({'order_status': 'Preparing'}).eq('id', order_id).ilike('order_status', '%Waiting%').execute()

            return jsonify({"message": "Order is prepearing."}), 200

        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post('/admin/orders/ship-order')
    @admin_auth()
    def admin_ship_order():
        try:
            admin_id = get_jwt()['sub']['id']
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {'message': 'Invalid credentials'}, 401

            data = request.get_json()
            order_ids = data['order_ids']

            for order_id in order_ids:
                supabase.table('orders').update({'order_status': 'Shipping'}).eq('id', order_id).ilike('order_status', '%Preparing%').execute()

            return jsonify({"message": "Order is shipping."}), 200

        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post('/admin/orders/deliver-order')
    @admin_auth()
    def admin_deliver_order():
        try:
            admin_id = get_jwt()['sub']['id']
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {'message': 'Invalid credentials'}, 401

            data = request.get_json()
            order_ids = data['order_ids']

            for order_id in order_ids:
                supabase.table('orders').update({'order_status': 'Delivered'}).eq('id', order_id).ilike('order_status', '%Shipping%').execute()

            return jsonify({"message": "Order is delivered."}), 200

        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post('/admin/orders/cancel-order')
    @admin_auth()
    def admin_cancel_order():
        try:
            admin_id = get_jwt()['sub']['id']
            admin = supabase.table("Admin").select("*").execute()
            if len(admin.data) == 0:
                return {'message': 'Invalid credentials'}, 401

            data = request.get_json()
            order_ids = data['order_ids']

            for order_id in order_ids:
                supabase.table('orders').update({'order_status': 'Canceled'}).eq('id', order_id).neq('order_status', '%Delivered%').execute()

            return jsonify({"message": "Order is canceled."}), 200

        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get('/admin/dashboard/graph-data')
    @admin_auth()
    def admin_dashboard_graph_data_get():
        try:
            admin_id = get_jwt()['sub']['id']
            admin = supabase.table("Admin").select("*").eq("id", admin_id).execute()
            if len(admin.data) == 0:
                return {'message': 'Invalid credentials'}, 401

            data = supabase.rpc('get_order_summary', {}).execute().data

            return jsonify({"data": data}), 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get('/admin/dashboard/most-sold-products')
    @admin_auth()
    def admin_dashboard_most_sold_products_get():
        try:
            admin_id = get_jwt()['sub']['id']
            admin = supabase.table("Admin").select("*").eq("id", admin_id).execute()
            if len(admin.data) == 0:
                return {'message': 'Invalid credentials'}, 401

            data = supabase.rpc('get_product_summary', {
                '_days': 30,
                '_limit': 3
            }).execute().data

            return jsonify({"data": data}), 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get('/admin/contacts')
    @admin_auth()
    def admin_contacts_get():
        try:
            admin_id = get_jwt()['sub']['id']
            admin = supabase.table("Admin").select("*").eq("id", admin_id).execute()
            if len(admin.data) == 0:
                return {'message': 'Invalid credentials'}, 401
            
            input_data = request.get_json()
            page_size = input_data['page_size']

            number_of_contacts = supabase.table('contact').select('*', count="exact").order("created_at", desc=True).execute().count
            page_number = number_of_contacts // page_size + 1

            return jsonify({"page_number": page_number}), 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post('/admin/contacts/<int:page_number>')
    @admin_auth()
    def admin_contacts_post(page_number):
        try:
            admin_id = get_jwt()['sub']['id']
            admin = supabase.table("Admin").select("*").eq("id", admin_id).execute()
            if len(admin.data) == 0:
                return {'message': 'Invalid credentials'}, 401
            
            input_data = request.get_json()
            page_size = input_data['page_size']

            contacts = supabase.table('contact').select('*').order("created_at", desc=True).limit(page_size).offset((page_number - 1) * (page_size)).execute().data

            return jsonify({"contacts": contacts}), 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500

    return app

@stub.function(name="dealer", 
               image=image)
@wsgi_app()
def dealer():
    from supabase import create_client, Client
    from flask_cors import CORS
    from flask import Flask, jsonify, request
    from flask_bcrypt import Bcrypt

    app = Flask(__name__)
    app.config.from_object(Config)
    CORS(app)

    bcrypt = Bcrypt(app)
    jwt = JWTManager(app)

    url: str = app.config["SUPABASE_URL"]
    key: str = app.config["SUPABASE_KEY"]
    supabase: Client = create_client(url, key)

    def generate_confirmation_token(email):
        try:
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
        except Exception as e:
            return -1
        
    def confirm_token(token, expiration=3600):
        try:
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            email = serializer.loads(
                token,
                salt=app.config['SECURITY_PASSWORD_SALT'],
                max_age=expiration
            )
            return email
        except Exception as e:
            return -1
        
    @app.post("/dealer/login")
    def dealer_login():
        try:
            data = request.get_json()

            email = data["email"]
            password = data["password"]
            
            dealer = supabase.table("dealer").select("*").eq("email", email).execute()
            if len(dealer.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            if not bcrypt.check_password_hash(dealer.data[0]["password"], password):
                return {"message": "Invalid credentials"}, 401
            
            if not dealer.data[0]["is_active"]:
                return {"message": "Your account is not active."}, 401
            
            access_token = create_access_token(identity={"user_type": "dealer", "id": dealer.data[0]["id"]})
            return {"access_token": access_token}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
    
    @app.post("/dealer/register")
    def dealer_register():
        try:
            data = request.get_json()
            email = data["email"]
            password = data["password"]
            name = data["name"]
            address = data["address"]
            city = data["city"]
            country = data["country"]
            phone = data["phone"]
            
            dealer = supabase.table("dealer").select("*").eq("email", email).execute()
            if len(dealer.data) > 0:
                return {"message": "Email already exists"}, 401
            
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            supabase.table("dealer").insert({"email": email, "password": hashed_password, "name": name, "address": address, "city": city, "country": country, "phone": phone}).execute()
            return {"message": "Dealer added successfully"}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/dealer/forgot-password")
    def dealer_forgot_password():
        try:
            data = request.get_json()
            email = data["email"]
            
            dealer = supabase.table("dealer").select("*").eq("email", email).execute()
            if len(dealer.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            token = generate_confirmation_token(email)

            if token == -1:
                return {"message": "Something went wrong"}, 500
            
            send_mail("Reset Password", f"Please click the link to reset your password:\nhttp://localhost:3000/dealer/reset-password/{token}", email)

            return {"token": token}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/dealer/reset-password/<token>")
    def dealer_reset_password(token):
        try:
            data = request.get_json()
            password = data["password"]
            
            email = confirm_token(token)
            if email == -1:
                return {"message": "Invalid token"}, 401
            
            dealer = supabase.table("dealer").select("*").eq("email", email).execute()
            if len(dealer.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            supabase.table("dealer").update({"password": hashed_password}).eq("email", email).execute()
            return {"message": "Password changed successfully"}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/dealer/change-password")
    @dealer_auth()
    def dealer_change_password():
        try:
            dealer_id = get_jwt()["sub"]["id"]
            dealer = supabase.table("dealer").select("*").eq("id", dealer_id).execute()
            if len(dealer.data) == 0:
                return {"message": "Invalid credentials"}, 401

            data = request.get_json()

            if not bcrypt.check_password_hash(dealer.data[0]["password"], data["old_password"]):
                return {"message": "Invalid credentials"}, 401
            
            hashed_password = bcrypt.generate_password_hash(data["new_password"]).decode("utf-8")
            
            supabase.table("dealer").update({"password": hashed_password}).eq("id", dealer_id).execute()
            return {"message": "Password changed successfully"}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get("/dealer/info")
    @dealer_auth()
    def dealer_info():
        try:
            dealer_id = get_jwt()["sub"]["id"]
            dealer = supabase.table("dealer").select("*").eq("id", dealer_id).execute()
            if len(dealer.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            return {"dealer": dealer.data[0]}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/dealer/edit")
    @dealer_auth()
    def dealer_edit():
        try:
            dealer_id = get_jwt()["sub"]["id"]
            dealer = supabase.table("dealer").select("*").eq("id", dealer_id).execute()
            if len(dealer.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            data = request.get_json()

            data = {key: data[key] for key in ["name", "address", "city", "country", "phone", "email"] if key in data}

            if "email" in data:
                dealer = supabase.table("dealer").select("*").eq("email", data["email"]).execute()
                if len(dealer.data) > 0:
                    return {"message": "Email already exists"}, 401
                
            supabase.table("dealer").update(data).eq("id", dealer_id).execute()
            return {"message": "Dealer updated successfully"}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get("/dealer/categories")
    def dealer_categories():
        try:
            categories = supabase.table("category").select("*").execute()
            return {"categories": categories.data}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get("/dealer/all-products")
    def dealer_all_products():
        try:
            products = supabase.table("products").select("*").eq("is_active", True).execute()
            return {"products": products.data}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500    
        
    @app.get("/dealer/products")
    def dealer_products():
        try:
            data = request.get_json()
            search = data["search"]
            categories = data["categories"]
            page_size = data["page_size"]

            products_count = supabase.table("products").select("id", count="exact").eq("is_active", True)

            if search != "":
                products_count = products_count.ilike("name", f"%{search}%")

            if len(categories) > 0:
                products_count = products_count.in_("category_id", categories)

            products_count = products_count.execute().count

            number_of_pages = products_count // page_size + 1
            return {"number_of_pages":number_of_pages}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/dealer/products/<int:page_number>")
    def dealer_products_post(page_number):
        try:
            data = request.get_json()
            search = data["search"]
            categories = data["categories"]
            page_size = data["page_size"]
            order_feature = ""
            order = ""

            products = supabase.table("products").select("*").eq("is_active", True)

            if search != "":
                products = products.ilike("name", f"%{search}%")

            if len(categories) > 0:
                products = products.in_("category_id", categories)

            if order_feature != "" and order != "" and order_feature in ["name", "price", "created_at"]:
                products = products.order(order_feature, desc= True if order == "desc" else False)

            products = products.limit(page_size).offset((page_number - 1) * (page_size)).execute()
            return {"products": products.data}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get("/dealer/product/<int:id>")
    def dealer_product_details(id):
        try:
            product = supabase.table("products").select("*").eq("id", id).execute()
            if len(product.data) == 0 or product.data[0]["is_active"] == False:
                return {"message": "Product not found"}, 401
            
            return {"product": product.data[0]}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/dealer/contact")
    def dealer_contact():
        try:
            data = request.get_json()
            id = data["id"]
            name = data["name"]
            email = data["email"]
            description = data["description"]

            if data["id"] == "":
                del data["id"]
            
            supabase.table("contact").insert(data).execute()
            return {"message": "Message sent successfully"}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/dealer/my-orders/<int:page_number>")
    @dealer_auth()
    def dealer_my_orders(page_number):
        try:
            dealer_id = get_jwt()["sub"]["id"]
            print(dealer_id)
            dealer = supabase.table("dealer").select("*").eq("id", dealer_id).execute()
            if len(dealer.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            data = request.get_json()
            order_status = data['order_status']
            start_date = data['start_date']
            end_date = data['end_date']
            product_search = data['product_search']
            page_size = data['page_size']

            query = supabase.table('order_details').select('''order_id, quantity, products!inner(name, price), orders!inner(dealer_id, order_status, description, cargo_brand, cargo_id, created_at, dealer!inner(email, name, address, city, country, phone))''', count='exact')
            query = query.eq('orders.order_status', order_status)
            query = query.eq('orders.dealer_id', dealer_id)

            if start_date != "" and end_date != "":
                query = query.gte('orders.created_at', start_date)
                query = query.lte('orders.created_at', end_date)

            if product_search != "":
                query = query.ilike('products.name', f'%{product_search}%')

            query = query.order('created_at', desc=True, foreign_table='orders')
            query = query.limit(page_size).offset((page_number - 1) * (page_size))

            orders = query.execute()
 
            return {"orders": orders.data}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/dealer/my-orders-max-page")
    @dealer_auth()
    def dealer_my_orders_get():
        try:
            dealer_id = get_jwt()["sub"]["id"]
            dealer = supabase.table("dealer").select("*").eq("id", dealer_id).execute()
            if len(dealer.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            data = request.get_json()
            order_status = data['order_status']
            start_date = data['start_date']
            end_date = data['end_date']
            product_search = data['product_search']
            page_size = data['page_size']

            query = supabase.table('order_details').select('''order_id, quantity, products!inner(name, price), orders!inner(dealer_id, order_status, description, cargo_brand, cargo_id, created_at, dealer!inner(email, name, address, city, country, phone))''', count='exact')
            query = query.eq('orders.order_status', order_status)
            query = query.eq('orders.dealer_id', dealer_id)

            if start_date != "" and end_date != "":
                query = query.gte('orders.created_at', start_date)
                query = query.lte('orders.created_at', end_date)

            if product_search != "":
                query = query.ilike('products.name', f'%{product_search}%')

            number_of_orders = query.execute().count

            page_number = number_of_orders // page_size + 1

            return jsonify({"page_number": page_number}), 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.post("/dealer/create-order")
    @dealer_auth()
    def dealer_create_order():
        try:
            dealer_id = get_jwt()["sub"]["id"]
            dealer = supabase.table("dealer").select("*").eq("id", dealer_id).execute()
            if len(dealer.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            data = request.get_json()
            products = data["products"]
            quantities = data["quantities"]
            description = data["description"]
            cargo_brand = data["cargo_brand"]

            card_number = data["card_number"]
            card_fullname = data["card_fullname"]
            card_month = data["card_month"]
            card_year = data["card_year"]
            card_cvv = data["card_cvv"]
            card_is_save = data["card_is_save"]
            print(data)
            if card_is_save:
                card = supabase.table("payment").select("*").eq("card_number", card_number).eq("dealer_id", dealer_id).execute()
                if len(card.data) == 0:
                    supabase.table("payment").insert({"card_number": card_number, 
                                                      "full_name": card_fullname, 
                                                      "month": card_month, 
                                                      "year": card_year, 
                                                      "cvv": card_cvv, 
                                                      "dealer_id": dealer_id}).execute()
            
            for product in products:
                product = supabase.table("products").select("*").eq("id", product).execute()
                if len(product.data) == 0 or product.data[0]["is_active"] == False:
                    return {"message": "Invalid product"}, 401
                
            if not all(quantity > 0 for quantity in quantities):
                return {"message": "Invalid quantity"}, 401

            order = supabase.table("orders").insert({"dealer_id": dealer_id, "order_status": "Waiting", "description": description, "cargo_brand": cargo_brand}).execute()
            order_id = order.data[0]["id"]

            for product, quantity in zip(products, quantities):
                supabase.table("order_details").insert({"order_id": order_id, "product_id": product, "quantity": quantity}).execute()

            return {"message": "Order created successfully"}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500
        
    @app.get("/dealer/saved-payments")
    @dealer_auth()
    def dealer_saved_payments():
        try:
            dealer_id = get_jwt()["sub"]["id"]
            dealer = supabase.table("dealer").select("*").eq("id", dealer_id).execute()
            if len(dealer.data) == 0:
                return {"message": "Invalid credentials"}, 401
            
            payments = supabase.table("payment").select("*").eq("dealer_id", dealer_id).execute()
            return {"payments": payments.data}, 200
        except Exception as e:
            print(e)
            return {'message': 'Something went wrong.'}, 500


    return app
