from decimal import Decimal
from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
import requests
import uuid
from collections import defaultdict
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# API Gateway URL
PRODUCTS_API_URL = os.getenv('PRODUCTS_API_URL')
USER_AUTH_API_URL = os.getenv('USER_AUTH_API_URL')
ORDERS_API_URL = os.getenv('ORDERS_API_URL')


# Decorator to check if user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('You need to log in first.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Decorator to restrict access to Administrators only
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'Administrator':
            flash('You do not have the required permissions.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# Decorator to restrict access to Merchants only
def merchant_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'Merchant':
            flash('You do not have the required permissions.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function



################################################################################
# Home
################################################################################
@app.route('/')
def home():
    return render_template('index.html')


################################################################################
# User Authentication
################################################################################
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Send data to API Gateway /login
        response = requests.post(f'{USER_AUTH_API_URL}/login', json={
            'username': username,
            'password': password
        })

        if response.status_code == 200:
            user_data = response.json()
            session['logged_in'] = True
            session['user_id'] = user_data['user_id']
            session['user_name'] = username
            session['role'] = user_data['role'] 

            flash('Login successful!', 'success')

            # Redirect based on the role
            if session['role'] == 'Administrator':
                return redirect(url_for('admin_dashboard'))
            elif session['role'] == 'Merchant':
                return redirect(url_for('merchant_dashboard'))
            else:
                flash('Unknown role, contact support.', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

# Route to handle registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        # Send data to API Gateway /register
        response = requests.post(f'{USER_AUTH_API_URL}/register', json={
            'username': username,
            'email': email,
            'password': password,
            'role': role
        })

        if response.status_code == 201:
            flash('User registered successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Please try again.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')


# Logout route
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('role', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


################################################################################
# Dashboard
################################################################################
@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')

    if role == 'Administrator':
        return redirect(url_for('admin_dashboard'))
    elif role == 'Merchant':
        return redirect(url_for('merchant_dashboard'))
    else:
        flash('Unknown role. Please contact support.', 'danger')
        return redirect(url_for('login'))



################################################################################
# Admin
################################################################################
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        # Fetch data from the API for dashboard summary
        orders_response = requests.get(f'{ORDERS_API_URL}/cms/admin/orders')
        products_response = requests.get(PRODUCTS_API_URL)
        users_response = requests.get(f'{USER_AUTH_API_URL}/users')
        
        orders_data = orders_response.json()
        products_data = products_response.json()
        users_data = users_response.json()

        # Validate that API responses are lists
        if not isinstance(orders_data, list):
            orders_data = []
        
        if not isinstance(products_data, list):
            products_data = []

        if not isinstance(users_data, list):
            users_data = []

        # Calculate total orders and total revenue
        total_orders = len(orders_data)
        total_revenue = round(sum(float(order['TotalPrice']) for order in orders_data if 'TotalPrice' in order), 2)

        # Get total products
        total_products = len(products_data)

        # Get total users
        total_users = len(users_data)

        # Prepare data for the Google chart (aggregate by date)
        date_aggregated_summary = defaultdict(float)
        for order in orders_data:
            if 'OrderDate' in order and 'TotalPrice' in order:
                order_date = order['OrderDate'].split(' ')[0]
                date_aggregated_summary[order_date] += float(order['TotalPrice'])

        # Convert the defaultdict to a list of tuples, sorted by date
        order_summary = sorted(date_aggregated_summary.items()) 

        # Prepare data for the Sales by Merchants chart
        sales_by_merchant = defaultdict(float)
        for order in orders_data:
            if 'CartItems' in order:
                for item in order['CartItems']:
                    merchant_id = item.get('MerchantName')
                    price = float(item.get('Price', 0))  # Handle cases where Price might be missing
                    sales_by_merchant[merchant_id] += price
        

        # Prepare data for Orders by Status chart
        orders_by_status = defaultdict(int)
        for order in orders_data:
            if 'OrderStatus' in order:
                status = order['OrderStatus']
                orders_by_status[status] += 1

        # Render the dashboard with all the prepared data
        return render_template(
            'admin_dashboard.html', 
            total_orders=total_orders, 
            total_revenue=total_revenue, 
            total_products=total_products,
            total_users=total_users, 
            order_summary=order_summary,
            sales_by_merchant=sales_by_merchant.items(),
            orders_by_status=orders_by_status.items() 
        )
    except Exception as e:
        flash(f"Error occurred: {str(e)}", 'danger')
        return redirect(url_for('admin_dashboard'))


###################
# Admin Users
###################
@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
    # Send GET request to API Gateway to fetch all users
    response = requests.get(f'{USER_AUTH_API_URL}/users')

    if response.status_code == 200:
        users = response.json() 
        return render_template('admin_users.html', users=users)
    else:
        flash('Error retrieving users list.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
@app.route('/users/<user_id>', methods=['GET', 'POST'])
@login_required
def get_user(user_id):
    response = requests.get(f'{USER_AUTH_API_URL}/users/{user_id}')
    
    if response.status_code == 200:
        user_data = response.json()
        return render_template('user_profile.html', user=user_data)
    else:
        flash('Error retrieving user data.', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/users/<user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']

        # Send a PUT request to API Gateway to update the user
        response = requests.put(f'{USER_AUTH_API_URL}/users/{user_id}', json={
            'username': username,
            'email': email,
            'role': role 
        })

        if response.status_code == 200:
            flash('User updated successfully.', 'success')
            return redirect(url_for('admin_users'))
        else:
            flash('Failed to update user.', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))

    # GET request: Get user details to pre-fill the form
    response = requests.get(f'{USER_AUTH_API_URL}/users/{user_id}')
    
    if response.status_code == 200:
        user = response.json()
        return render_template('admin_edit_user.html', user=user)
    else:
        flash('Error retrieving user details.', 'danger')
        return redirect(url_for('admin_users'))


@app.route('/users/<user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    response = requests.delete(f'{USER_AUTH_API_URL}/users/{user_id}')
    
    if response.status_code == 200:
        flash('User deleted successfully.', 'success')
        return redirect(url_for('admin_users'))
    else:
        flash('Failed to delete user.', 'danger')
        return redirect(url_for('admin_users', user_id=user_id))


###################
# Admin Products
###################
@app.route('/admin/products', methods=['GET'])
@admin_required
def admin_products():
    try:
        # Send a GET request to the API Gateway to retrieve products
        response = requests.get(PRODUCTS_API_URL)
        
        if response.status_code == 200:
            products = response.json()  
            return render_template('admin_products.html', products=products)
        else:
            flash('Failed to retrieve products.', 'danger')
            return redirect(url_for('admin_dashboard')) 
    except Exception as e:
        flash(f'Error occurred: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))
    

@app.route('/admin/products/<product_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    if request.method == 'POST':
        # Get form data to update the product
        product_name = request.form['product_name']
        description = request.form['description']
        image_url = request.form['image_url']
        price = request.form['price']
        
        # Send PUT request to API Gateway to update the product
        response = requests.put(f'{PRODUCTS_API_URL}/{product_id}', json={
            'ProductName': product_name,
            'Description': description,
            'ImageUrl': image_url,
            'Price': price
        })
        
        if response.status_code == 200:
            flash('Product updated successfully!', 'success')
            return redirect(url_for('admin_products'))
        else:
            flash('Failed to update product.', 'danger')
            return redirect(url_for('edit_product', product_id=product_id))

    # GET request: Retrieve product details to pre-fill the form
    response = requests.get(f'{PRODUCTS_API_URL}/{product_id}')
    
    if response.status_code == 200:
        product = response.json()
        return render_template('admin_edit_product.html', product=product)
    else:
        flash('Error retrieving product details.', 'danger')
        return redirect(url_for('admin_products'))


@app.route('/admin/products/add', methods=['GET', 'POST'])
@admin_required
def admin_add_product():
    if request.method == 'POST':
        # Extract form data
        product_name = request.form['product_name']
        price = request.form['price']
        description = request.form['description']
        quantity = request.form['quantity']
        image_url = request.form['image_url']

        # Generate a unique ProductID
        product_id = str(uuid.uuid4())

        # Convert price to a float and quantity to an int
        try:
            price = float(price)
            quantity = int(quantity)
        except ValueError:
            flash('Invalid price or quantity. Please enter valid numbers.', 'danger')
            return redirect(url_for('admin_add_product'))

        # Prepare data to send to the API (or directly to the database)
        product_data = {
            'ProductID': product_id,
            'ProductName': product_name,
            'Price': price,
            'Description': description,
            'Quantity': quantity,
            'ImageUrl': image_url,
            'MerchantID': 'ADMIN',
            'MerchantName': 'ADMIN'
        }

        # Make a POST request to add the product to the database/API
        response = requests.post(f'{PRODUCTS_API_URL}', json=product_data)

        if response.status_code == 201:
            flash('Product added successfully.', 'success')
        else:
            flash(f'Failed to add the product. {response.text}', 'danger')

        return redirect(url_for('admin_products'))

    return render_template('admin_add_product.html')


@app.route('/admin/products/<product_id>/delete', methods=['POST'])
@admin_required
def delete_product(product_id):
    try:
        # Send DELETE request to API Gateway to delete the product by product_id
        response = requests.delete(f'{PRODUCTS_API_URL}/{product_id}')
        
        if response.status_code == 200:
            flash('Product deleted successfully!', 'success')
        else:
            flash('Failed to delete product.', 'danger')
        
        return redirect(url_for('admin_products'))
    except Exception as e:
        flash(f'Error occurred: {str(e)}', 'danger')
        return redirect(url_for('admin_products'))


###################
# Admin Orders
###################
@app.route('/admin/orders', methods=['GET'])
@admin_required  # Ensuring only admins can access
def admin_orders():
    try:
        # Send a GET request to fetch all orders
        response = requests.get(f'{ORDERS_API_URL}/cms/admin/orders')
        
        
        if response.status_code == 200:
            orders = response.json()  
                
            # Sort items in the order by OrderDate (descending) 
            orders = sorted(orders, key=lambda x: x['OrderDate'], reverse=True)  
            
            return render_template('admin_orders.html', orders=orders)
        else:
            flash('Failed to retrieve orders.', 'danger')
            return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash(f'Error occurred: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/order_product/<order_id>', methods=['GET'])
@admin_required
def view_order(order_id):
    try:
        # Fetch the order details from the API (no need for 'user_id' in params if not needed)
        response = requests.get(f'{ORDERS_API_URL}/cms/admin/orders/{order_id}')
        
        if response.status_code == 200:
            order = response.json()  
            return render_template('admin_view_order.html', order=order) 
        
        elif response.status_code == 404:
            flash('Order not found.', 'warning') 
        
        else:
            flash('Failed to retrieve order details.', 'danger') 

        # Redirect back to the orders page in case of failure
        return redirect(url_for('admin_orders'))
    
    except Exception as e:
        # Handle any exceptions that occur during the API call or rendering
        flash(f'Error occurred: {str(e)}', 'danger')
        return redirect(url_for('admin_orders'))


@app.route('/admin/order_product/<order_id>/update', methods=['POST'])
@admin_required
def update_order(order_id):
    try:
        # Send PUT request to update the order status or other details
        response = requests.put(f'{ORDERS_API_URL}/order_product/{order_id}', json={
            'status': request.form['status']
        })
        if response.status_code == 200:
            flash('Order updated successfully!', 'success')
        else:
            flash('Failed to update order.', 'danger')
        return redirect(url_for('admin_orders'))
    except Exception as e:
        flash(f'Error occurred: {str(e)}', 'danger')
        return redirect(url_for('admin_orders'))


@app.route('/admin/order_product/<order_id>/delete', methods=['POST'])
@admin_required
def delete_order(order_id):
    try:
        # Send DELETE request to remove the order
        response = requests.delete(f'{ORDERS_API_URL}/cms/admin/orders/{order_id}?user_id={session["user_id"]}')
        if response.status_code == 200:
            flash('Order deleted successfully!', 'success')
        else:
            flash('Failed to delete order.', 'danger')
        return redirect(url_for('admin_orders'))
    except Exception as e:
        flash(f'Error occurred: {str(e)}', 'danger')
        return redirect(url_for('admin_orders'))


############################################################################
# Merchant
############################################################################
@app.route('/merchant/dashboard')
@merchant_required
def merchant_dashboard():
    try:
        # Fetch data from the API for dashboard summary
        products_response = requests.get(f'{PRODUCTS_API_URL}?merchant_id={session["user_id"]}')
        orders_response = requests.get(f'{ORDERS_API_URL}/cms/merchant/orders/{session["user_id"]}')
        
        products_data = products_response.json()
        orders_data = orders_response.json()

        if not isinstance(products_data, list):
            products_data = []
        
        if not isinstance(orders_data, list):
            orders_data = []

        # Calculate total products, orders, and total sales (revenue)
        total_products = len(products_data)
        total_orders = len(orders_data)
        total_sales = round(sum(float(order['TotalPrice']) for order in orders_data if 'TotalPrice' in order), 2)

        # Prepare data for the sales chart (aggregate by date)
        date_aggregated_sales = defaultdict(float)
        for order in orders_data:
            if 'OrderDate' in order and 'TotalPrice' in order:
                order_date = order['OrderDate'].split(' ')[0]  
                date_aggregated_sales[order_date] += float(order['TotalPrice'])

        # Convert the defaultdict to a list of tuples, sorted by date
        sales_summary = sorted(date_aggregated_sales.items())  # List of (date, total_sales) tuples

        return render_template('merchant_dashboard.html', 
                               total_products=total_products, 
                               total_orders=total_orders, 
                               total_sales=total_sales, 
                               sales_summary=sales_summary)
    except Exception as e:
        flash(f"Error occurred: {str(e)}", 'danger')
        return redirect(url_for('merchant_dashboard'))


###################
# Admin Products
###################
@app.route('/merchant/products')
@merchant_required
def merchant_products():
    # Fetch products related to the logged-in merchant
    products_response = requests.get(f'{PRODUCTS_API_URL}?merchant_id={session["user_id"]}')
    products_data = products_response.json()
    return render_template('merchant_products.html', products=products_data)


@app.route('/merchant/products/add', methods=['GET', 'POST'])
@merchant_required
def merchant_add_product():
    if request.method == 'POST':
        product_name = request.form['product_name']
        price = request.form['price']
        description = request.form['description']
        image_url = request.form['image_url']

        # Generate a unique ProductID
        product_id = str(uuid.uuid4())  

        # Convert price to a float
        try:
            price = float(price)
        except ValueError:
            flash('Invalid price. Please enter a valid number.', 'danger')
            return redirect(url_for('merchant_add_product'))

        # Prepare data to send to the API (or directly to the database)
        product_data = {
            'ProductID': product_id,  
            'ProductName': product_name,
            'Price': price,
            'Description': description,
            'ImageUrl': image_url,
            'MerchantID': session['user_id'],
            'MerchantName': session['user_name']
        }

        # Make a POST request to add the product to the database/API
        response = requests.post(f'{PRODUCTS_API_URL}', json=product_data)

        if response.status_code == 201:
            flash('Product added successfully.', 'success')
        else:
            flash(f'Failed to add the product. {response.text}', 'danger')

        return redirect(url_for('merchant_products'))

    return render_template('merchant_add_product.html')



@app.route('/merchant/products/<product_id>/edit', methods=['GET', 'POST'])
@merchant_required  
def merchant_edit_product(product_id):
    if request.method == 'POST':
        product_name = request.form['product_name']
        price = request.form['price']
        description = request.form['description']
        image_url = request.form['image_url']

        # Prepare data for updating the product
        product_data = {
            'ProductName': product_name,
            'Price': price,
            'Description': description,
            'ImageUrl': image_url
        }

        # Send a PUT request to the API Gateway to update the product
        response = requests.put(f'{PRODUCTS_API_URL}/{product_id}', json=product_data)

        if response.status_code == 200:
            flash('Product updated successfully.', 'success')
        else:
            flash('Failed to update the product.', 'danger')

        return redirect(url_for('merchant_products'))

    # If GET request, fetch the product details to pre-fill the form
    response = requests.get(f'{PRODUCTS_API_URL}/{product_id}')
    
    if response.status_code == 200:
        product = response.json()
        return render_template('merchant_edit_product.html', product=product)
    else:
        flash('Error retrieving product details.', 'danger')
        return redirect(url_for('merchant_products'))


@app.route('/merchant/products/<product_id>/delete', methods=['POST'])
@merchant_required
def merchant_delete_product(product_id):
    # Send a DELETE request to the API Gateway to delete the product
    response = requests.delete(f'{PRODUCTS_API_URL}/{product_id}')

    if response.status_code == 200:
        flash('Product deleted successfully.', 'success')
    else:
        flash('Failed to delete the product.', 'danger')

    return redirect(url_for('merchant_products'))


###################
# Admin Orders
###################
@app.route('/merchant/orders')
@merchant_required
def merchant_orders():
    # Fetch orders related to the logged-in merchant's products
    merchant_id = session['user_id']
    orders_response = requests.get(f'{ORDERS_API_URL}/cms/merchant/orders/{merchant_id}')
    orders_data = orders_response.json()
    
    # Sort items in the order by OrderDate (descending) 
    orders_data = sorted(orders_data, key=lambda x: x['OrderDate'], reverse=True)        

    return render_template('merchant_orders.html', orders=orders_data)


@app.route('/merchant/orders/<order_id>', methods=['GET'])
@merchant_required
def view_merchant_order(order_id):
    try:
        merchant_id = session['user_id']
        response = requests.get(f'{ORDERS_API_URL}/cms/merchant/orders/{merchant_id}/{order_id}')
        
        if response.status_code == 200:
            order = response.json()
            
            return render_template('merchant_view_orders.html', order=order)
        else:
            flash('Order not found', 'danger')
            return redirect(url_for('merchant_orders'))
    except Exception as e:
        flash(f'Error occurred: {str(e)}', 'danger')
        return redirect(url_for('merchant_orders'))


@app.route('/merchant/orders/<order_id>/delete', methods=['POST'])
@merchant_required
def delete_merchant_order(order_id):
    # Send DELETE request to API Gateway to delete the order
    response = requests.delete(f'{ORDERS_API_URL}/{order_id}?merchant_id={session["user_id"]}')
    if response.status_code == 200:
        flash('Order deleted successfully.', 'success')
    else:
        flash('Failed to delete order.', 'danger')
    return redirect(url_for('merchant_orders'))



if __name__ == '__main__':
    app.run(debug=True)
