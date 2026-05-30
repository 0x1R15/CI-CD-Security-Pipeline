import os
import tempfile
import pytest
from app.app import app, DB_PATH, init_db

@pytest.fixture
def client():
    # Use a temporary database for testing
    db_fd, temp_db_path = tempfile.mkstemp()
    app.config['TESTING'] = True
    app.config['DATABASE'] = temp_db_path
    
    # Configure app database path dynamically for testing
    import app.app as app_module
    old_db_path = app_module.DB_PATH
    app_module.DB_PATH = temp_db_path
    
    with app.test_client() as client:
        with app.app_context():
            init_db()
        yield client
        
    # Teardown
    app_module.DB_PATH = old_db_path
    os.close(db_fd)
    os.unlink(temp_db_path)

def test_login_page_renders(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b"Secure CI/CD Demo" in response.data

def test_successful_login(client):
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'SuperSecurePassword123!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Welcome" in response.data
    assert b"admin" in response.data

def test_failed_login(client):
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'WrongPassword!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Invalid credentials" in response.data

def test_security_headers(client):
    response = client.get('/login')
    headers = response.headers
    
    # Check secure HTTP headers added by Flask-Talisman
    assert 'Content-Security-Policy' in headers
    assert 'X-Frame-Options' in headers
    assert 'X-Content-Type-Options' in headers
    assert headers['X-Frame-Options'] == 'DENY'
    assert headers['X-Content-Type-Options'] == 'nosniff'

def test_unauthorized_dashboard_redirect(client):
    response = client.get('/dashboard', follow_redirects=False)
    assert response.status_code == 302
    assert '/login' in response.headers['Location']
