// Authentication JavaScript

const API_BASE_URL = '';

// Helper function to show alerts
function showAlert(message, type = 'danger') {
    const alertContainer = document.getElementById('alert-container');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    alertContainer.appendChild(alert);
    
    setTimeout(() => {
        alert.remove();
    }, 5000);
}

// Login Form Handler
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const loginBtn = document.getElementById('loginBtn');
        
        loginBtn.disabled = true;
        loginBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Logging in...';
        
        try {
            // FastAPI OAuth2 expects form data with username/password fields
            const formData = new URLSearchParams();
            formData.append('username', email);
            formData.append('password', password);
            
            const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Store token
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('user_email', email);
                
                showAlert('Login successful! Redirecting...', 'success');
                
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1000);
            } else {
                showAlert(data.detail || 'Login failed. Please check your credentials.', 'danger');
                loginBtn.disabled = false;
                loginBtn.innerHTML = '<i class="bi bi-box-arrow-in-right"></i> Login';
            }
        } catch (error) {
            console.error('Login error:', error);
            showAlert('An error occurred. Please try again.', 'danger');
            loginBtn.disabled = false;
            loginBtn.innerHTML = '<i class="bi bi-box-arrow-in-right"></i> Login';
        }
    });
}

// Register Form Handler
const registerForm = document.getElementById('registerForm');
if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        const registerBtn = document.getElementById('registerBtn');
        
        // Validate passwords match
        if (password !== confirmPassword) {
            showAlert('Passwords do not match!', 'danger');
            return;
        }
        
        registerBtn.disabled = true;
        registerBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Creating account...';
        
        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                showAlert('Account created successfully! Redirecting to login...', 'success');
                
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);
            } else {
                showAlert(data.detail || 'Registration failed. Please try again.', 'danger');
                registerBtn.disabled = false;
                registerBtn.innerHTML = '<i class="bi bi-person-plus"></i> Create Account';
            }
        } catch (error) {
            console.error('Registration error:', error);
            showAlert('An error occurred. Please try again.', 'danger');
            registerBtn.disabled = false;
            registerBtn.innerHTML = '<i class="bi bi-person-plus"></i> Create Account';
        }
    });
}
