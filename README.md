# Securing an Existing Banking Application - Security Assessment and Improvement of a Web-Based Banking Application


### Group Members: 
- Laurence Bryan Belen
- Lily Rose Julianes
- Kenth Lorenz Collao

**Live Web App**: [Deployed Banking Application]

**Video Presentation**: [Youtube Link]

---
---

## **Introduction**
The Simple Banking App is a secure and user-friendly web application developed using the Flask framework, integrated with a MySQL database to facilitate essential banking functionalities. Designed for both standard users and administrators, it supports account creation, secure login, balance inquiries, transaction tracking, and peer-to-peer money transfers. Each user is assigned a unique account number, and all financial activities are meticulously recorded to ensure transparency and accountability.

Security is at the forefront of the application’s design. It utilizes bcrypt for password hashing, Flask-Login for session management, CSRF protection to prevent cross-site request forgery, and rate limiting to prevent abuse. Additionally, the app features an admin dashboard that allows administrators and managers to monitor operations, manage users, and uphold system integrity.

Environment-based configuration guarantees seamless deployment across both development and production environments. The backend is underpinned by a well-structured SQL schema that employs indexing and relational constraints to maintain data consistency and optimize performance. Overall, the application offers a reliable and extensible framework for delivering essential banking services online.

---
---

## **Objectives**

- Implement robust user authentication and role-based access control.
- Enable users to perform essential banking transactions, including transfers and balance inquiries.
- Safeguard the system against security threats such as SQL injection, CSRF attacks, and excessive request abuse.
- Design for scalability and maintainability using clean architecture and modular design principles.

---
---

## **Original Application Features**

User authentication using Flask-Login and bcrypt for password hashing.

Transaction logging and user account management.

CSRF protection with Flask-WTF.

Rate limiting using Flask-Limiter to prevent abuse of endpoints.

Database-backed with MySQL using SQLAlchemy.

---
---
<div align = 'center'>
<center>
<h1>Security Assessment Findings</h1>
</center>
</div>

### **OWASP ZAP Security QA Report**

### **Identified Vulnerabilities**

##### **Medium Priority**

| Vulnerability                          | Description                                                                 |
|----------------------------------------|-----------------------------------------------------------------------------|
| **Content Security Policy (CSP) Header Not Set** | The application does not set a CSP header, which helps prevent XSS and data injection attacks. |
| **Missing Anti-clickjacking Header**   | X-Frame-Options or Content-Security-Policy with frame-ancestors directive is missing, making the site vulnerable to clickjacking. |

#### **Low Priority**

| Vulnerability                          | Description                                                                 |
|----------------------------------------|-----------------------------------------------------------------------------|
| **Application Error Disclosure**       | The application reveals internal error messages that could help an attacker understand backend logic. |
| **Cookie Without Secure Flag**         | Cookies are set without the 'Secure' flag, meaning they could be transmitted over non-HTTPS connections. |
| **Cookie Without SameSite Attribute**  | Cookies are missing the SameSite attribute, which helps prevent CSRF attacks. |
| **Cross-Domain JavaScript Source File Inclusion** | External JavaScript files are included from different domains, increasing the risk of external code compromise. |
| **Information Disclosure - Debug Error Messages** | Debug-level error messages are exposed, potentially leaking sensitive information to attackers. |


The security review of the system also revealed several critical vulnerabilities and weaknesses that could expose it to both external and internal threats.

1. Weak Password Practices
    - Passwords stored with minimal validation.
    - Use of weak default credentials increases risk of unauthorized access.

2. Financial Calculation Risk
    - Use of floating-point values for balance calculations can lead to rounding errors.

3.  API Error Handling
    - Lack of error handling for PSGC API failures

4.   XSS Vulnerability
    - No output escaping on user-generated content (risk of Cross-Site Scripting).

5.  Data Transmission Security
    - No HTTPS enforcement; sensitive data may be intercepted.
    - Missing security headers reduce resistance to web attacks.

6.   Session and CSRF Issues
    - Incomplete session management.
    - CSRF token implementation is inconsistent or missing.

7.   Outdated Dependencies
    - Use of outdated third-party packages with known vulnerabilities.

8. Lack of Audit Logging
    - Admin/manager actions are untracked.
    - No audit trail exists for sensitive operations.

---
---

<div align = 'center'>
<center>
<h1>Security Improvements Implemented</h1>
</center>
</div>

### *app.py*

**Original code**
```python
# Create Flask application
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
```

The original implementation sets the SECRET_KEY to a randomly generated value using secrets.token_hex(16) if no environment variable is set. While this fallback seems secure at first glance, it introduces a critical vulnerability in a production environment where the environment variable may be unset or misconfigured.

```python
# Create Flask application
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
```
Created a .env file to securely store environment variables, including the SECRET_KEY. Environment variables are loaded securely at application startup using tools such as python-dotenv or the hosting platform’s environment variable configuration.
Restricts secret exposure to only the runtime environment, improving security posture.

**improvement**
```python
   debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
app.run(debug=debug_mode) 

added flask debugg it allows you to control Flask’s debug mode using an environment variable—helpful for toggling between development and production without changing the code.

---

### ***route.py***
#### */login*
1. **Timing Attack Vulnerability in Password Comparison**
   
The original code compared SHA-256 password hashes using a simple equality check:  
```python
if sha2_hash == user.password_hash:
```

This allows potential timing attacks where an attacker measures response time to infer partial matches, undermining password security.

***Improvements***
```python
import hmac
if hmac.compare_digest(sha2_hash, user.password_hash):
```

Replaced simple equality with hmac.compare_digest() for constant-time comparison.
Mitigates timing attacks by ensuring the comparison takes the same time regardless of matching prefix length.

<br>

2. **Lack of CSRF Protection**
   
The login route lacked explicit CSRF protection, leaving it vulnerable to Cross-Site Request Forgery attacks.

***Improvements***

Added CSRF protection, through Flask-WTF with form.hidden_tag() and CSRF tokens.
This prevents malicious sites from forging POST requests to the login endpoint.

---

#### */register*

1. **No Email Domain Validation (Disposable Emails Allowed)**
    
The original code accepted any email address without filtering disposable or temporary email services. This can lead to fake accounts, spam, and abuse.

***Improvements***
```python
disposable_domains = {'mailinator.com', '10minutemail.com', 'tempmail.com'}
email_domain = form.email.data.split('@')[-1].lower()
if email_domain in disposable_domains:
    flash('Disposable email addresses are not allowed. Please use a valid email.')
    return redirect(url_for('register'))
```
Added a deny list of disposable email domains to prevent registration with temporary or throwaway addresses.
Helps reduce spam, fake registrations, and abuse of system resources.


2. **No Duplicate Username or Email Check**
   
The function failed to verify whether the email address or login was already registered. This might permit several accounts with the same credentials or result in database issues.

***Improvements***
```python
existing_user = User.query.filter(
    (User.username == form.username.data) | (User.email == form.email.data)).first()
if existing_user:
    flash('Registration failed. Please check your input and try again.')  # generic message
    return redirect(url_for('register'))
```
Added a database query to check if the username or email already exists before creating a new user.
Uses a generic error message to avoid revealing which specific field is duplicated (prevents username/email enumeration attacks).

3. **Weak Password Policy (No Complexity Enforcement)**
 
The original registration allowed any password regardless of length or complexity, increasing risk of account compromise through weak passwords.

***Improvements***
```python
pwd = form.password.data
if (len(pwd) < 8 or 
    not re.search(r'[A-Z]', pwd) or 
    not re.search(r'[a-z]', pwd) or 
    not re.search(r'\d', pwd)):
    flash('Password must be at least 8 characters long and include uppercase, lowercase, and a number.')
    form.password.data = ''
    form.password2.data = ''
    return render_template('register.html', title='Register', form=form)
```
Enforces a minimum password length of 8 characters.
Requires at least one uppercase letter, one lowercase letter, and one digit.
Enhances overall account security by preventing weak passwords.

4. **Informative Error Messages for User Existence**

No explicit feedback was given about existing users or emails, potentially causing confusion.

***Improvements***

Upon password validation failure, clears only the password fields to avoid frustrating the user by losing all entered data.

---

#### */transfer*

1. **No Validation of `transfer_type` Input**  
The original code did not verify if the `transfer_type` field contained only allowed values (`'username'` or `'account'`). This could lead to unexpected behavior or abuse if invalid types are passed.

***Improvements***
```python
if form.transfer_type.data not in ['username', 'account']:
flash('Invalid transfer type.')
return redirect(url_for('transfer'))
```
Added explicit validation to ensure transfer_type is either 'username' or 'account'.
Prevents malformed or unexpected inputs from affecting business logic or causing errors.

2. **Recipient Enumeration Risk**  
If the recipient could not be found (for example, because the username or account number was invalid), the system replied in a different way, which could have let information about valid usernames or accounts get leaked out.

***Improvements***
```python
if not recipient:
    flash('Invalid recipient or transfer not allowed.')
    return redirect(url_for('transfer'))
```
When recipient lookup fails, a generic error message is shown rather than revealing if a username or account number exists.
This prevents attackers from probing valid accounts via response differences.

3. **Order of Balance Check and Recipient Status Check**  
The original code checked to see if there was enough money in the account before checking to see if the recipient's account was open. This could have wasted resources or accidentally shared information.

***Improvements***

Moved the recipient active status check before balance validation to avoid unnecessary processing if the recipient is inactive.

---

#### */execute_transfer*

1. **Insecure Handling of Invalid Forms**  
The original code only proceeded if `form.validate_on_submit()` passed but didn't handle the failure path explicitly. Users could bypass intended behavior or receive no useful feedback.

***Improvements***
```python
try:
    amount = float(form.amount.data)
    if amount <= 0 or amount > 1_000_000:
        flash("Invalid transfer amount.")
        return redirect(url_for('transfer'))
except ValueError:
    flash("Invalid amount format.")
    return redirect(url_for('transfer'))
```
Checks that the transfer amount is:
- A valid float.
- Greater than zero.
- Below a set cap (₱1,000,000).

Prevents negative or zero transfers and mitigates abuse such as draining accounts or service disruption through extreme values.

2. **Recipient Enumeration Risk**  
Flashing specific errors like “Recipient not found” could allow an attacker to probe for valid usernames or account numbers through timing and message analysis.

***Improvements***
```python
if not recipient or (recipient.status != 'active' and not recipient.is_admin and not recipient.is_manager):
    time.sleep(1.5)
    flash("Transfer failed. Please verify recipient details.")
    return redirect(url_for('transfer'))
```
Merged both "not found" and "inactive" recipient cases into one generic error message.
Prevents user enumeration by avoiding error message differences based on the validity of the recipient.
Bonus: Adds a 1.5-second artificial delay to deter brute-force guessing attempts.

---

#### */admin*

1. **CSRF Risk via GET Requests for State-Changing Operations**
 `activate_user` and `deactivate_user` routes used the `GET` method to modify server-side data.
An attacker could embed image tags or links to perform CSRF attacks and trigger unintended state changes (e.g., `img src="https://bank.com/admin/deactivate_user/5"`).

***Improvements***
```python
@app.route('/admin/activate_user/<int:user_id>', methods=['POST'])
@app.route('/admin/deactivate_user/<int:user_id>', methods=['POST'])
```
Uses POST for all state-changing routes.
Mitigates CSRF risks by requiring deliberate form submissions with CSRF tokens (assuming Flask-WTF is used).


2. **Account Enumeration and Duplicate Entry Risk in `create_account`**

No validation to check for existing usernames or emails during user creation.
Allows creation of duplicate accounts, potential errors, and disclosure of registered usernames/emails via feedback timing or error messages.

***Improvements***
```python
if User.query.filter_by(username=form.username.data).first():
    flash('Username already exists.')
...
if User.query.filter_by(email=form.email.data).first():
    flash('Email already registered.')
```
Checks for existing users before account creation.
Prevents database integrity issues and stops malicious or accidental duplication of user credentials

3. **Defaulting to Active Status on New Accounts**

New accounts were automatically marked as `'active'`.
No vetting or moderation by an administrator—risk of abuse through admin-created accounts without oversight.

***Improvements***
```python
status='pending'  # Force admin approval
```
New users are not active by default.
Adds an approval workflow, ensuring admins verify users before they can access the system.

---

#### */admin/deposit*

1. **Missing Validation on Deposit Amount**
The `amount` input was not validated to ensure it was a positive number or within a reasonable range.
Negative deposits may allow manipulation of account balances or introduce inconsistencies, while excessive amounts could lead to financial errors, abuse, or system misuse by entering extremely large deposit amounts (e.g., billions of pesos).

***Improvements***
```python
if amount <= 0 or amount > 100_000:
    flash('Invalid deposit amount.')
    return redirect(url_for('admin_deposit'))
```
Ensures that only reasonable, non-negative deposit amounts (₱0.01 to ₱100,000) are processed.

Security Benefit:
- Blocks malicious input such as zero or negative values.
- Prevents extreme values that could cause overflow, fraud, or ledger imbalance.
- Adds a layer of business rule enforcement directly in the controller.

---

### **Penetration Testing Report**

| Route/File        | Vulnerability                                | Risk Level | Status     |
|------------------|-----------------------------------------------|------------|------------|
| `app.py`         | Random fallback for `SECRET_KEY`             | High       | Fixed ✅   |
| `/login`         | Password comparison using `==`               | High       | Fixed ✅   |
| `/login`         | No CSRF protection                           | High       | Fixed ✅   |
| `/register`      | No email domain validation                   | Medium     | Fixed ✅   |
| `/register`      | No duplicate user/email checks               | High       | Fixed ✅   |
| `/register`      | Weak password policy                         | High       | Fixed ✅   |
| `/transfer`      | Unvalidated `transfer_type` field            | Medium     | Fixed ✅   |
| `/transfer`      | Recipient enumeration via error messages     | High       | Fixed ✅   |
| `/execute_transfer` | No validation on transfer amount         | High       | Fixed ✅   |
| `/admin`         | CSRF via GET for state-changing actions      | High       | Fixed ✅   |
| `/admin`         | No duplicate username/email checks           | High       | Fixed ✅   |
| `/admin`         | Accounts default to active                   | High       | Fixed ✅   |
| `/admin/deposit` | No deposit amount validation                 | High       | Fixed ✅   |

---

| Recommendation                             | Status       |
|--------------------------------------------|--------------|
| Enforce `.env` configuration in production | ✅ Implemented |
| Add logging for repeated failed attempts    | 🔄 Pending     |
| Use rate limiting on auth endpoints         | 🔄 Pending     |
| Add audit logs for admin actions            | 🔄 Pending     |
| Conduct regular security code reviews       | 🔄 Ongoing     |

> Note: Due to time constraints, Other sensitive routes such as `/manager`, `/api`, and `/admin/edit_user` was not thoroughly audited. These endpoints should be prioritized in the next round of review to ensure proper access control and input validation are in place.

---
---

<div align = 'center'>
<center>
<h1>Remediation Plan</h1>
</center>
</div>

#### 1. `app.py`: Insecure SECRET_KEY Handling
- **Issue**: Secret key fallback uses `secrets.token_hex(16)` if unset.
- **Exploit**: Predictable key resets on each restart; session hijacking possible.
- **Fix**: SECRET_KEY must be explicitly set via environment (.env) file.

---

#### 2. `/login`: Timing Attack on Hash Comparison
- **Issue**: Used `==` for hash comparison.
- **Exploit**: Attacker infers hash via timing differences.
- **Fix**: Replaced with `hmac.compare_digest()`.

---

#### 3. `/login`: No CSRF Protection
- **Issue**: Form lacked CSRF tokens.
- **Exploit**: Malicious site submits login requests on user's behalf.
- **Fix**: Added Flask-WTF CSRF protection.

---

#### 4. `/register`: Disposable Email Allowed
- **Issue**: No filtering for throwaway emails.
- **Exploit**: Attackers flood system using temporary emails.
- **Fix**: Reject known disposable domains.

---

#### 5. `/register`: No Duplicate User or Email Check
- **Issue**: No check for uniqueness.
- **Exploit**: Duplicates lead to data corruption or enumeration.
- **Fix**: Validate username/email against database before account creation.

---

#### 6. `/register`: Weak Password Policy
- **Issue**: No password strength validation.
- **Exploit**: Easy brute-force or credential stuffing.
- **Fix**: Require min 8 characters, uppercase, lowercase, and digit.

---

#### 7. `/transfer`: Unvalidated `transfer_type`
- **Issue**: Accepts any string.
- **Exploit**: Malicious input could bypass logic or cause errors.
- **Fix**: Restrict to `'username'` or `'account'` only.

---

#### 8. `/transfer`: Recipient Enumeration
- **Issue**: Detailed error reveals if account exists.
- **Exploit**: Probe for valid usernames/accounts.
- **Fix**: Use generic error: `"Invalid recipient or transfer not allowed."`

---

#### 9. `/execute_transfer`: No Validation on Amount
- **Issue**: No cap or non-numeric check.
- **Exploit**: Use ₱0, negative, or billion-peso transfers to manipulate balance.
- **Fix**: Validate float, enforce range ₱1–₱1,000,000.

---

#### 10. `/execute_transfer`: Recipient Timing Leak
- **Issue**: Reveals if recipient exists or is inactive.
- **Exploit**: Enumeration via error response.
- **Fix**: Merge errors, add `time.sleep(1.5)` delay.

---

#### 11. `/admin`: State Change via GET (CSRF)
- **Issue**: Activating/deactivating users via GET.
- **Exploit**: CSRF via image or malicious link.
- **Fix**: Change method to POST and use CSRF tokens.

---

#### 12. `/admin`: No Duplicate User Check
- **Issue**: Allows duplicate creation.
- **Exploit**: Account takeover or DB errors.
- **Fix**: Validate both username and email before creation.

---

#### 13. `/admin`: New Users Automatically Active
- **Issue**: No approval required.
- **Exploit**: Admins create unmoderated users.
- **Fix**: Default new user `status='pending'`.

---

#### 14. `/admin/deposit`: No Validation on Amount
- **Issue**: Allows invalid deposits.
- **Exploit**: Insert negative/huge values.
- **Fix**: Enforce 0 < amount ≤ ₱100,000.

---
---

<div align = 'center'>
<center>
<h1>Technology Stack</h1>
</center>
</div>

| Layer         | Technology/Library                         | Purpose                                                                 |
|---------------|--------------------------------------------|-------------------------------------------------------------------------|
| **Backend**   | Python                                     | Main programming language                                               |
|               | Flask                                      | Lightweight web framework                                               |
|               | Flask-Limiter                              | Rate limiting to prevent brute-force attacks                           |
|               | Flask-Login                                | Session-based user authentication                                      |
|               | Flask-Bcrypt                               | Password hashing and salting                                           |
|               | Werkzeug                                   | Utility library for secure password comparison                         |
|               | hmac                                       | Secure comparison to prevent timing attacks                            |
|               | `python-dotenv`                            | Environment variable management                                        |
| **Database**  | MySQL                                      | Relational database system                                              |
|               | SQLAlchemy                                 | ORM for database interaction                                            |
|               | Flask-SQLAlchemy                           | Integration of SQLAlchemy with Flask                                    |
| **Frontend**  | HTML, CSS                                  | Markup and styling                                                      |
|               | Bootstrap 5                                | Responsive UI framework                                                 |
|               | Jinja2                                     | Templating engine for Flask                                            |
|               | JavaScript                                 | Frontend interactivity                                                  |
| **Forms**     | Flask-WTF                                  | Integration of WTForms with Flask for CSRF-protected forms              |
|               | WTForms                                    | Form handling and input validation                                      |
| **Security**  | CSRF Protection                            | Built into Flask-WTF to prevent CSRF attacks                            |
|               | Flask-Limiter                              | Protects routes from excessive access (rate limiting)                   |
|               | Password Hashing (Bcrypt)                  | Secure password storage                                                 |
| **External APIs** | PSGC API                               | Fetches Philippine Standard Geographic Code data                        |
| **Version Control** | Git                                   | Source code management                                                  |
|                     | GitHub / GitLab                       | Remote repository hosting                                               |

---
---

<div align = 'center'>
<center>
<h1>Setup Instructions</h1>
</center>
</div>

## Getting Started

### Prerequisites
- Python 3.7+
- pip (Python package manager)
- MySQL Server 5.7+ or MariaDB 10.2+
- Git (optional, for cloning the repo)

### Database Setup

1. Install MySQL Server or MariaDB if you haven't already:
   ```
   # For Ubuntu/Debian
   sudo apt update
   sudo apt install mysql-server
   
   # For macOS with Homebrew
   brew install mysql
   
   # For Windows
   # Download and install from the official website
   ```

2. Create a database user and set privileges:
   ```
   mysql -u root -p
   
   # In MySQL prompt
   CREATE USER 'bankapp'@'localhost' IDENTIFIED BY 'your_password';
   GRANT ALL PRIVILEGES ON *.* TO 'bankapp'@'localhost';
   FLUSH PRIVILEGES;
   EXIT;
   ```

3. Update the `.env` file with your MySQL credentials:
   ```
   DATABASE_URL=mysql+pymysql://bankapp:your_password@localhost/simple_banking
   MYSQL_USER=bankapp
   MYSQL_PASSWORD=your_password
   MYSQL_HOST=localhost
   MYSQL_PORT=3306
   MYSQL_DATABASE=simple_banking
   ```

4. Initialize the database:
   ```
   python init_db.py
   ```

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/LKbryan777/simple-banking-app-v2.git
   cd simple-banking-app-v2
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python app.py
   ```

4. Access the application at `http://localhost:5000`

---
---
