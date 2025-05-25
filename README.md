# Web Application Security Enhancement for a Flask-Powered Banking System


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
| **Content Security Policy (CSP) Header Not Set** | The application does not implement a Content Security Policy (CSP) header, which is essential for mitigating cross-site scripting (XSS) and data injection attacks. |
| **Missing Anti-clickjacking Header**   |The lack of an X-Frame-Options header or a Content Security Policy with the frame-ancestors directive leaves the site vulnerable to clickjacking.|

#### **Low Priority**

| Vulnerability                          | Description                                                                 |
|----------------------------------------|-----------------------------------------------------------------------------|
| **Application Error Disclosure**       | The application discloses internal error messages that could provide attackers with insights into the backend logic. |
| **Cookie Without Secure Flag**         | Cookies are set without the 'Secure' flag, which poses a risk as they may be transmitted over non-HTTPS connections.  |
| **Cookie Without SameSite Attribute**  |  The absence of the SameSite attribute on cookies compromises protection against cross-site request forgery (CSRF) attacks. |
| **Cross-Domain JavaScript Source File Inclusion** | External JavaScript files from various domains heightens the risk of external code compromise. |
| **Information Disclosure - Debug Error Messages** | Exposing debug-level error messages could inadvertently leak sensitive information to potential attackers. |


The security review found several serious weaknesses in the system that could make it vulnerable to threats from both outside and inside.

1. Weak Password Practices
   - Passwords are stored with minimal validation.
   - The use of weak default credentials heightens the risk of unauthorized access.

2. Financial Calculation Risks
   - Utilizing floating-point values for balance calculations can result in rounding errors.

3. API Error Handling
   - There is insufficient error handling for failures in the PSGC API.

4. XSS Vulnerability
   - User-generated content lacks output escaping, posing a risk for Cross-Site Scripting (XSS).

5. Data Transmission Security
   - HTTPS is not enforced, which allows sensitive data to be intercepted.
   - Missing security headers diminish the system's resistance to web attacks.

6. Session and CSRF Concerns
   - Session management is incomplete.
   - CSRF token implementation is either inconsistent or absent.

7. Outdated Dependencies
   - The use of outdated third-party packages with known vulnerabilities is present.

8. Lack of Audit Logging
   - Actions taken by administrators and managers are untracked.
   - There is no audit trail for sensitive operations.
     
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

The initial implementation assigns the SECRET_KEY a randomly generated value via secrets.token_hex(16) if an environment variable is not defined. Although this fallback appears to be secure at first sight, it creates a significant vulnerability in a production environment where the environment variable might be absent or incorrectly set.

```python
# Create Flask application
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
```
Created a .env file to safely keep environment variables, including the SECRET_KEY. Environment variables are loaded securely during application initialization using tools like python-dotenv or the environment variable settings provided by the hosting platform. This limits the exposure of secrets to just the runtime environment, enhancing the security stance.

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

This creates opportunities for timing attacks, where an attacker can assess response times to deduce partial matches, thereby compromising password security.

***Improvements***
```python
import hmac
if hmac.compare_digest(sha2_hash, user.password_hash):

```

Substituted basic equality checks with hmac.compare_digest() for comparisons that run in constant time.
Reduces the risk of timing attacks by making sure the comparison duration remains constant, irrespective of the length of the matching prefix.

<br>

2. **Absence of CSRF Safeguards**

The login route was missing clear CSRF protections, making it susceptible to Cross-Site Request Forgery attacks.

***Improvements***

Implemented CSRF protection using Flask-WTF with form.hidden_tag() and CSRF tokens. This stops harmful sites from generating forged POST requests to the login endpoint.

---

#### */register*

1. **Lack of Validation for Email Domains (Disposable Emails Permitted)**

The original code allowed all email addresses without checking for disposable or temporary email providers. This could result in the creation of fake accounts, increased spam, and potential misuse.

***Improvements***
```python
disposable_domains = {'mailinator.com', '10minutemail.com', 'tempmail.com'}
email_domain = form.email.data.split('@')[-1].lower()
if email_domain in disposable_domains:
    flash('Disposable email addresses are not allowed. Please use a valid email.')
    return redirect(url_for('register'))
```
Implemented a blacklist of temporary email domains to stop registrations using disposable or throwaway addresses.
This helps to minimize spam, fake sign-ups, and misuse of system resources.


2. **Lack of Verification for Duplicate Usernames or Emails**

The function did not check if the email address or username was already in use. This could allow for multiple accounts with identical credentials or lead to problems within the database.

***Improvements***
```python
existing_user = User.query.filter(
    (User.username == form.username.data) | (User.email == form.email.data)).first()
if existing_user:
    flash('Registration failed. Please check your input and try again.')  # generic message
    return redirect(url_for('register'))
```
Implemented a database query to verify whether the username or email is already in use prior to creating a new user.
Employs a universal error message to prevent disclosing which specific field has a duplicate (mitigating username/email enumeration attacks).

3. **Inadequate Password Policy (Lack of Complexity Requirements)**

The initial registration process permitted any password without restrictions on length or complexity, heightening the risk of account breaches due to weak passwords.

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
Imposes a minimum password length of 8 characters.
Mandates the inclusion of at least one uppercase letter, one lowercase letter, and one digit.
Boosts overall account security by obstructing weak passwords.

---

#### */transfer*

1. **Lack of Validation for `transfer_type` Input**  
The initial code failed to check whether the `transfer_type` field included only permitted values (`'username'` or `'account'`). This oversight could result in unintended consequences or misuse if unauthorized types are provided.

***Improvements***
```python
if form.transfer_type.data not in ['username', 'account']:
flash('Invalid transfer type.')
return redirect(url_for('transfer'))
```
Implemented strict validation to guarantee that transfer_type is either 'username' or 'account.'
This helps prevent malformed or unexpected inputs from impacting business logic or leading to errors.

2. **Risk of Recipient Enumeration**  
When the recipient was not identifiable (for instance, due to an incorrect username or account number), the system responded differently, potentially exposing information about valid usernames or accounts.

***Improvements***
```python
if not recipient:
    flash('Invalid recipient or transfer not allowed.')
    return redirect(url_for('transfer'))
```
When recipient lookup is unsuccessful, a general error message is displayed instead of indicating whether a username or account number is valid.
This approach stops attackers from testing valid accounts by exploiting variations in responses.

3. **Order of Balance Verification and Recipient Status Verification**  
The initial code verified whether there were sufficient funds in the account prior to confirming if the recipient's account was active. This sequence might have led to resource wastage or unintended information disclosure.

***Enhancements***

Rearranged the check for the recipient's active status to precede the balance validation, thus preventing unnecessary processing when the recipient is inactive.

---

#### */execute_transfer*


1. **Improper Management of Invalid Forms**  

The initial code continued execution solely when `form.validate_on_submit()` was successful, yet it did not explicitly address what happens when validation fails. As a result, users might circumvent the intended functionality or be left without helpful feedback.

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

Stops transfers that are negative or zero and helps reduce misuse, like emptying accounts or causing service interruptions through excessive values.

2. **Recipient Enumeration Risk**  
Displaying particular error messages such as “Recipient not found” may enable an attacker to identify valid usernames or account numbers by analyzing timing and messages.

***Improvements***
```python
if not recipient or (recipient.status != 'active' and not recipient.is_admin and not recipient.is_manager):
    time.sleep(1.5)
    flash("Transfer failed. Please verify recipient details.")
    return redirect(url_for('transfer'))
```
Combined the "not found" and "inactive" recipient scenarios into a single generic error message.
This stops user enumeration by ensuring that the error messages remain the same regardless of the recipient's validity.
Bonus: A 1.5-second artificial delay has been incorporated to discourage brute-force guessing attempts.

---

#### */admin*

1. **CSRF Vulnerability through GET Requests for Operations that Change State**  
The `activate_user` and `deactivate_user` endpoints utilized the `GET` method to alter data on the server side. An attacker could insert image tags or links to execute CSRF attacks, causing unwanted changes in state (e.g., `img src="https://bank.com/admin/deactivate_user/5"`).

***Improvements***
```python
@app.route('/admin/activate_user/<int:user_id>', methods=['POST'])
@app.route('/admin/deactivate_user/<int:user_id>', methods=['POST'])
```
Utilizes POST for every route that alters the state.
Reduces CSRF threats by necessitating intentional form submissions with CSRF tokens (assuming Flask-WTF is implemented).


2.**Account Enumeration and Duplicate Entry Risk in `create_account`**

There is a lack of validation to verify existing usernames or emails when creating a user account. This enables the creation of duplicate accounts, which can lead to errors and the inadvertent exposure of registered usernames/emails through discrepancies in feedback timing or error messages.

***Improvements***
```python
if User.query.filter_by(username=form.username.data).first():
    flash('Username already exists.')
...
if User.query.filter_by(email=form.email.data).first():
    flash('Email already registered.')
```
Verifies the presence of current users prior to creating a new account.
Averts database integrity problems and prevents the unintentional or harmful duplication of user credentials.

3. **Automatic Active Status for New Accounts**

New accounts were instantly labeled as `'active'`.  
There was no review or moderation by an administrator—this posed a risk of misuse via accounts created by admins without supervision.

***Improvements***
```python
status='pending'  # Force admin approval
```
New users are inactive by default.
An approval process is implemented, requiring administrators to confirm users before they gain access to the system.
---

#### */admin/deposit*

1. **Lack of Validation on Deposit Amount**  
The `amount` input lacked checks to confirm that it was a positive number or fell within a sensible range.  
Negative deposits might enable the manipulation of account balances or cause inconsistencies, while overly large amounts could result in financial inaccuracies, misuse, or abuse of the system by entering extraordinarily high deposit figures (e.g., billions of pesos).

***Improvements***
```python
if amount <= 0 or amount > 100_000:
    flash('Invalid deposit amount.')
    return redirect(url_for('admin_deposit'))
```
Guarantees that only acceptable deposit amounts (₱0.01 to ₱100,000) are handled.

Security Advantage:
- Prevents harmful inputs like zero or negative figures.
- Avoids extreme values that might lead to overflow, fraud, or discrepancies in the ledger.
- Introduces an additional layer of business rule enforcement right within the controller.
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

> Note: Because of time limitations, other sensitive paths like `/manager`, `/api`, and `/admin/edit_user` were not fully examined. It's important to give priority to these endpoints in the next review to guarantee that appropriate access control and input validation are implemented.

---
---

<div align = 'center'>
<center>
<h1>Remediation Plan</h1>
</center>
</div>

#### 1. `app.py`: Insecure Handling of SECRET_KEY  
- **Issue**: The secret key defaults to `secrets.token_hex(16)` if it is not set.  
- **Exploit**: Keys that can be predicted are reset with each restart, making session hijacking a risk.  
- **Fix**: The SECRET_KEY should be explicitly defined in an environment (.env) file.  

---

#### 2. `/login`: Vulnerability to Timing Attacks during Hash Comparison  
- **Issue**: Hash comparison uses the `==` operator.  
- **Exploit**: An attacker can deduce the hash through timing variations.  
- **Fix**: Use `hmac.compare_digest()` instead.  

---

#### 3. `/login`: Absence of CSRF Protection  
- **Issue**: The form does not include CSRF tokens.  
- **Exploit**: A malicious site can submit login requests on behalf of the user.  
- **Fix**: Implement CSRF protection with Flask-WTF.  

---

#### 4. `/register`: Acceptance of Disposable Emails  
- **Issue**: There's no filtering for disposable email addresses.  
- **Exploit**: Attackers can inundate the system using temporary email addresses.  
- **Fix**: Block known disposable email domains.  

---

#### 5. `/register`: Lack of Checks for Duplicate Users or Emails  
- **Issue**: Uniqueness is not verified.  
- **Exploit**: Duplicate entries can result in data corruption or enumeration issues.  
- **Fix**: Confirm that the username/email is unique before creating an account.  

---

#### 6. `/register`: Inadequate Password Strength Policy  
- **Issue**: There is no validation for password strength.  
- **Exploit**: Simple passwords can be easily brute-forced or subjected to credential stuffing attacks.  
- **Fix**: Enforce a requirement of at least 8 characters, including uppercase, lowercase letters, and digits.  

---

#### 7. `/transfer`: Unchecked `transfer_type` Parameter  
- **Issue**: The system accepts any string for the transfer type.  
- **Exploit**: Malicious input could circumvent logic or trigger errors.  
- **Fix**: Limit accepted values to either `'username'` or `'account'`.  

---

#### 8. `/transfer`: Enumeration of Recipients  
- **Issue**: Detailed error messages indicate whether an account exists.  
- **Exploit**: Attackers can search for valid usernames or accounts.  
- **Fix**: Display a generic error message: `"Invalid recipient or transfer not allowed."`  

---

#### 9. `/execute_transfer`: Lack of Validation on Transfer Amount  
- **Issue**: There are no checks for non-numeric values or limits on amounts.  
- **Exploit**: Users could attempt to transfer ₱0, negative amounts, or excessive values to manipulate their balance.  
- **Fix**: Validate that the amount is a float and falls within the range of ₱1–₱1,000,000.  

---

#### 10. `/execute_transfer`: Timing Leak on Recipient Validation  
- **Issue**: It reveals whether a recipient exists or is inactive.  
- **Exploit**: Attackers can enumerate users based on the response.  
- **Fix**: Combine error messages and introduce a `time.sleep(1.5)` delay.  

---

#### 11. `/admin`: State Change via GET Method (CSRF)  
- **Issue**: Users can be activated or deactivated using a GET request.  
- **Exploit**: This could allow CSRF via a malicious link or image.  
- **Fix**: Switch the method to POST and implement CSRF tokens.  

---

#### 12. `/admin`: Absence of Duplicate User Validation  
- **Issue**: The system allows the creation of duplicate user accounts.  
- **Exploit**: This could lead to account takeovers or database errors.  
- **Fix**: Check both username and email for duplicates before account creation.  

---

#### 13. `/admin`: Automatic Activation of New Users  
- **Issue**: New users are automatically set to active status.  
- **Exploit**: Admins could create users without moderation.  
- **Fix**: Default the status of new users to `pending`.  

---

#### 14. `/admin/deposit`: Lack of Validation on Deposit Amount  
- **Issue**: Invalid deposit amounts are accepted.  
- **Exploit**: This could permit negative or excessively large values.  
- **Fix**: Ensure the amount is greater than 0 and does not exceed ₱100,000.  

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
