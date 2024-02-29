# focus-timer Backend

## Overview
This project is the backend server for a  focus-timer application built using Python, Flask, and SQLAlchemy. The backend handles user authentication, task tracking, and provides APIs for the frontend.



## Technologies Used
- Python
- Flask
- SQLAlchemy
- Flask Bcrypt
- Flask CORS
- Flask JWT Extended
- Flask Migrate
- SQLite (or your preferred database)

## Prerequisites
Make sure you have the following installed before running the backend:
- Python 3.x
- Flask: `pip install Flask`
- Flask Bcrypt: `pip install Flask-Bcrypt`
- Flask CORS: `pip install Flask-CORS`
- Flask JWT Extended: `pip install Flask-JWT-Extended`
- Flask Migrate: `pip install Flask-Migrate`
- SQLAlchemy: `pip install Flask-SQLAlchemy`

## Getting Started
1. Clone the repository: `git clone <repository-url>`
2. Navigate to the project directory: `cd focus-timer backend`
3. Create a virtual environment: `python -m venv venv`
4. Activate the virtual environment:
   - On Windows: `venv\Scripts\activate`
   - On Unix or MacOS: `source venv/bin/activate`
5. Install dependencies: `pip install -r requirements.txt`
6. Run the application: `python app.py`
7. The server will run on `http://localhost:5000`

## Configuration
- Update the database configuration in `models.py` to match your database setup.
- Customize any other configuration variables as needed.

## Database Migration
If you make changes to the database models, you may need to perform a migration:
1. Run `flask db migrate` to generate migration scripts.
2. Run `flask db upgrade` to apply the changes to the database.

## API Endpoints
- `/signup`: POST - Register a new user.
- `/login`: POST - User login and authentication.
- `/api/protected`: GET - A protected endpoint that requires authentication.
- `/update_user/<string:username>`: PATCH - Update user details.
- `/delete_user/<string:username>`: DELETE - Delete a user account.
- `/users`: GET - Get a list of all users.
- `/users/<int:user_id>`: GET - Get user details by ID.
- `/logout`: POST - Log out the user.
- `/create_task`: POST - Create a new task.
- `/get_tasks/<int:user_id>`: GET - Get ongoing tasks for a user.
- `/get_task/<int:task_id>`: GET - Get details of a specific task.
- `/update_task/<int:id>`: PUT - Update details of a task.
- `/delete_task/<int:id>`: DELETE - Delete a task.
- `/get_reports`: GET - Get a list of all reports.
- `/delete_report/<int:id>`: DELETE - Delete a report.



## Authentication
- User authentication is implemented using JWT (JSON Web Tokens).
- Users must authenticate to access protected endpoints.

## Models
- `User`: Represents user details.
- `Report`: Represents task reports with completed tasks.
- `Task`: Represents individual tasks.

## Contributing
We welcome contributions! If you'd like to contribute, please follow these steps:
1. Fork the repository.
2. Create a new branch: `git checkout -b feature/new-feature`
3. Make your changes and commit them: `git commit -m 'Add new feature'`
4. Push to the branch: `git push origin feature/new-feature`
5. Submit a pull request.
