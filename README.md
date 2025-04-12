Bible Tracker Web Application
Bible Tracker is a comprehensive web application designed to help users track their Bible reading progress, join reading groups, and stay accountable in their spiritual journey.
Features
Personal Bible Reading

Track daily Bible readings with chapter and verse references
Maintain a reading streak for consistent engagement
Record personal highlights and notes
Choose from multiple Bible versions (KJV, WEB, ASV, NLT, ESV)
View reading history and statistics

Reading Groups

Create public, private, or invitation-only reading groups
Invite friends via email to join reading groups
Track group progress through a selected book of the Bible
Set target completion dates for reading plans
View member activity within groups

User Authentication

Email/password registration and login
Google OAuth integration for easy sign-up
Profile management and preferences

Admin Features

Dashboard with application statistics
User management capabilities
Group moderation tools

Technical Stack
The application is built using:

Flask: Web framework for Python
SQLAlchemy: ORM for database interactions
Flask-Login: User session management
Flask-Dance: OAuth integration
SQLite: Database for storing user data and reading records
Flask-Mail: Email functionality for invitations
Werkzeug: Security features for password handling
Flask-Caching: Performance optimization

API Integration
Bible Tracker integrates with the Scripture API Bible to provide:

Bible book listings
Chapter counts for each book
Bible content retrieval for different versions

Getting Started

Clone the repository
Install dependencies with pip install -r requirements.txt
Set up environment variables:

MAIL_SERVER
MAIL_PORT
MAIL_USERNAME
MAIL_PASSWORD
MAIL_DEFAULT_SENDER
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET


Initialize the database with flask db upgrade
Run the application with flask run

Core Routes

/: Home dashboard
/login: User authentication
/register: New user registration
/read: Record Bible readings
/groups: Join or view reading groups
/groups/create: Create new reading groups
/profile: User settings and statistics
/history: View reading history
/invitations: Manage group invitations

Additional Information

The app uses caching for Bible content to improve performance
Asynchronous email processing with threading
Mobile-responsive design for all devices
Supports multiple Bible versions
Admin panel accessible to administrators

Security Features

Password hashing with Werkzeug
CSRF protection
Input validation
Session management
OAuth secure flow
