from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import requests
import os
from functools import wraps
from flask_caching import Cache
import secrets
import json
from flask import session
import uuid
# Add these imports at the top of your file
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_dance.consumer import oauth_authorized
from sqlalchemy.orm.exc import NoResultFound
import os
from authlib.integrations.flask_client import OAuth
import json
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin
from dotenv import load_dotenv
from flask_mail import Mail, Message
import threading



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bible_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BIBLE_API_KEY'] = '8a0917d65309e51e5e9181896306b9d9'
load_dotenv()  # Add this near the top of your application

# Set up mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@bibletracker.app')

# Initialize mail
mail = Mail(app)

# Cache configuration
cache = Cache(app, config={
    'CACHE_TYPE': 'SimpleCache',
    'CACHE_DEFAULT_TIMEOUT': 3600
})

BIBLE_VERSIONS = {
    'KJV': 'de4e12af7f28f599-02',
    'WEB': '9879dbb7cfe39e4d-01',
    'ASV': '06125adad2d5898a-01',
    'NLT': '65eec8e0b60e656b-01',
    'ESV': '9879dbb7cfe39e4d-01'
}

app.config['DEFAULT_BIBLE_VERSION'] = 'KJV'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# for development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


# Set up Google OAuth blueprint with proper redirect URI
google_bp = make_google_blueprint(
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    scope=["https://www.googleapis.com/auth/userinfo.profile",
           "https://www.googleapis.com/auth/userinfo.email",
           "openid"],
    redirect_to="home",  # Redirect to home page after authorization
    storage=SQLAlchemyStorage(OAuth, db.session, user=current_user)
)

app.register_blueprint(google_bp, url_prefix="/login")


# Database Models with indexes
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    streak = db.Column(db.Integer, default=0)
    last_read_date = db.Column(db.DateTime, index=True)
    readings = db.relationship('Reading', backref='user', lazy='dynamic')
    preferred_version = db.Column(db.String(10), default='KJV')
    created_groups = db.relationship('ReadingGroup', backref='creator', lazy='dynamic')
    group_memberships = db.relationship('GroupMember', backref='user', lazy='dynamic')


class Reading(db.Model):
    __table_args__ = (
        db.Index('idx_user_date', 'user_id', 'date'),
    )
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book = db.Column(db.String(50), nullable=False)
    chapter = db.Column(db.Integer, nullable=False)
    verses = db.Column(db.String(200))
    highlights = db.Column(db.Text)
    date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    bible_version = db.Column(db.String(10), default='KJV')


# Modified ReadingGroup model with correct relationship definition
class ReadingGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    book = db.Column(db.String(50), nullable=False)
    current_chapter = db.Column(db.Integer, default=1)
    target_completion_date = db.Column(db.DateTime)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    visibility = db.Column(db.String(20), default='public')
    access_code = db.Column(db.String(20))
    # Modified relationship definitions
    members = db.relationship('GroupMember', backref='reading_group', lazy='joined')
    readings = db.relationship('GroupReading', backref='reading_group', lazy='dynamic')
    invitations = db.relationship('GroupInvitation', backref='reading_group', lazy='dynamic')


class GroupInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('reading_group.id'), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    invite_code = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    used = db.Column(db.Boolean, default=False)


class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('reading_group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    join_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_read_chapter = db.Column(db.Integer, default=0)
    __table_args__ = (db.UniqueConstraint('group_id', 'user_id'),)


class GroupReading(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('reading_group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chapter = db.Column(db.Integer, nullable=False)
    completion_date = db.Column(db.DateTime, default=datetime.utcnow)
    recorded_date = db.Column(db.DateTime, default=datetime.utcnow)  # New field
    notes = db.Column(db.Text)






class OAuth(db.Model, OAuthConsumerMixin):
    __tablename__ = 'oauth'

    provider = db.Column(db.String(50), nullable=False)
    provider_user_id = db.Column(db.String(256), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')

    # Don't add a token column - OAuthConsumerMixin provides it with proper serialization

    __table_args__ = (db.UniqueConstraint('provider', 'provider_user_id'),)


# Bible API helper functions with caching
@cache.memoize(timeout=86400)
def get_bible_books(version_id):
    cache_key = f'bible_books_{version_id}'
    cached_books = cache.get(cache_key)
    if cached_books:
        return cached_books

    url = f"https://api.scripture.api.bible/v1/bibles/{version_id}/books"
    headers = {'api-key': app.config['BIBLE_API_KEY']}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            books = response.json()['data']
            result = {book['name']: book['id'] for book in books}
            cache.set(cache_key, result)
            return result
    except requests.exceptions.RequestException:
        pass
    return {}


@cache.memoize(timeout=86400)
def get_chapter_count(version_id, book_id):
    cache_key = f'chapter_count_{version_id}_{book_id}'
    cached_count = cache.get(cache_key)
    if cached_count is not None:
        return cached_count

    url = f"https://api.scripture.api.bible/v1/bibles/{version_id}/books/{book_id}/chapters"
    headers = {'api-key': app.config['BIBLE_API_KEY']}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            count = len(response.json()['data']) - 1
            cache.set(cache_key, count)
            return count
    except requests.exceptions.RequestException:
        pass
    return 0


@cache.memoize(timeout=86400)
def get_bible_content(version_id, book_id, chapter):
    cache_key = f'bible_content_{version_id}_{book_id}_{chapter}'
    cached_content = cache.get(cache_key)
    if cached_content:
        return cached_content

    url = f"https://api.scripture.api.bible/v1/bibles/{version_id}/chapters/{book_id}.{chapter}"
    headers = {'api-key': app.config['BIBLE_API_KEY']}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            content = response.json()['data']['content']
            cache.set(cache_key, content)
            return content
    except requests.exceptions.RequestException:
        pass
    return None




# Routes
@app.route('/')
@login_required
def home():
    if current_user.last_read_date:
        days_difference = (datetime.utcnow() - current_user.last_read_date).days
        if days_difference > 1:
            current_user.streak = 0
            db.session.commit()

    current_year = datetime.utcnow().year
    start_of_year = datetime(current_year, 1, 1)

    total_readings = Reading.query.filter(
        Reading.user_id == current_user.id,
        Reading.date >= start_of_year
    ).count()

    recent_readings = Reading.query.filter_by(user_id=current_user.id) \
        .order_by(Reading.date.desc()) \
        .limit(5) \
        .all()

    my_groups = ReadingGroup.query \
        .join(GroupMember) \
        .filter(GroupMember.user_id == current_user.id) \
        .options(db.joinedload(ReadingGroup.members)) \
        .limit(3) \
        .all()

    version_id = BIBLE_VERSIONS.get(current_user.preferred_version,
                                    BIBLE_VERSIONS[app.config['DEFAULT_BIBLE_VERSION']])
    bible_books = get_bible_books(version_id)

    return render_template('home.html',
                           books=bible_books,
                           total_readings=total_readings,
                           streak=current_user.streak,
                           recent_readings=recent_readings,
                           my_groups=my_groups)


from sqlalchemy import func

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form.get('email').lower()  # Ensure case-insensitivity
        password = request.form.get('password')
        user = User.query.filter(func.lower(User.email) == email).first()  # Compare emails case-insensitively

        if user and check_password_hash(user.password_hash, password):
            # Explicitly set session variables
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_email'] = user.email

            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Invalid email or password')

    return render_template('login.html')


# Modify your user loader to use session
@login_manager.user_loader
def load_user(user_id):
    # Use the session to get the most recent user information
    if 'user_id' in session:
        return User.query.get(int(session['user_id']))
    return None


# Add a context processor to ensure consistent user name
@app.context_processor
def inject_user_name():
    if current_user.is_authenticated:
        return dict(user_name=current_user.name)
    return dict(user_name='Guest')

@app.route('/logout')
@login_required
def logout():
    # Clear the user name from session
    session.pop('user_name', None)
    logout_user()
    flash('You have been logged out successfully')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        preferred_version = request.form.get('preferred_version', 'KJV')

        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))

        user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            preferred_version=preferred_version
        )
        db.session.add(user)
        db.session.commit()

        flash('Registration successful')
        return redirect(url_for('login'))

    return render_template('register.html', versions=BIBLE_VERSIONS.keys())




@app.route('/read', methods=['GET', 'POST'])
@login_required
def read():
    selected_version = request.args.get('version', current_user.preferred_version)
    version_id = BIBLE_VERSIONS.get(selected_version, BIBLE_VERSIONS[app.config['DEFAULT_BIBLE_VERSION']])
    bible_books = get_bible_books(version_id)

    if request.method == 'POST':
        book_id = request.form.get('book')
        chapter = request.form.get('chapter')
        verses = request.form.get('verses')
        highlights = request.form.get('highlights')
        version = request.form.get('version', current_user.preferred_version)

        book_name = next((name for name, id_ in bible_books.items() if id_ == book_id), None)

        reading = Reading(
            user_id=current_user.id,
            book=book_name,
            chapter=chapter,
            verses=verses,
            highlights=highlights,
            bible_version=version
        )
        db.session.add(reading)

        today = datetime.utcnow().date()
        if not current_user.last_read_date or current_user.last_read_date.date() < today:
            current_user.streak += 1
        current_user.last_read_date = datetime.utcnow()

        db.session.commit()
        flash('Reading recorded successfully!')
        return redirect(url_for('home'))

    return render_template('read.html',
                           books=bible_books,
                           versions=BIBLE_VERSIONS.keys(),
                           selected_version=selected_version)


# Update the create_group function to send emails for invitation-only groups
@app.route('/groups/create', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            description = request.form.get('description')
            book = request.form.get('book')
            target_date = request.form.get('target_date')
            visibility = request.form.get('visibility', 'public')

            # Convert target_date to datetime
            try:
                target_date = datetime.strptime(target_date, '%Y-%m-%d')
            except ValueError:
                flash('Invalid target date format. Use YYYY-MM-DD.')
                return redirect(url_for('create_group'))

            # Validate required fields
            if not all([name, description, book, target_date]):
                flash('All required fields must be filled out.')
                return redirect(url_for('create_group'))

            group = ReadingGroup(
                name=name,
                description=description,
                book=book,
                target_completion_date=target_date,
                creator_id=current_user.id,
                visibility=visibility
            )

            # Handle access code for private groups
            if visibility == 'private':
                access_code = request.form.get('access_code')
                if not access_code:
                    flash('Access code is required for private groups.')
                    return redirect(url_for('create_group'))
                group.access_code = access_code

            # Handle invitations for invitation-only groups
            if visibility == 'invitation':
                # Get emails from form
                emails = request.form.getlist('emails[]')
                emails = list(set(filter(bool, emails)))  # Remove duplicates and empty emails

                if not emails:
                    flash('At least one email is required for invitation-only groups.')
                    return redirect(url_for('create_group'))

            # Save group to database
            db.session.add(group)
            db.session.commit()

            # Add creator as first member
            member = GroupMember(group_id=group.id, user_id=current_user.id)
            db.session.add(member)

            # Create invitations if visibility is 'invitation'
            if visibility == 'invitation':
                for email in emails:
                    invite_code = secrets.token_hex(16)
                    invitation = GroupInvitation(
                        group_id=group.id,
                        email=email.lower(),
                        invite_code=invite_code,
                        expires_at=datetime.utcnow() + timedelta(days=7)
                    )
                    db.session.add(invitation)
                    db.session.flush()  # This gives the invitation an ID before commit

                    # Send invitation email
                    send_invitation_email(invitation, group.name, current_user.name)

            db.session.commit()

            cache.delete_memoized(list_groups)
            flash('Reading group created successfully!')
            return redirect(url_for('view_group', group_id=group.id))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while creating the group: {str(e)}')
            return redirect(url_for('create_group'))

    # Existing GET route code remains the same
    version_id = BIBLE_VERSIONS.get(current_user.preferred_version,
                                    BIBLE_VERSIONS[app.config['DEFAULT_BIBLE_VERSION']])
    bible_books = get_bible_books(version_id)
    return render_template('groups/create.html', books=bible_books)

@app.route('/groups/<int:group_id>/join', methods=['GET', 'POST'])
@login_required
def join_group(group_id):
    group = ReadingGroup.query.get_or_404(group_id)
    existing_membership = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id
    ).first()

    if existing_membership:
        flash('You are already a member of this group.')
        return redirect(url_for('view_group', group_id=group_id))

    if group.visibility == 'private':
        if request.method == 'POST':
            access_code = request.form.get('access_code')
            if not access_code:
                flash('Access code is required for private groups.')
                return redirect(url_for('list_groups'))

            if access_code != group.access_code:
                flash('Invalid access code.')
                return redirect(url_for('list_groups'))
        else:
            flash('Please submit the access code to join this group.')
            return redirect(url_for('list_groups'))

    elif group.visibility == 'invitation':
        invitation = GroupInvitation.query.filter_by(
            group_id=group_id,
            email=current_user.email,
            used=False
        ).filter(GroupInvitation.expires_at > datetime.utcnow()).first()

        if not invitation:
            flash('This group requires a valid invitation to join.')
            return redirect(url_for('list_groups'))

        invitation.used = True
        db.session.add(invitation)

    try:
        member = GroupMember(group_id=group_id, user_id=current_user.id)
        db.session.add(member)
        db.session.commit()
        cache.delete_memoized(list_groups)
        flash('Successfully joined the group!')
        return redirect(url_for('view_group', group_id=group_id))
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while joining the group.')
        return redirect(url_for('list_groups'))


@app.route('/groups')
@login_required
def list_groups():
    # My Groups: Groups where current user is a member
    my_groups = ReadingGroup.query \
        .join(GroupMember) \
        .filter(GroupMember.user_id == current_user.id) \
        .all()

    # Available Groups: Groups not already joined by current user
    available_groups = ReadingGroup.query \
        .filter(
            ReadingGroup.id.notin_(
                db.session.query(GroupMember.group_id)
                .filter_by(user_id=current_user.id)
            ),
            db.or_(
                ReadingGroup.visibility == 'public',
                ReadingGroup.visibility == 'private',  # Include private groups
                db.and_(
                    ReadingGroup.visibility == 'invitation',
                    ReadingGroup.id.in_(
                        db.session.query(GroupInvitation.group_id)
                        .filter(
                            GroupInvitation.email == current_user.email,
                            GroupInvitation.used == False,
                            GroupInvitation.expires_at > datetime.utcnow()
                        )
                    )
                )
            )
        ) \
        .all()

    return render_template('groups/list.html',
        my_groups=my_groups,
        available_groups=available_groups,
        current_user_name=current_user.name
    )

@app.route('/groups/<int:group_id>')
@login_required
def view_group(group_id):
    group = ReadingGroup.query.get_or_404(group_id)

    # Check group visibility and user membership
    is_member = GroupMember.query.filter_by(
        group_id=group_id,
        user_id=current_user.id
    ).first() is not None

    is_creator = group.creator_id == current_user.id

    # Handle different group visibility scenarios
    if group.visibility == 'private' and not (is_member or is_creator):
        flash('You do not have permission to view this private group.')
        return redirect(url_for('list_groups'))

    if group.visibility == 'invitation' and not (is_member or is_creator):
        # Check if user has a valid invitation
        invitation = GroupInvitation.query.filter_by(
            group_id=group_id,
            email=current_user.email,
            used=False
        ).filter(GroupInvitation.expires_at > datetime.utcnow()).first()

        if not invitation:
            flash('You do not have permission to view this group.')
            return redirect(url_for('list_groups'))

    # Fetch group with members
    group = db.session.query(ReadingGroup).options(
        db.joinedload(ReadingGroup.members).joinedload(GroupMember.user)
    ).get(group_id)

    version_id = BIBLE_VERSIONS.get(current_user.preferred_version,
                                    BIBLE_VERSIONS[app.config['DEFAULT_BIBLE_VERSION']])
    bible_books = get_bible_books(version_id)
    book_id = next((id_ for name, id_ in bible_books.items() if name == group.book), None)
    total_chapters = get_chapter_count(version_id, book_id) if book_id else 0

    # Only show progress for members
    progress = {}
    if is_member or is_creator:
        progress = {
            member.user_id: GroupReading.query.filter_by(
                group_id=group_id,
                user_id=member.user_id
            ).order_by(GroupReading.chapter.desc()).first().chapter
            if GroupReading.query.filter_by(group_id=group_id, user_id=member.user_id).first()
            else 0
            for member in group.members
        }

    current_user_progress = progress.get(current_user.id, 0)

    return render_template('groups/view.html',
                           group=group,
                           members=group.members,  # Add this line
                           progress=progress,
                           total_chapters=total_chapters,
                           current_chapter=group.current_chapter,  # Add this line
                           current_user_progress=current_user_progress,
                           bible_versions=BIBLE_VERSIONS.keys())


@app.route('/groups/<int:group_id>/record', methods=['POST'])
@login_required
def record_group_reading(group_id):
    chapter = int(request.form.get('chapter'))
    notes = request.form.get('notes')

    try:
        reading = GroupReading(
            group_id=group_id,
            user_id=current_user.id,
            chapter=chapter,
            notes=notes,
            recorded_date=datetime.utcnow()  # Set the recorded date explicitly
        )
        db.session.add(reading)

        member = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()
        member.last_read_chapter = chapter

        group = ReadingGroup.query.get(group_id)
        if chapter > group.current_chapter:
            group.current_chapter = chapter

        db.session.commit()
        flash('Reading recorded successfully!')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while recording the reading.')

    return redirect(url_for('view_group', group_id=group_id))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.preferred_version = request.form.get('preferred_version', 'KJV')
        db.session.commit()
        cache.delete_memoized(get_bible_books)
        flash('Preferences updated successfully!')
        return redirect(url_for('profile'))

    reading_stats = db.session.query(
        Reading.bible_version,
        db.func.count(Reading.id)
    ).filter_by(user_id=current_user.id).group_by(Reading.bible_version).all()

    group_stats = GroupMember.query.filter_by(user_id=current_user.id).options(
        db.joinedload(GroupMember.reading_group)  # Change 'group' to 'reading_group'
    ).all()

    return render_template('profile.html',
                         versions=BIBLE_VERSIONS.keys(),
                         reading_stats=reading_stats,
                         group_stats=group_stats)


@app.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    reading_type = request.args.get('type', 'personal')

    if reading_type == 'personal':
        # Get personal readings
        readings = Reading.query.filter_by(user_id=current_user.id) \
            .order_by(Reading.date.desc()) \
            .paginate(page=page, per_page=10)
    else:
        # Get group readings - Use recorded_date instead of date
        group_readings_query = db.session.query(
            GroupReading,
            ReadingGroup.name.label('group_name'),
            ReadingGroup.book.label('book')
        ).join(
            ReadingGroup,
            GroupReading.group_id == ReadingGroup.id
        ).filter(
            GroupReading.user_id == current_user.id
        ).order_by(
            GroupReading.recorded_date.desc()  # Changed from date to recorded_date
        )

        readings = group_readings_query.paginate(page=page, per_page=10)

    def format_date(date):
        return date.strftime("%B %d, %Y")

    return render_template('history.html',
                           readings=readings,
                           reading_type=reading_type,
                           format_date=format_date)


@app.route('/groups/<int:group_id>/leave')
@login_required
def leave_group(group_id):
    group = ReadingGroup.query.get_or_404(group_id)

    if group.creator_id == current_user.id:
        flash('As the group creator, you cannot leave the group.')
        return redirect(url_for('view_group', group_id=group_id))

    try:
        membership = GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
        ).first()

        if membership:
            db.session.delete(membership)
            db.session.commit()
            cache.delete_memoized(list_groups)
            flash('You have left the reading group.')
            return redirect(url_for('list_groups'))
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while leaving the group.')

    return redirect(url_for('view_group', group_id=group_id))

# API Routes
@app.route('/get_books/<version>')
@cache.cached(timeout=3600)
def get_books(version):
    version_id = BIBLE_VERSIONS.get(version, BIBLE_VERSIONS[app.config['DEFAULT_BIBLE_VERSION']])
    books = get_bible_books(version_id)
    return jsonify({'books': books})

@app.route('/get_chapters/<version>/<book_id>')
@cache.cached(timeout=3600)
def get_chapters(version, book_id):
    version_id = BIBLE_VERSIONS.get(version, BIBLE_VERSIONS[app.config['DEFAULT_BIBLE_VERSION']])
    chapter_count = get_chapter_count(version_id, book_id)
    return jsonify({'chapters': list(range(1, chapter_count + 1))})

@app.route('/get_content/<version>/<book>/<int:chapter>')
@cache.cached(timeout=3600)
def get_content(version, book, chapter):
    version_id = BIBLE_VERSIONS.get(version, BIBLE_VERSIONS[app.config['DEFAULT_BIBLE_VERSION']])
    books = get_bible_books(version_id)
    book_id = books.get(book)
    if book_id:
        content = get_bible_content(version_id, book_id, chapter)
        return jsonify({'content': content})
    return jsonify({'content': 'Book not found'})

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Context processors
@app.context_processor
def utility_processor():
    def format_date(date):
        return date.strftime('%Y-%m-%d %H:%M')

    def get_group_completion(group):
        total_members = GroupMember.query.filter_by(group_id=group.id).count()
        if total_members == 0:
            return 0

        version_id = BIBLE_VERSIONS.get('KJV')
        book_id = next((id_ for name, id_ in get_bible_books(version_id).items()
                       if name == group.book), None)
        total_chapters = get_chapter_count(version_id, book_id) if book_id else 0

        if total_chapters == 0:
            return 0

        completed_chapters = GroupReading.query.filter_by(group_id=group.id)\
            .with_entities(db.func.count(db.distinct(GroupReading.chapter)))\
            .scalar()

        return int((completed_chapters / total_chapters) * 100)

    return dict(format_date=format_date, get_group_completion=get_group_completion)


# Function to send emails asynchronously
def send_async_email(app_context, msg):
    with app_context:
        try:
            mail.send(msg)
        except Exception as e:
            print(f"Failed to send email: {str(e)}")


def send_email(subject, recipients, html_body, text_body=None):
    msg = Message(subject, recipients=recipients)
    msg.html = html_body
    if text_body:
        msg.body = text_body

    # Send email asynchronously to not block the main thread
    threading.Thread(target=send_async_email,
                    args=(app.app_context(), msg)).start()


def send_invitation_email(invitation, group_name, inviter_name):
    subject = f"Join '{group_name}' Bible Reading Group - Invitation from {inviter_name}"

    # Create links for the email
    invitation_link = url_for('view_invitations', _external=True)
    register_link = url_for('register', _external=True)

    # HTML version with modern, vibrant styling
    html_body = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>BibleFlow Invitation</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    </head>
    <body style="margin: 0; padding: 0; font-family: 'Inter', sans-serif; color: #333333; background-color: #f0f4f8;">
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="max-width: 650px; margin: 20px auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 8px 30px rgba(0,0,0,0.12);">
            <tr>
                <td style="padding: 0;">
                    <!-- Header with Gradient -->
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                            <td style="padding: 40px 0; text-align: center; background-image: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); position: relative;">
                                <h1 style="margin: 0; font-size: 28px; font-weight: 700; color: #ffffff; letter-spacing: -0.5px;">BibleFlow</h1>
                                <div style="position: absolute; bottom: 0; left: 0; right: 0; height: 6px; background-image: linear-gradient(90deg, #3B82F6, #10B981, #F59E0B);"></div>
                            </td>
                        </tr>
                    </table>

                    <!-- Main Content -->
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                            <td style="padding: 40px 40px 30px 40px;">
                                <h2 style="margin: 0 0 24px 0; font-size: 24px; font-weight: 700; color: #1F2937; letter-spacing: -0.3px;">You've Been Invited! ✨</h2>
                                <p style="margin: 0 0 16px 0; font-size: 16px; line-height: 1.6; color: #4B5563;">Hello,</p>
                                <p style="margin: 0 0 22px 0; font-size: 16px; line-height: 1.6; color: #4B5563;"><strong style="color: #111827;">{inviter_name}</strong> has invited you to join the Bible reading group:</p>

                                <div style="margin: 0 0 30px 0; padding: 20px; background-color: #F3F4F6; border-left: 4px solid #4F46E5; border-radius: 8px;">
                                    <p style="margin: 0; font-size: 20px; font-weight: 600; text-align: center; color: #111827;">{group_name}</p>
                                </div>

                                <p style="margin: 0 0 30px 0; font-size: 16px; line-height: 1.6; color: #4B5563;">Joining this group will help you stay accountable in your Bible reading journey and connect with others who are reading the same passages.</p>

                                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                                    <tr>
                                        <td style="text-align: center; padding: 12px 0 30px 0;">
                                            <a href="{invitation_link}" style="display: inline-block; padding: 14px 32px; background-image: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px; transition: all 0.3s ease; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);">View Your Invitations</a>
                                        </td>
                                    </tr>
                                </table>

                                <p style="margin: 0 0 16px 0; font-size: 16px; line-height: 1.6; color: #4B5563;">This invitation will expire in <span style="color: #EC4899; font-weight: 500;">7 days</span>.</p>

                                <p style="margin: 0 0 16px 0; font-size: 16px; line-height: 1.6; color: #4B5563;">If you don't have a BibleFlow account yet, you can <a href="{register_link}" style="color: #4F46E5; text-decoration: none; font-weight: 500; border-bottom: 1px solid #4F46E5;">register here</a>.</p>
                            </td>
                        </tr>
                    </table>

                    <!-- Footer -->
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                        <tr>
                            <td style="padding: 30px 40px; text-align: center; background-color: #F9FAFB; color: #6B7280;">
                                <p style="margin: 0 0 12px 0; font-size: 15px;">Blessings,<br><span style="font-weight: 600; color: #4B5563;">The BibleFlow Team</span></p>
                                <div style="width: 60px; height: 2px; background-image: linear-gradient(90deg, #3B82F6, #10B981, #F59E0B); margin: 20px auto;"></div>
                                <p style="margin: 0; font-size: 13px;">This is a legitimate invitation email sent on behalf of {inviter_name}.</p>
                                <p style="margin: 10px 0 0 0; font-size: 13px;">If you believe you received this email in error, please disregard it.</p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>
    '''

    # Plain text version for email clients that don't support HTML
    text_body = f'''
BibleFlow - Group Invitation

Hello,

{inviter_name} has invited you to join the Bible reading group: {group_name}.

Joining this group will help you stay accountable in your Bible reading journey and connect with others who are reading the same passages.

To accept this invitation, please visit: {invitation_link}

This invitation will expire in 7 days.

If you don't have a BibleFlow account yet, you can register at: {register_link}

Blessings,
The BibleFlow Team
    '''

    send_email(subject, [invitation.email], html_body, text_body)

# Now update the invite_to_group route to send emails when invitations are created
@app.route('/groups/<int:group_id>/invite', methods=['POST'])
@login_required
def invite_to_group(group_id):
    group = ReadingGroup.query.get_or_404(group_id)

    # Ensure only group members or creator can invite
    if group.creator_id != current_user.id and not GroupMember.query.filter_by(
            group_id=group_id,
            user_id=current_user.id
    ).first():
        flash('You do not have permission to invite members.')
        return redirect(url_for('view_group', group_id=group_id))

    # Get all emails (supporting multiple emails)
    emails = request.form.getlist('emails[]')

    # Remove duplicates and empty emails
    emails = list(set(filter(bool, emails)))

    if not emails:
        flash('At least one email address is required.')
        return redirect(url_for('view_group', group_id=group_id))

    # Track successful and failed invites
    successful_invites = 0
    failed_invites = 0

    try:
        for email in emails:
            # Check for existing valid invitation
            existing_invitation = GroupInvitation.query.filter_by(
                group_id=group_id,
                email=email.lower(),
                used=False
            ).filter(GroupInvitation.expires_at > datetime.utcnow()).first()

            if existing_invitation:
                failed_invites += 1
                continue

            invite_code = secrets.token_hex(16)
            invitation = GroupInvitation(
                group_id=group_id,
                email=email.lower(),
                invite_code=invite_code,
                expires_at=datetime.utcnow() + timedelta(days=7)
            )
            db.session.add(invitation)
            db.session.flush()  # This gives the invitation an ID before commit

            # Send invitation email
            send_invitation_email(invitation, group.name, current_user.name)

            successful_invites += 1

        db.session.commit()

        # Provide feedback based on invite results
        if successful_invites > 0:
            flash(f'Sent {successful_invites} invitation(s) successfully.')
        if failed_invites > 0:
            flash(f'{failed_invites} invitation(s) were already sent.')
    except Exception as e:
        db.session.rollback()
        flash(f'Error sending invitations: {str(e)}')

    return redirect(url_for('view_group', group_id=group_id))

@app.route('/invitations')
@login_required
def view_invitations():
    # Get active invitations for current user's email
    invitations = GroupInvitation.query.filter(
        GroupInvitation.email == current_user.email,
        GroupInvitation.used == False,
        GroupInvitation.expires_at > datetime.utcnow()
    ).all()

    return render_template('invitations.html', invitations=invitations)

@app.route('/invitations/<int:invitation_id>/accept', methods=['POST'])
@login_required
def accept_invitation(invitation_id):
    invitation = GroupInvitation.query.get_or_404(invitation_id)

    # Validate invitation
    if (invitation.email != current_user.email or
        invitation.used or
        invitation.expires_at < datetime.utcnow()):
        flash('Invalid or expired invitation.')
        return redirect(url_for('view_invitations'))

    try:
        # Add user to group
        member = GroupMember(
            group_id=invitation.group_id,
            user_id=current_user.id
        )
        db.session.add(member)

        # Mark invitation as used
        invitation.used = True
        db.session.commit()

        flash('You have successfully joined the group!')
        return redirect(url_for('view_group', group_id=invitation.group_id))
    except Exception as e:
        db.session.rollback()
        flash('Error joining group.')
        return redirect(url_for('view_invitations'))

@app.route('/invitations/<int:invitation_id>/decline', methods=['POST'])
@login_required
def decline_invitation(invitation_id):
    invitation = GroupInvitation.query.get_or_404(invitation_id)

    # Validate invitation
    if invitation.email != current_user.email:
        flash('Invalid invitation.')
        return redirect(url_for('view_invitations'))

    try:
        # Mark invitation as used without adding to group
        invitation.used = True
        db.session.commit()

        flash('Invitation declined.')
        return redirect(url_for('view_invitations'))
    except Exception as e:
        db.session.rollback()
        flash('Error processing invitation.')
        return redirect(url_for('view_invitations'))


@app.context_processor
def inject_invitation_count():
    if current_user.is_authenticated:
        invitation_count = GroupInvitation.query.filter(
            GroupInvitation.email == current_user.email,
            GroupInvitation.used == False,
            GroupInvitation.expires_at > datetime.utcnow()
        ).count()
        return dict(invitation_count=invitation_count)
    return dict(invitation_count=0)

@app.route("/error")
def error_page():
    # Generate a unique error ID for tracking
    error_id = str(uuid.uuid4())  # You can replace this with your preferred error ID generation logic
    return render_template("500.html", error_id=error_id)


from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required
from sqlalchemy import func


# Add this to your existing routes

from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.email.lower() != 'mukuhalevi@gmail.com'.lower():
            flash('You do not have permission to access the admin panel.')
            return redirect(url_for('home'))
        return f(*args, **kwargs)

    return decorated_function



@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    # User statistics
    total_users = User.query.count()
    users_by_version = db.session.query(
        User.preferred_version,
        func.count(User.id)
    ).group_by(User.preferred_version).all()

    # Reading statistics
    total_readings = Reading.query.count()
    readings_by_version = db.session.query(
        Reading.bible_version,
        func.count(Reading.id)
    ).group_by(Reading.bible_version).all()

    # Group statistics
    total_groups = ReadingGroup.query.count()
    groups_by_visibility = db.session.query(
        ReadingGroup.visibility,
        func.count(ReadingGroup.id)
    ).group_by(ReadingGroup.visibility).all()

    return render_template('admin/admin_dashboard.html',
                           total_users=total_users,
                           users_by_version=users_by_version,
                           total_readings=total_readings,
                           readings_by_version=readings_by_version,
                           total_groups=total_groups,
                           groups_by_visibility=groups_by_visibility)


@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    users = User.query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('admin/users.html', users=users)


@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.preferred_version = request.form.get('preferred_version')

        # Optional: Reset streak or last read date
        if request.form.get('reset_streak'):
            user.streak = 0
            user.last_read_date = None

        db.session.commit()
        flash('User updated successfully.')
        return redirect(url_for('admin_users'))

    return render_template('admin/edit_user.html', user=user)


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)

    try:
        # Delete associated readings, group memberships, etc.
        Reading.query.filter_by(user_id=user_id).delete()
        GroupMember.query.filter_by(user_id=user_id).delete()
        GroupReading.query.filter_by(user_id=user_id).delete()

        # Delete user
        db.session.delete(user)
        db.session.commit()

        flash('User and associated data deleted successfully.')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}')

    return redirect(url_for('admin_users'))


@app.route('/admin/groups')
@login_required
@admin_required
def admin_groups():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    groups = ReadingGroup.query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('admin/groups.html', groups=groups)


@app.route('/admin/groups/<int:group_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_group(group_id):
    group = ReadingGroup.query.get_or_404(group_id)

    if request.method == 'POST':
        group.name = request.form.get('name')
        group.description = request.form.get('description')
        group.book = request.form.get('book')
        group.visibility = request.form.get('visibility')

        # Update target completion date
        target_date = request.form.get('target_date')
        if target_date:
            group.target_completion_date = datetime.strptime(target_date, '%Y-%m-%d')

        db.session.commit()
        flash('Group updated successfully.')
        return redirect(url_for('admin_groups'))

    return render_template('admin/edit_group.html', group=group)


@app.route('/admin/group_readings')
@login_required
@admin_required
def admin_group_readings():
    page = request.args.get('page', 1, type=int)
    per_page = 50

    # Join with ReadingGroup and User to get their names
    group_readings = db.session.query(
        GroupReading,
        ReadingGroup.name.label('group_name'),
        User.name.label('user_name')
    ).join(
        ReadingGroup, GroupReading.group_id == ReadingGroup.id
    ).join(
        User, GroupReading.user_id == User.id
    ).order_by(
        GroupReading.recorded_date.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    return render_template('admin/group_readings.html', group_readings=group_readings)


@app.route('/admin/group_readings/<int:reading_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_group_reading(reading_id):
    reading = GroupReading.query.get_or_404(reading_id)

    try:
        db.session.delete(reading)
        db.session.commit()
        flash('Group reading deleted successfully.')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting group reading: {str(e)}')

    return redirect(url_for('admin_group_readings'))

@app.route('/admin/groups/<int:group_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_group(group_id):
    group = ReadingGroup.query.get_or_404(group_id)

    try:
        # Delete associated group members, readings, and invitations
        GroupMember.query.filter_by(group_id=group_id).delete()
        GroupReading.query.filter_by(group_id=group_id).delete()
        GroupInvitation.query.filter_by(group_id=group_id).delete()

        # Delete group
        db.session.delete(group)
        db.session.commit()

        flash('Group and associated data deleted successfully.')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting group: {str(e)}')

    return redirect(url_for('admin_groups'))


@app.route('/admin/readings')
@login_required
@admin_required
def admin_readings():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    readings = Reading.query.order_by(Reading.date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('admin/readings.html', readings=readings)


@app.route('/admin/readings/<int:reading_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_reading(reading_id):
    reading = Reading.query.get_or_404(reading_id)

    try:
        db.session.delete(reading)
        db.session.commit()
        flash('Reading deleted successfully.')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting reading: {str(e)}')

    return redirect(url_for('admin_readings'))

def group_creator_or_admin_required(f):
    @wraps(f)
    def decorated_function(group_id, *args, **kwargs):
        group = ReadingGroup.query.get_or_404(group_id)
        if not (current_user.is_authenticated and
                (group.creator_id == current_user.id or
                 current_user.email.lower() == 'mukuhalevi@gmail.com'.lower())):
            flash('You do not have permission to modify this group.')
            return redirect(url_for('view_group', group_id=group_id))
        return f(group_id, *args, **kwargs)
    return decorated_function


@app.route('/groups/<int:group_id>/edit', methods=['GET', 'POST'])
@login_required
@group_creator_or_admin_required
def edit_group(group_id):
    group = ReadingGroup.query.get_or_404(group_id)

    if request.method == 'POST':
        group.name = request.form.get('name')
        group.description = request.form.get('description')
        group.book = request.form.get('book')
        old_visibility = group.visibility
        new_visibility = request.form.get('visibility')
        group.visibility = new_visibility

        # Update target completion date
        target_date = request.form.get('target_date')
        if target_date:
            group.target_completion_date = datetime.strptime(target_date, '%Y-%m-%d')

        # Handle access code for private groups
        if group.visibility == 'private':
            access_code = request.form.get('access_code')
            if access_code:
                group.access_code = access_code

        # Handle invitations for invitation-only groups
        if group.visibility == 'invitation':
            # Get emails from form
            emails = request.form.getlist('emails[]')
            emails = list(set(filter(bool, emails)))  # Remove duplicates and empty emails

            if emails:
                for email in emails:
                    # Check if user is already a member
                    existing_member = db.session.query(User, GroupMember) \
                        .join(GroupMember, User.id == GroupMember.user_id) \
                        .filter(User.email == email.lower(), GroupMember.group_id == group.id) \
                        .first()

                    if existing_member:
                        flash(f'User {email} is already a member of this group.')
                        continue

                    # Check if invitation already exists
                    existing_invitation = GroupInvitation.query \
                        .filter_by(group_id=group.id, email=email.lower()) \
                        .first()

                    if existing_invitation:
                        flash(f'User {email} has already been invited.')
                        continue

                    # Create new invitation
                    invite_code = secrets.token_hex(16)
                    invitation = GroupInvitation(
                        group_id=group.id,
                        email=email.lower(),
                        invite_code=invite_code,
                        expires_at=datetime.utcnow() + timedelta(days=7)
                    )
                    db.session.add(invitation)

                    # Send invitation email
                    send_invitation_email(invitation, group.name, current_user.name)

        # If visibility changed from invitation-only to something else, we might want to
        # handle existing invitations (e.g., cancel them)
        if old_visibility == 'invitation' and new_visibility != 'invitation':
            # Optionally: Cancel pending invitations
            # pending_invitations = GroupInvitation.query.filter_by(group_id=group.id).all()
            # for invitation in pending_invitations:
            #     db.session.delete(invitation)
            pass

        try:
            db.session.commit()
            flash('Group updated successfully.')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}')

        return redirect(url_for('view_group', group_id=group_id))

    # Get book list for dropdown
    version_id = BIBLE_VERSIONS.get(current_user.preferred_version,
                                    BIBLE_VERSIONS[app.config['DEFAULT_BIBLE_VERSION']])
    bible_books = get_bible_books(version_id)

    # Get current members for invitation-only groups
    members = []
    invitations = []
    if group.visibility == 'invitation':
        members = GroupMember.query \
            .join(User, GroupMember.user_id == User.id) \
            .filter(GroupMember.group_id == group.id) \
            .all()

        invitations = GroupInvitation.query \
            .filter_by(group_id=group.id) \
            .filter(GroupInvitation.expires_at > datetime.utcnow()) \
            .all()

    today = datetime.now().strftime('%Y-%m-%d')
    return render_template('groups/edit.html',
                           group=group,
                           books=bible_books,
                           members=members,
                           invitations=invitations,
                           today=today,
                           current_user=current_user)


@app.route('/groups/<int:group_id>/delete', methods=['POST'])
@login_required
@group_creator_or_admin_required
def delete_group(group_id):
    group = ReadingGroup.query.get_or_404(group_id)

    try:
        # Delete associated group members, readings, and invitations
        GroupMember.query.filter_by(group_id=group_id).delete()
        GroupReading.query.filter_by(group_id=group_id).delete()
        GroupInvitation.query.filter_by(group_id=group_id).delete()

        # Delete group
        db.session.delete(group)
        db.session.commit()

        flash('Group and associated data deleted successfully.')
        return redirect(url_for('list_groups'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting group: {str(e)}')
        return redirect(url_for('view_group', group_id=group_id))


# Handle Google OAuth login
@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", category="error")
        return False

    resp = blueprint.session.get("/oauth2/v1/userinfo")
    if not resp.ok:
        msg = f"Failed to fetch user info from Google. Status: {resp.status_code}"
        flash(msg, category="error")
        return False

    google_info = resp.json()
    google_user_id = google_info["id"]
    google_email = google_info.get("email", "").lower().strip()

    # Log OAuth attempt for debugging
    app.logger.info(f"Google OAuth login attempt with email: {google_email}, Google ID: {google_user_id}")

    if not google_email:
        flash("Google account did not provide an email address.", category="error")
        return False

    # First, check if this Google ID is already associated with a user
    query = OAuth.query.filter_by(
        provider=blueprint.name,
        provider_user_id=google_user_id,
    )

    try:
        oauth = query.one()
        # If this OAuth token has a user, log them in
        if oauth.user:
            app.logger.info(
                f"Found existing OAuth connection for Google ID: {google_user_id}, user: {oauth.user.email}")

            # Verify the emails still match as an additional security check
            if oauth.user.email.lower().strip() != google_email:
                app.logger.warning(
                    f"Email mismatch: OAuth connected to {oauth.user.email} but Google returned {google_email}")
                flash("Your Google email doesn't match our records. Please contact support.", category="error")
                return False

            login_user(oauth.user)
            flash("Successfully signed in with Google.")

            # Update session variables
            session['user_id'] = oauth.user.id
            session['user_name'] = oauth.user.name
            session['user_email'] = oauth.user.email
            return False
    except NoResultFound:
        # No existing OAuth found, create a new one later
        oauth = None

    # At this point, either there's no OAuth entry or it exists but has no user
    # Check if a user exists with this email
    user = User.query.filter(func.lower(User.email) == google_email).first()

    if user:
        app.logger.info(f"Found existing user with email: {google_email}")

        # User exists but no OAuth connection exists yet
        if oauth is None:
            oauth = OAuth(
                provider=blueprint.name,
                provider_user_id=google_user_id,
                token=token,
            )

        # Instead of automatically connecting, send to a confirmation page
        # Store temporary data in session
        session['pending_oauth_id'] = google_user_id
        session['pending_oauth_email'] = google_email
        session['pending_oauth_token'] = token

        # Redirect to confirmation page
        flash("Please confirm you want to connect your Google account.", category="info")
        return redirect(url_for('confirm_google_connection'))
    else:
        # Create a new user - no existing account with this email
        app.logger.info(f"Creating new user with Google email: {google_email}")

        user = User(
            name=google_info.get("name", ""),
            email=google_email,
            password_hash=generate_password_hash(secrets.token_hex(16)),  # Random secure password
            preferred_version='KJV'  # Default Bible version
        )

        db.session.add(user)

        # Create new OAuth entry
        oauth = OAuth(
            provider=blueprint.name,
            provider_user_id=google_user_id,
            token=token,
            user=user
        )

        db.session.add(oauth)
        db.session.commit()

        login_user(user)
        flash("Successfully created new account with Google.")

        # Update session variables
        session['user_id'] = user.id
        session['user_name'] = user.name
        session['user_email'] = user.email

    # Disable Flask-Dance's default behavior for saving the OAuth token
    return False


# Add a Google login route
@app.route('/login/google')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    return redirect(url_for('home'))


# Add confirmation route for connecting Google account
@app.route('/confirm-google-connection', methods=['GET', 'POST'])
def confirm_google_connection():
    # Check if we have pending OAuth data
    if not all(k in session for k in ['pending_oauth_id', 'pending_oauth_email', 'pending_oauth_token']):
        flash("No pending Google connection found.", category="error")
        return redirect(url_for('login'))

    google_user_id = session['pending_oauth_id']
    google_email = session['pending_oauth_email']
    token = session['pending_oauth_token']

    # Find the user with this email
    user = User.query.filter(func.lower(User.email) == google_email.lower()).first()

    if not user:
        flash("User account not found.", category="error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # User confirmed the connection
        if 'confirm' in request.form:
            # Create the OAuth connection
            oauth = OAuth(
                provider="google",
                provider_user_id=google_user_id,
                token=token,
                user=user
            )

            db.session.add(oauth)
            db.session.commit()

            # Clean up session
            for key in ['pending_oauth_id', 'pending_oauth_email', 'pending_oauth_token']:
                session.pop(key, None)

            # Log in the user
            login_user(user)
            flash("Successfully connected Google account.", category="success")

            # Update session variables
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_email'] = user.email

            return redirect(url_for('home'))
        else:
            # User cancelled
            for key in ['pending_oauth_id', 'pending_oauth_email', 'pending_oauth_token']:
                session.pop(key, None)

            flash("Google account connection cancelled.", category="info")
            return redirect(url_for('login'))

    # GET request - show confirmation page
    return render_template('confirm_google_connection.html', email=google_email)


# Debug code to add temporarily
# print(f"GOOGLE_CLIENT_ID: {os.environ.get('GOOGLE_CLIENT_ID')}")
# print(f"GOOGLE_CLIENT_SECRET: {os.environ.get('GOOGLE_CLIENT_SECRET')}")

@app.route('/edit_reading/<int:reading_id>', methods=['GET', 'POST'])
@login_required
def edit_reading(reading_id):
    reading = Reading.query.filter_by(id=reading_id, user_id=current_user.id).first_or_404()

    if request.method == 'POST':
        # Update reading details
        reading.book = request.form.get('book')
        reading.chapter = request.form.get('chapter')
        reading.verses = request.form.get('verses')
        reading.highlights = request.form.get('highlights')
        reading.bible_version = request.form.get('bible_version')

        # Could update date if needed
        # reading.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d')

        db.session.commit()
        flash('Reading updated successfully!', 'success')
        return redirect(url_for('history', type='personal'))

    return render_template('edit_reading.html', reading=reading, bible_versions=BIBLE_VERSIONS.keys())


@app.route('/edit_group_reading/<int:reading_id>', methods=['GET', 'POST'])
@login_required
def edit_group_reading(reading_id):
    reading = GroupReading.query.filter_by(id=reading_id, user_id=current_user.id).first_or_404()
    group = ReadingGroup.query.get_or_404(reading.group_id)

    if request.method == 'POST':
        # Update group reading details
        reading.notes = request.form.get('notes')

        # Could update other fields if needed
        # Typically for group readings, you wouldn't change the chapter

        db.session.commit()
        flash('Group reading updated successfully!', 'success')
        return redirect(url_for('history', type='group'))

    return render_template('groups/edit_group_reading.html', reading=reading, group=group)


@app.route('/delete_reading/<int:reading_id>', methods=['POST'])
@login_required
def delete_reading(reading_id):
    reading = Reading.query.get_or_404(reading_id)

    # Ensure the user owns this reading
    if reading.user_id != current_user.id:
        abort(403)

    db.session.delete(reading)
    db.session.commit()

    flash('Reading entry deleted successfully', 'success')
    return jsonify({'success': True})


@app.route('/delete_group_reading/<int:reading_id>', methods=['POST'])
@login_required
def delete_group_reading(reading_id):
    reading = GroupReading.query.get_or_404(reading_id)

    # Ensure the user owns this reading or is admin of the group
    if reading.user_id != current_user.id:
        # Check if user is group admin
        group = ReadingGroup.query.get(reading.group_id)
        if group.creator_id != current_user.id:
            abort(403)

    db.session.delete(reading)
    db.session.commit()

    flash('Group reading entry deleted successfully', 'success')
    return jsonify({'success': True})


@app.route('/groups/<int:group_id>/members/<int:user_id>/remove', methods=['POST'])
@login_required
@group_creator_or_admin_required
def remove_member(group_id, user_id):
    group = ReadingGroup.query.get_or_404(group_id)

    # Prevent removing the creator
    if user_id == group.creator_id:
        flash('Cannot remove the group creator.')
        return redirect(url_for('edit_group', group_id=group_id))

    # Prevent removing yourself
    if user_id == current_user.id:
        flash('Cannot remove yourself from the group this way.')
        return redirect(url_for('edit_group', group_id=group_id))

    # Find and remove the member
    member = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first_or_404()

    try:
        db.session.delete(member)
        db.session.commit()
        flash('Member removed successfully.')
    except Exception as e:
        db.session.rollback()
        flash(f'Error removing member: {str(e)}')

    return redirect(url_for('edit_group', group_id=group_id))


@app.route('/invitations/<int:invitation_id>/resend', methods=['POST'])
@login_required
def resend_invitation(invitation_id):
    invitation = GroupInvitation.query.get_or_404(invitation_id)
    group = ReadingGroup.query.get_or_404(invitation.group_id)

    # Check if user has permission
    if current_user.id != group.creator_id and not current_user.is_admin:
        flash('You do not have permission to resend invitations.')
        return redirect(url_for('view_group', group_id=group.id))

    # Update expiration and resend
    invitation.expires_at = datetime.utcnow() + timedelta(days=7)

    try:
        db.session.commit()
        # Resend the invitation email
        send_invitation_email(invitation, group.name, current_user.name)
        flash('Invitation resent successfully.')
    except Exception as e:
        db.session.rollback()
        flash(f'Error resending invitation: {str(e)}')

    return redirect(url_for('edit_group', group_id=group.id))


@app.route('/invitations/<int:invitation_id>/cancel', methods=['POST'])
@login_required
def cancel_invitation(invitation_id):
    invitation = GroupInvitation.query.get_or_404(invitation_id)
    group = ReadingGroup.query.get_or_404(invitation.group_id)

    # Check if user has permission
    if current_user.id != group.creator_id and not current_user.is_admin:
        flash('You do not have permission to cancel invitations.')
        return redirect(url_for('view_group', group_id=group.id))

    try:
        db.session.delete(invitation)
        db.session.commit()
        flash('Invitation cancelled successfully.')
    except Exception as e:
        db.session.rollback()
        flash(f'Error cancelling invitation: {str(e)}')

    return redirect(url_for('edit_group', group_id=group.id))



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)