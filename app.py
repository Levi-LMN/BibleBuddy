from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
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



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bible_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BIBLE_API_KEY'] = '8a0917d65309e51e5e9181896306b9d9'
load_dotenv()  # Add this near the top of your application

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
            successful_invites += 1

        db.session.commit()

        # Provide feedback based on invite results
        if successful_invites > 0:
            flash(f'Sent {successful_invites} invitation(s) successfully.')
        if failed_invites > 0:
            flash(f'{failed_invites} invitation(s) were already sent.')
    except Exception as e:
        db.session.rollback()
        flash('Error sending invitations.')

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
        group.visibility = request.form.get('visibility')

        # Update target completion date
        target_date = request.form.get('target_date')
        if target_date:
            group.target_completion_date = datetime.strptime(target_date, '%Y-%m-%d')

        # Handle access code for private groups
        if group.visibility == 'private':
            access_code = request.form.get('access_code')
            if access_code:
                group.access_code = access_code

        db.session.commit()
        flash('Group updated successfully.')
        return redirect(url_for('view_group', group_id=group_id))

    # Get book list for dropdown
    version_id = BIBLE_VERSIONS.get(current_user.preferred_version,
                                    BIBLE_VERSIONS[app.config['DEFAULT_BIBLE_VERSION']])
    bible_books = get_bible_books(version_id)

    return render_template('groups/edit.html', group=group, books=bible_books)

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
        msg = "Failed to fetch user info from Google."
        flash(msg, category="error")
        return False

    google_info = resp.json()
    google_user_id = google_info["id"]

    # Find this OAuth token in the database, or create it
    query = OAuth.query.filter_by(
        provider=blueprint.name,
        provider_user_id=google_user_id,
    )
    try:
        oauth = query.one()
    except NoResultFound:
        oauth = OAuth(
            provider=blueprint.name,
            provider_user_id=google_user_id,
            token=token,
        )

    if oauth.user:
        # If this OAuth token has a user, log them in
        login_user(oauth.user)
        flash("Successfully signed in with Google.")

        # Update session variables
        session['user_id'] = oauth.user.id
        session['user_name'] = oauth.user.name
        session['user_email'] = oauth.user.email

    else:
        # If no user is associated with this token, check if the email exists
        user = User.query.filter_by(email=google_info["email"]).first()

        if user:
            # Connect the existing account to this OAuth token
            oauth.user = user
            db.session.add(oauth)
            db.session.commit()
            login_user(user)
            flash("Successfully signed in with Google.")

            # Update session variables
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_email'] = user.email
        else:
            # Create a new user account with information from Google
            user = User(
                name=google_info["name"],
                email=google_info["email"],
                password_hash=generate_password_hash(secrets.token_hex(16)),  # Random secure password
                preferred_version='KJV'  # Default Bible version
            )
            db.session.add(user)
            oauth.user = user
            db.session.add(oauth)
            db.session.commit()
            login_user(user)
            flash("Successfully signed in with Google.")

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

# Debug code to add temporarily
# print(f"GOOGLE_CLIENT_ID: {os.environ.get('GOOGLE_CLIENT_ID')}")
# print(f"GOOGLE_CLIENT_SECRET: {os.environ.get('GOOGLE_CLIENT_SECRET')}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)