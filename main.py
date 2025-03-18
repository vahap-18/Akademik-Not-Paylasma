
from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from flask.json import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask import Flask, render_template, url_for, request, redirect, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import current_user, login_required
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///akademik_platform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload
#app.config['SECRET_KEY'] = '970-019-725'  # Güvenlik anahtarı
socketio = SocketIO(app, cors_allowed_origins="http://192.168.224.4:8080")  # CORS kısıtlaması eklendi

# Upload klasörünü oluştur
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# Profil resimleri için klasörü oluştur
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profiles'), exist_ok=True)

# Default profil resmini kontrol et ve oluştur
default_profile_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', 'default_profile.jpg')
if not os.path.exists(default_profile_path):
    try:
        import urllib.request
        # Varsayılan bir profil resmi indir
        urllib.request.urlretrieve(
            "https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&f=y", 
            default_profile_path
        )
    except Exception as e:
        print(f"Varsayılan profil resmi oluşturulamadı: {e}")

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Veritabanı Modelleri
followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    about_me = db.Column(db.String(140), nullable=True)
    university = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    profile_image = db.Column(db.String(100), nullable=True, default='profiles/default_profile.jpg')
    joined_date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.relationship('Note', backref='author', lazy='dynamic')
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')
    messages_sent = db.relationship('Message',
                                    foreign_keys='Message.sender_id',
                                    backref='sender', lazy='dynamic')
    messages_received = db.relationship('Message',
                                        foreign_keys='Message.recipient_id',
                                        backref='recipient', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0

    def followed_notes(self):
        return Note.query.join(
            followers, (followers.c.followed_id == Note.user_id)).filter(
                followers.c.follower_id == self.id).union(
                    Note.query.filter_by(user_id=self.id)
                ).order_by(Note.timestamp.desc())

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    subject = db.Column(db.String(50))
    files = db.relationship('NoteFile', backref='note', lazy='dynamic')
    likes = db.relationship('Like', backref='note', lazy='dynamic')
    comments = db.relationship('Comment', backref='note', lazy='dynamic')

class NoteFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class CommentLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    author = db.relationship('User', backref='comment_likes')

class CommentReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    author = db.relationship('User', backref='replies')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'))
    author = db.relationship('User', backref='comments')
    likes = db.relationship('CommentLike', backref='comment', lazy='dynamic')
    replies = db.relationship('CommentReply', backref='comment', lazy='dynamic')

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'))
    author = db.relationship('User', backref='user_likes')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    link = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    type = db.Column(db.String(20), default='info')  # info, message, follow, like, comment
    
    user = db.relationship('User', backref='notifications')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Ana sayfa
@app.route('/')
def index():
    if current_user.is_authenticated:
        # Filtreleme parametrelerini al
        university_filter = request.args.get('university')
        department_filter = request.args.get('department')
        subject_filter = request.args.get('subject')
        
        # Base query
        query = Note.query
        
        # Filtreleri uygula
        if university_filter:
            # Not yazarının üniversitesiyle eşleştir
            query = query.join(User).filter(User.university.like(f'%{university_filter}%'))
        
        if department_filter:
            # Not yazarının bölümüyle eşleştir
            query = query.join(User, isouter=True).filter(User.department.like(f'%{department_filter}%'))
        
        if subject_filter:
            # Not konusuyla eşleştir
            query = query.filter(Note.subject.like(f'%{subject_filter}%'))
        
        # Eğer filtre varsa uygula, yoksa tüm notları göster
        if not (university_filter or department_filter or subject_filter):
            # Tüm notları göster
            notes = Note.query.order_by(Note.timestamp.desc()).all()
        else:
            # Notları zaman damgasına göre sırala ve getir
            notes = query.order_by(Note.timestamp.desc()).all()
        
        # Veritabanından üniversiteleri çek
        universities = User.query.with_entities(User.university).distinct().all()
        universities = [university[0] for university in universities if university[0]]  # Boş değerleri filtrele

        # Filtreleme parametresini al
        university_filter = request.args.get('university', '')

        # Kullanıcıları filtrele
        filtered_users = User.query
        if university_filter:
            filtered_users = filtered_users.filter_by(university=university_filter)
        filtered_users = filtered_users.all()

        # Tüm üniversiteleri ve bölümleri filtreleme için getir
        universities = db.session.query(User.university).distinct().all()
        departments = db.session.query(User.department).distinct().all()
        subjects = db.session.query(Note.subject).distinct().all()
        
        return render_template('index.html', 
                              notes=notes, 
                              show_all=bool(request.args.get('all_notes')),
                              universities=[u[0] for u in universities if u[0]],
                              departments=[d[0] for d in departments if d[0]],
                              subjects=[s[0] for s in subjects if s[0]],
                              current_university_filter=university_filter,
                              current_department_filter=department_filter,
                              current_subject_filter=subject_filter)
    return render_template('welcome.html')

# Kullanıcı kaydı
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        university = request.form.get('university')
        department = request.form.get('department')
        
        user_exists = User.query.filter_by(username=username).first()
        email_exists = User.query.filter_by(email=email).first()
        
        if user_exists:
            flash('Bu kullanıcı adı zaten alınmış.')
            return redirect(url_for('register'))
        
        if email_exists:
            flash('Bu e-posta adresi zaten kullanılıyor.')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email, university=university, department=department, profile_image='profiles/default_profile.jpg')
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Kayıt başarılı! Şimdi giriş yapabilirsiniz.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Giriş
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user is None or not user.check_password(password):
            flash('Geçersiz kullanıcı adı veya şifre')
            return redirect(url_for('login'))
        
        login_user(user)
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('index')
        return redirect(next_page)
    
    return render_template('login.html')

# Çıkış yap
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# Profil görüntüleme
@app.route('/user/<username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    notes = Note.query.filter_by(author=user).order_by(Note.timestamp.desc()).all()
    return render_template('profile.html', user=user, notes=notes)

# Profil düzenleme
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.about_me = request.form.get('about_me')
        current_user.university = request.form.get('university')
        current_user.department = request.form.get('department')
        
        # Profil resmi yükleme
        if 'profile_image' in request.files:
            profile_image = request.files['profile_image']
            if profile_image.filename:
                # Profil resimleri için klasör oluştur
                profile_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles')
                os.makedirs(profile_upload_folder, exist_ok=True)
                
                # Dosya adını güvenli hale getir ve benzersiz yap
                filename = secure_filename(profile_image.filename)
                file_ext = os.path.splitext(filename)[1]
                unique_filename = f"{current_user.username}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}{file_ext}"
                
                # Dosyayı kaydet
                file_path = os.path.join(profile_upload_folder, unique_filename)
                profile_image.save(file_path)
                
                # Kullanıcının profil resmini güncelle
                current_user.profile_image = f"profiles/{unique_filename}"
        
        db.session.commit()
        flash('Profiliniz güncellendi.')
        return redirect(url_for('user_profile', username=current_user.username))
    
    return render_template('edit_profile.html')

# Kullanıcı takip etme
@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(f'{username} adlı kullanıcı bulunamadı.')
        return redirect(url_for('index'))
    if user == current_user:
        flash('Kendinizi takip edemezsiniz!')
        return redirect(url_for('user_profile', username=username))
    current_user.follow(user)
    
    # Bildirim oluştur
    notification = Notification(
        user_id=user.id, 
        message=f"{current_user.username} sizi takip etmeye başladı", 
        link=url_for('user_profile', username=current_user.username),
        type='follow'
    )
    db.session.add(notification)
    db.session.commit()
    
    flash(f'{username} kullanıcısını takip ediyorsunuz.')
    return redirect(url_for('user_profile', username=username))

# Kullanıcı takibi bırakma
@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(f'{username} adlı kullanıcı bulunamadı.')
        return redirect(url_for('index'))
    if user == current_user:
        flash('Kendinizi takipten çıkaramazsınız!')
        return redirect(url_for('user_profile', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash(f'{username} kullanıcısını takip etmeyi bıraktınız.')
    return redirect(url_for('user_profile', username=username))

# Not oluşturma
@app.route('/create_note', methods=['GET', 'POST'])
@login_required
def create_note():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        subject = request.form.get('subject')
        
        if not title or not content:
            flash('Başlık ve içerik alanları doldurulmalıdır.')
            return redirect(url_for('create_note'))
        
        note = Note(title=title, content=content, subject=subject, author=current_user)
        db.session.add(note)
        db.session.commit()
        
        # Dosya yükleme
        if 'files' in request.files:
            files = request.files.getlist('files')
            for file in files:
                if file.filename:
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    note_file = NoteFile(filename=filename, note=note)
                    db.session.add(note_file)
            
            db.session.commit()
        
        flash('Notunuz başarıyla paylaşıldı!')
        return redirect(url_for('index'))
    
    return render_template('create_note.html')

# Not görüntüleme
@app.route('/note/<int:note_id>')
def view_note(note_id):
    note = Note.query.get_or_404(note_id)
    return render_template('view_note.html', note=note)

# Not beğenme
@app.route('/like/<int:note_id>')
@login_required
def like_note(note_id):
    note = Note.query.get_or_404(note_id)
    
    # Eğer kullanıcı zaten beğenmiş ise beğeniyi kaldır
    like = Like.query.filter_by(user_id=current_user.id, note_id=note_id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
        flash('Beğeni kaldırıldı.')
    else:
        # Yeni beğeni ekle
        like = Like(user_id=current_user.id, note_id=note_id)
        db.session.add(like)
        db.session.commit()
        flash('Not beğenildi!')
    
    return redirect(url_for('view_note', note_id=note_id))

# Yorum ekleme
@app.route('/comment/<int:note_id>', methods=['POST'])
@login_required
def add_comment(note_id):
    note = Note.query.get_or_404(note_id)
    content = request.form.get('content')
    
    if not content:
        flash('Yorum boş olamaz.')
        return redirect(url_for('view_note', note_id=note_id))
    
    comment = Comment(content=content, author=current_user, note=note)
    db.session.add(comment)
    
    # Bildirim oluştur
    if note.author != current_user:
        notification = Notification(
            user_id=note.author.id, 
            message=f"{current_user.username} notunuza yorum yaptı", 
            link=url_for('view_note', note_id=note_id, _anchor=f'comment-{comment.id}'),
            type='comment'
        )
        db.session.add(notification)
    
    db.session.commit()
    
    flash('Yorumunuz eklendi!')
    
    # Referer URL'yi kontrol et
    referrer = request.referrer
    if referrer and 'view_note' in referrer:
        return redirect(url_for('view_note', note_id=note_id))
    else:
        return redirect(url_for('index', _anchor=f'note-{note_id}'))

# Yorum beğenme
@app.route('/like_comment/<int:comment_id>')
@login_required
def like_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    # Eğer kullanıcı zaten beğenmiş ise beğeniyi kaldır
    like = CommentLike.query.filter_by(user_id=current_user.id, comment_id=comment_id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
        flash('Yorum beğenisi kaldırıldı.')
    else:
        # Yeni beğeni ekle
        like = CommentLike(user_id=current_user.id, comment_id=comment_id)
        db.session.add(like)
        db.session.commit()
        flash('Yorum beğenildi!')
    
    return redirect(url_for('view_note', note_id=comment.note_id))

# Yoruma yanıt verme
@app.route('/reply_comment/<int:comment_id>', methods=['POST'])
@login_required
def reply_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    content = request.form.get('reply_content')
    
    if not content:
        flash('Yanıt boş olamaz.')
        return redirect(url_for('view_note', note_id=comment.note_id))
    
    reply = CommentReply(content=content, author=current_user, comment=comment)
    db.session.add(reply)
    db.session.commit()
    
    flash('Yanıtınız eklendi!')
    return redirect(url_for('view_note', note_id=comment.note_id))

# Kullanıcı ve not arama
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    if query:
        users = User.query.filter(User.username.like(f'%{query}%')).all()
        # Not başlığı veya içeriği sorguyu içeren notları bul
        notes = Note.query.filter(
            db.or_(
                Note.title.like(f'%{query}%'), 
                Note.content.like(f'%{query}%')
            )
        ).all()
        return render_template('search_results.html', users=users, notes=notes, query=query)
    
    return render_template('search.html')

# Not paylaşma
@app.route('/share_note/<int:note_id>')
@login_required
def share_note(note_id):
    note = Note.query.get_or_404(note_id)
    # Link oluştur
    share_link = url_for('index', _anchor=f'note-{note_id}', _external=True)
    flash(f'Not paylaşım linki: {share_link}')
    return redirect(url_for('index'))

# Bildirimleri görüntüle
@app.route('/notifications')
@login_required
def notifications():
    # Tüm bildirimleri al
    user_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    
    # Okunmamış bildirimleri okundu olarak işaretle
    for notification in user_notifications:
        if not notification.read:
            notification.read = True
    
    db.session.commit()
    
    return render_template('notifications.html', notifications=user_notifications)

# Okunmamış bildirim sayısını döndüren yardımcı fonksiyon
@app.context_processor
def inject_unread_count():
    # Kullanıcı giriş yapmış mı kontrol et
    if current_user.is_authenticated:
        unread_messages = Message.query.filter_by(recipient_id=current_user.id, read=False).count()
        unread_notifications = Notification.query.filter_by(user_id=current_user.id, read=False).count()
        return {'unread_messages': unread_messages, 'unread_notifications': unread_notifications}
    # Kullanıcı giriş yapmamışsa sıfır değerleri döndür
    return {'unread_messages': 0, 'unread_notifications': 0}

# Çevrimiçi kullanıcıları takip etmek için dictionary
online_users = {}

# Kullanıcı Socket.IO'ya bağlandığında
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(current_user.username)
        online_users[current_user.username] = request.sid
        emit('user_status', {'username': current_user.username, 'status': 'online'}, broadcast=True)

# Kullanıcının Socket.IO'dan bağlantısı kesildiğinde
@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated and current_user.username in online_users:
        leave_room(current_user.username)
        del online_users[current_user.username]
        emit('user_status', {'username': current_user.username, 'status': 'offline'}, broadcast=True)

# Mesaj gönderme
@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated:
        return {'status': 'error', 'message': 'Kullanıcı oturumu bulunamadı'}
    
    recipient_username = data.get('recipient')
    body = data.get('body')
    media_url = data.get('media_url')  # Yeni: Medya URL'si
    gif_url = data.get('gif_url')  # Yeni: GIF URL'si
    
    if not recipient_username or (not body and not media_url and not gif_url):
        return {'status': 'error', 'message': 'Geçersiz alıcı veya mesaj içeriği'}
    
    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return {'status': 'error', 'message': 'Alıcı bulunamadı'}
    
    try:
        # Mesajı veritabanına kaydet
        message = Message(
            sender=current_user,
            recipient=recipient,
            body=body,
            media_url=media_url,
            gif_url=gif_url,
            timestamp=datetime.now()
        )
        db.session.add(message)
        
        # Bildirim oluştur
        notification = Notification(
            user_id=recipient.id,
            message=f"{current_user.username} tarafından yeni bir mesaj aldınız",
            link="/messages",
            type='message',
            timestamp=datetime.now()
        )
        db.session.add(notification)
        db.session.commit()
        
        # Mesajı alıcıya gönder
        formatted_time = message.timestamp.strftime('%d.%m.%Y, %H:%M')
        emit('new_message', {
            'message_id': message.id,
            'sender': current_user.username,
            'body': body,
            'media_url': media_url,
            'gif_url': gif_url,
            'timestamp': formatted_time
        }, room=recipient_username)
        
        return {'status': 'success'}
    except Exception as e:
        db.session.rollback()
        return {'status': 'error', 'message': f'Mesaj gönderilirken bir hata oluştu: {str(e)}'}

# Medya yükleme endpoint'i
@app.route('/upload_media', methods=['POST'])
@login_required
def upload_media():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'Dosya bulunamadı'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'Dosya adı boş'}), 400
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    media_url = url_for('static', filename=f'uploads/{file.filename}')
    return jsonify({'status': 'success', 'media_url': media_url})

# Mesajları okundu olarak işaretleme
@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    if not current_user.is_authenticated:
        return {'status': 'error', 'message': 'Kullanıcı oturumu bulunamadı'}
    message_id = data.get('message_id')
    if not message_id:
        return {'status': 'error', 'message': 'Mesaj ID bulunamadı'}
    try:
        message = Message.query.get(message_id)
        if not message or message.recipient != current_user:
            return {'status': 'error', 'message': 'Mesaj bulunamadı veya bu mesaja erişim izniniz yok'}
        message.read = True
        db.session.commit()
        return {'status': 'success'}
    except Exception as e:
        db.session.rollback()
        return {'status': 'error', 'message': f'Mesaj işaretleme hatası: {str(e)}'}

# Tüm konuşmayı okundu olarak işaretleme
@socketio.on('mark_conversation_read')
def handle_mark_conversation_read(data):
    if not current_user.is_authenticated:
        return {'status': 'error', 'message': 'Kullanıcı oturumu bulunamadı'}
    sender_username = data.get('sender')
    if not sender_username:
        return {'status': 'error', 'message': 'Gönderen kullanıcı adı bulunamadı'}
    try:
        sender = User.query.filter_by(username=sender_username).first()
        if not sender:
            return {'status': 'error', 'message': 'Gönderen kullanıcı bulunamadı'}
        # Okunmamış mesajları bul ve güncelle
        unread_messages = Message.query.filter_by(sender=sender, recipient=current_user, read=False).all()
        for message in unread_messages:
            message.read = True
        db.session.commit()
        return {'status': 'success'}
    except Exception as e:
        db.session.rollback()
        return {'status': 'error', 'message': f'Konuşma işaretleme hatası: {str(e)}'}

# Sohbet geçmişini çekme
@app.route('/api/conversation_history', methods=['GET'])
@login_required
def api_conversation_history():
    username = request.args.get('username')
    if not username:
        return jsonify({"error": "Geçersiz kullanıcı adı."}), 400
    partner = User.query.filter_by(username=username).first()
    if not partner:
        return jsonify([]), 404  # Boş bir liste döndür
    messages = (
        Message.query
        .filter(
            ((Message.sender == current_user) & (Message.recipient == partner)) |
            ((Message.sender == partner) & (Message.recipient == current_user))
        )
        .order_by(Message.timestamp.asc())
        .all()
    )
    formatted_messages = [
        {
            "id": message.id,
            "isReceived": message.sender != current_user,
            "body": message.body,
            "media_url": message.media_url,
            "gif_url": message.gif_url,
            "timestamp": message.timestamp.strftime('%d.%m.%Y, %H:%M'),
            "read": message.read
        }
        for message in messages
    ]
    return jsonify(formatted_messages)

# Ana sayfa
@app.route('/messages')
@login_required
def messages():
    return render_template('messages.html')


# # Mesaj gönderme
# @app.route('/send_message/<username>', methods=['GET', 'POST'])
# @login_required
# def send_message(username):
#     user = User.query.filter_by(username=username).first_or_404()
    
#     if user == current_user:
#         flash('Kendinize mesaj gönderemezsiniz!')
#         return redirect(url_for('index'))
    
#     if request.method == 'POST':
#         body = request.form.get('body')
        
#         if not body:
#             flash('Boş mesaj gönderilemez.')
#             # Referrer URL'den gelen istekleri kontrol et
#             referrer = request.referrer
#             if referrer and 'messages' in referrer:
#                 return redirect(url_for('messages'))
#             return redirect(url_for('send_message', username=username))
        
#         message = Message(sender=current_user, recipient=user, body=body)
#         db.session.add(message)
        
#         # Bildirim oluştur
#         notification = Notification(
#             user_id=user.id, 
#             message=f"{current_user.username} tarafından yeni bir mesaj aldınız", 
#             link=url_for('messages'),
#             type='message'
#         )
#         db.session.add(notification)
#         db.session.commit()
        
#         # Referrer URL'den gelen istekleri kontrol et
#         referrer = request.referrer
#         if referrer and 'messages' in referrer:
#             return redirect(url_for('messages'))
        
#         flash('Mesajınız gönderildi!')
#         return redirect(url_for('user_profile', username=username))
    
#     return render_template('send_message.html', user=user)

# # # Mesajları görüntüleme
# @app.route('/messages')
# @login_required
# def messages():
#     # Kullanıcının aldığı tüm mesajları al
#     received_messages = Message.query.filter_by(recipient=current_user).order_by(Message.timestamp.desc()).all()
#     # Kullanıcının gönderdiği tüm mesajları al
#     sent_messages = Message.query.filter_by(sender=current_user).order_by(Message.timestamp.desc()).all()
    
#     # Okunmamış mesajları okundu olarak işaretle
#     for message in received_messages:
#         if not message.read:
#             message.read = True
    
#     db.session.commit()
    
#     return render_template('messages.html', received_messages=received_messages, sent_messages=sent_messages)



# Filtreleme
@app.route('/filter')
def filter():
    # Veritabanından üniversiteleri çek
    universities = User.query.with_entities(User.university).distinct().all()
    universities = [university[0] for university in universities if university[0]]  # Boş değerleri filtrele

    # Diğer filtreleme parametrelerini al
    university_filter = request.args.get('university', '')
    department_filter = request.args.get('department', '')
    subject_filter = request.args.get('subject', '')

    # Sorguyu oluştur (filtreleme işlemleri burada...)
    filtered_notes = (
        Note.query.join(User, Note.user_id == User.id)
        .filter(
            (not university_filter or User.university.like(f"%{university_filter}%")),
            (not department_filter or User.department.like(f"%{department_filter}%")),
            (not subject_filter or Note.subject.like(f"%{subject_filter}%"))
        )
        .order_by(Note.timestamp.desc())
        .all()
    )

    return render_template('index.html', notes=filtered_notes, universities=universities)

# Uygulama başlatma
if __name__ == '__main__':
    # with app.app_context():
    #     db.drop_all()  # Tüm tabloları sil
    #     db.create_all()  # Tabloları yeniden oluştur
    #     print("Veritabanı başarıyla sıfırlandı ve yeniden oluşturuldu.")
    socketio.run(app, debug=True)
    app.run(host='0.0.0.0', port=8080, debug=True)
