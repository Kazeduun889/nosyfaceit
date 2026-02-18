from flask import Flask, render_template, request, redirect, url_for, session, flash, g, send_file
import sqlite3
import os
import sys
from datetime import datetime

# Add parent directory to path to import db.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    import db
    # Initialize DB on startup (auto-migrate)
    print("Initializing database...")
    db.init_db()
except ImportError:
    print("Warning: Could not import db module. Database initialization skipped.")
    pass 
except Exception as e:
    print(f"Error initializing database: {e}")

# Explicitly set template and static folders relative to this file
basedir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(basedir, 'templates')
static_dir = os.path.join(basedir, 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-change-me')

def get_db_connection():
    try:
        return db.get_db_connection()
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    try:
        user = None
        if 'user_id' in session:
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE user_id = ?', (session['user_id'],)).fetchone()
            
            if user is None:
                session.clear()
                return redirect(url_for('index'))
                
            conn.close()
            
        return render_template('index.html', user=user)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"<h1>Internal Server Error (Debug)</h1><p>{str(e)}</p><pre>{traceback.format_exc()}</pre><p>Please send this to the developer.</p>"

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        avatar_url = request.form.get('avatar_url')
        bio = request.form.get('bio')
        
        # Validation
        if avatar_url and len(avatar_url) > 500: avatar_url = avatar_url[:500]
        if bio and len(bio) > 1000: bio = bio[:1000]
        if nickname and len(nickname) > 20: nickname = nickname[:20]
        
        try:
            if nickname:
                # Check uniqueness if changed
                current_nick = conn.execute('SELECT nickname FROM users WHERE user_id = ?', (session['user_id'],)).fetchone()[0]
                if nickname != current_nick:
                    exists = conn.execute('SELECT 1 FROM users WHERE nickname = ?', (nickname,)).fetchone()
                    if exists:
                        flash('Этот никнейм уже занят!', 'error')
                        return redirect(url_for('settings'))
                    session['nickname'] = nickname # Update session

            conn.execute('UPDATE users SET nickname = ?, avatar_url = ?, bio = ? WHERE user_id = ?',
                         (nickname, avatar_url, bio, session['user_id']))
            conn.commit()
            flash('Настройки сохранены!', 'success')
        except sqlite3.OperationalError:
            flash('Ошибка базы данных. Пожалуйста, обновите базу (/debug/update_db)', 'error')
        except Exception as e:
            flash(f'Ошибка: {e}', 'error')
            
    user = conn.execute('SELECT * FROM users WHERE user_id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return render_template('settings.html', user=user)

@app.route('/health')
def health_check():
    return "OK", 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
        
        if user:
            session['user_id'] = user['user_id']
            session['nickname'] = user['nickname']
            # Safe access to is_admin
            try:
                session['is_admin'] = user['is_admin']
            except (IndexError, KeyError):
                session['is_admin'] = 0
                
            flash('Вы успешно вошли!', 'success')
            conn.close()
            return redirect(url_for('index'))
        else:
            # Auto-register if user not found (for testing/easy access)
            try:
                # Default nickname based on ID
                nickname = f"User_{user_id}"
                conn.execute('INSERT INTO users (user_id, nickname, elo, is_admin) VALUES (?, ?, ?, ?)', 
                             (user_id, nickname, 1000, 0))
                conn.commit()
                
                # Login immediately
                session['user_id'] = int(user_id)
                session['nickname'] = nickname
                session['is_admin'] = 0
                
                flash(f'Аккаунт создан! Ваш ник: {nickname}. Измените его в настройках.', 'success')
                conn.close()
                return redirect(url_for('index'))
            except Exception as e:
                flash(f'Ошибка регистрации: {e}', 'error')
                conn.close()
            
    return render_template('login.html')

@app.route('/debug/update_db')
def update_db():
    try:
        # Re-import db to ensure we have latest version
        import sys
        if 'db' in sys.modules:
            import importlib
            importlib.reload(sys.modules['db'])
        else:
            import db
            
        db.init_db()
        return "Database updated successfully! <a href='/'>Go Home</a>"
    except Exception as e:
        return f"Error updating database: {e}"

@app.route('/debug/reset_all')
def reset_all_data():
    if not session.get('is_admin'):
        return "Access denied. Only admins can reset the database."
        
    try:
        conn = get_db_connection()
        # Wipe all data but keep tables
        tables = [
            'users', 'matches', 'match_players', 'support_tickets', 'lobby_members',
            'clans', 'clan_members', 'polls', 'poll_options', 'poll_votes',
            'clan_matchmaking_queue', 'clan_matches', 'matchmaking_queue', 
            'match_stats', 'match_chat'
        ]
        
        for table in tables:
            try:
                conn.execute(f'DELETE FROM {table}')
                # Reset auto-increment
                if not db.IS_POSTGRES:
                    try:
                        conn.execute(f"DELETE FROM sqlite_sequence WHERE name='{table}'")
                    except Exception: pass
            except (sqlite3.OperationalError, Exception):
                pass # Table might not exist yet
                
        conn.commit()
        conn.close()
        
        session.clear() # Logout everyone
        return "ALL DATA WIPED! Site is fresh. <a href='/'>Go Home</a>"
    except Exception as e:
        return f"Error resetting database: {e}"

@app.route('/debug/make_me_admin/<secret_key>')
def make_me_admin_route(secret_key):
    if secret_key != 'super-admin-secret':
        return "Invalid secret key"
        
    if 'user_id' not in session:
        return "Please login first"
        
    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET is_admin = 1 WHERE user_id = ?', (session['user_id'],))
        conn.commit()
        session['is_admin'] = 1
        return "You are now an admin! <a href='/'>Go Home</a>"
    except Exception as e:
        return f"Error: {e}"
    finally:
        conn.close()

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

@app.route('/matches')
def matches():
    conn = get_db_connection()
    matches = conn.execute('SELECT * FROM matches ORDER BY created_at DESC LIMIT 50').fetchall()
    conn.close()
    return render_template('matches.html', matches=matches)

@app.route('/matches/<int:match_id>')
def match_detail(match_id):
    conn = get_db_connection()
    match = conn.execute('SELECT * FROM matches WHERE id = ?', (match_id,)).fetchone()
    
    if not match:
        conn.close()
        return "Match not found", 404
        
    # Get players with team info (if available)
    players = conn.execute('''
        SELECT mp.*, u.nickname, u.elo, u.avatar_url, ms.kills, ms.deaths
        FROM match_players mp
        JOIN users u ON mp.user_id = u.user_id
        LEFT JOIN match_stats ms ON ms.match_id = mp.match_id AND ms.user_id = mp.user_id
        WHERE mp.match_id = ?
    ''', (match_id,)).fetchall()
    
    conn.close()
    return render_template('match_detail.html', match=match, players=players)

@app.route('/u/<nickname>')
def user_profile(nickname):
    conn = get_db_connection()
    # Use db helper if possible, but we are in app.py with local get_db_connection
    # Let's just use SQL directly for consistency within app.py
    user = conn.execute('SELECT * FROM users WHERE nickname = ?', (nickname,)).fetchone()
    
    if not user:
        conn.close()
        return "User not found", 404
        
    friend_status = None
    if 'user_id' in session and session['user_id'] != user['user_id']:
        # Check friend status
        res = conn.execute('''
            SELECT user_id, status FROM friends 
            WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
        ''', (session['user_id'], user['user_id'], user['user_id'], session['user_id'])).fetchone()
        if res:
            friend_status = (res['user_id'], res['status']) # (requester_id, status)
            
    conn.close()
    return render_template('user_profile.html', user=user, friend_status=friend_status)

@app.route('/friends')
def friends_list():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    user_id = session['user_id']
    
    # Get accepted friends
    friends = conn.execute('''
        SELECT u.user_id, u.nickname, u.avatar_url, u.elo, u.is_vip
        FROM users u
        JOIN friends f ON (f.friend_id = u.user_id AND f.user_id = ?) 
                       OR (f.user_id = u.user_id AND f.friend_id = ?)
        WHERE f.status = 'accepted'
    ''', (user_id, user_id)).fetchall()
    
    # Get pending requests (incoming)
    requests = conn.execute('''
        SELECT u.user_id, u.nickname, u.avatar_url
        FROM users u
        JOIN friends f ON f.user_id = u.user_id
        WHERE f.friend_id = ? AND f.status = 'pending'
    ''', (user_id,)).fetchall()
    
    conn.close()
    return render_template('friends.html', friends=friends, requests=requests)

@app.route('/friends/add/<int:friend_id>', methods=['POST'])
def add_friend(friend_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        # Check if already friends
        existing = conn.execute('SELECT 1 FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)', 
                                (session['user_id'], friend_id, friend_id, session['user_id'])).fetchone()
        if not existing:
            conn.execute('INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, ?)', (session['user_id'], friend_id, 'pending'))
            conn.commit()
            flash('Запрос отправлен!', 'success')
        else:
            flash('Запрос уже отправлен или вы уже друзья', 'info')
    except Exception as e:
        flash(f'Error: {e}', 'error')
    finally:
        conn.close()
        
    return redirect(request.referrer or url_for('friends_list'))

@app.route('/friends/accept/<int:friend_id>', methods=['POST'])
def accept_friend(friend_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        conn.execute("UPDATE friends SET status = 'accepted' WHERE user_id = ? AND friend_id = ?", (friend_id, session['user_id']))
        conn.commit()
        flash('Запрос принят!', 'success')
    except Exception as e:
        flash(f'Error: {e}', 'error')
    finally:
        conn.close()
        
    return redirect(request.referrer or url_for('friends_list'))

@app.route('/friends/remove/<int:friend_id>', methods=['POST'])
def remove_friend(friend_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)', 
                     (session['user_id'], friend_id, friend_id, session['user_id']))
        conn.commit()
        flash('Пользователь удален из друзей', 'info')
    except Exception as e:
        flash(f'Error: {e}', 'error')
    finally:
        conn.close()
        
    return redirect(request.referrer or url_for('friends_list'))

@app.route('/leaderboard')
def leaderboard():
    conn = get_db_connection()
    # Join with clans to get tags
    users = conn.execute('''
        SELECT u.*, c.tag as clan_tag 
        FROM users u 
        LEFT JOIN clan_members cm ON u.user_id = cm.user_id 
        LEFT JOIN clans c ON cm.clan_id = c.id 
        ORDER BY u.elo DESC LIMIT 50
    ''').fetchall()
    conn.close()
    return render_template('leaderboard.html', users=users)

# === CLAN SYSTEM ===

@app.route('/clans')
def clans():
    conn = get_db_connection()
    clans = conn.execute('SELECT * FROM clans ORDER BY clan_elo DESC').fetchall()
    
    user_clan = None
    if 'user_id' in session:
        user_clan = conn.execute('''
            SELECT c.* FROM clans c 
            JOIN clan_members cm ON c.id = cm.clan_id 
            WHERE cm.user_id = ?
        ''', (session['user_id'],)).fetchone()
        
    conn.close()
    return render_template('clans.html', clans=clans, user_clan=user_clan)

@app.route('/clans/create', methods=['GET', 'POST'])
def create_clan():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    
    # Check if user is already in a clan
    existing_clan = conn.execute('SELECT * FROM clan_members WHERE user_id = ?', (session['user_id'],)).fetchone()
    if existing_clan:
        conn.close()
        flash('Вы уже состоите в клане', 'error')
        return redirect(url_for('clans'))

    if request.method == 'POST':
        tag = request.form['tag'].upper()
        name = request.form['name']
        
        if not tag or not name:
            flash('Заполните все поля', 'error')
        elif len(tag) > 5:
            flash('Тег не может быть длиннее 5 символов', 'error')
        else:
            try:
                cursor = conn.cursor()
                if db.IS_POSTGRES:
                    cursor.execute('INSERT INTO clans (tag, name, owner_id) VALUES (%s, %s, %s) RETURNING id', (tag, name, session['user_id']))
                    clan_id = cursor.fetchone()[0]
                else:
                    cursor.execute('INSERT INTO clans (tag, name, owner_id) VALUES (?, ?, ?)', (tag, name, session['user_id']))
                    clan_id = cursor.lastrowid
                
                if db.IS_POSTGRES:
                    cursor.execute('INSERT INTO clan_members (clan_id, user_id, role) VALUES (%s, %s, %s)', (clan_id, session['user_id'], 'owner'))
                else:
                    cursor.execute('INSERT INTO clan_members (clan_id, user_id, role) VALUES (?, ?, ?)', (clan_id, session['user_id'], 'owner'))
                
                conn.commit()
                flash('Клан успешно создан!', 'success')
                return redirect(url_for('clan_detail', clan_id=clan_id))
            except (sqlite3.IntegrityError, db.IntegrityError):
                flash('Клан с таким тегом уже существует', 'error')
            except Exception as e:
                flash(f'Ошибка создания клана: {e}', 'error')
                
    conn.close()
    return render_template('create_clan.html')

@app.route('/clans/<int:clan_id>')
def clan_detail(clan_id):
    conn = get_db_connection()
    clan = conn.execute('SELECT * FROM clans WHERE id = ?', (clan_id,)).fetchone()
    
    if not clan:
        conn.close()
        flash('Клан не найден', 'error')
        return redirect(url_for('clans'))
        
    members = conn.execute('''
        SELECT u.nickname, u.elo, cm.role, u.user_id
        FROM clan_members cm
        JOIN users u ON cm.user_id = u.user_id
        WHERE cm.clan_id = ?
    ''', (clan_id,)).fetchall()
    
    is_member = False
    is_owner = False
    if 'user_id' in session:
        member_record = conn.execute('SELECT * FROM clan_members WHERE clan_id = ? AND user_id = ?', (clan_id, session['user_id'])).fetchone()
        if member_record:
            is_member = True
            if member_record['role'] == 'owner':
                is_owner = True
                
    conn.close()
    return render_template('clan_detail.html', clan=clan, members=members, is_member=is_member, is_owner=is_owner)

@app.route('/clans/<int:clan_id>/join', methods=['POST'])
def join_clan(clan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    
    # Check if user is already in ANY clan
    existing_clan = conn.execute('SELECT * FROM clan_members WHERE user_id = ?', (session['user_id'],)).fetchone()
    if existing_clan:
        conn.close()
        flash('Вы уже состоите в клане', 'error')
        return redirect(url_for('clans'))
        
    try:
        conn.execute('INSERT INTO clan_members (clan_id, user_id) VALUES (?, ?)', (clan_id, session['user_id']))
        conn.commit()
        flash('Вы вступили в клан!', 'success')
    except Exception as e:
        flash(f'Ошибка вступления: {e}', 'error')
        
    conn.close()
    return redirect(url_for('clan_detail', clan_id=clan_id))

@app.route('/clans/<int:clan_id>/leave', methods=['POST'])
def leave_clan(clan_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    
    # Check if user is owner
    member = conn.execute('SELECT * FROM clan_members WHERE clan_id = ? AND user_id = ?', (clan_id, session['user_id'])).fetchone()
    if member and member['role'] == 'owner':
        conn.close()
        flash('Владелец не может покинуть клан. Удалите клан или передайте права.', 'error')
        return redirect(url_for('clan_detail', clan_id=clan_id))
        
    conn.execute('DELETE FROM clan_members WHERE clan_id = ? AND user_id = ?', (clan_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Вы покинули клан', 'info')
    return redirect(url_for('clans'))

@app.route('/clans/matchmaking')
def clan_matchmaking():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    
    # Get user's clan and role
    user_clan_info = conn.execute('''
        SELECT c.id, c.name, cm.role 
        FROM clan_members cm
        JOIN clans c ON cm.clan_id = c.id
        WHERE cm.user_id = ?
    ''', (session['user_id'],)).fetchone()
    
    if not user_clan_info:
        conn.close()
        flash('Вы должны состоять в клане', 'error')
        return redirect(url_for('clans'))
        
    if user_clan_info['role'] != 'owner':
        conn.close()
        flash('Только лидер клана может искать матчи', 'error')
        return redirect(url_for('clan_detail', clan_id=user_clan_info['id']))
        
    # Check queue status
    in_queue = conn.execute('SELECT * FROM clan_matchmaking_queue WHERE clan_id = ?', (user_clan_info['id'],)).fetchone()
    
    # Find active matches
    active_match = conn.execute('''
        SELECT * FROM clan_matches 
        WHERE (clan1_id = ? OR clan2_id = ?) AND status = 'active'
    ''', (user_clan_info['id'], user_clan_info['id'])).fetchone()
    
    opponent = None
    if active_match:
        opponent_id = active_match['clan2_id'] if active_match['clan1_id'] == user_clan_info['id'] else active_match['clan1_id']
        opponent = conn.execute('SELECT * FROM clans WHERE id = ?', (opponent_id,)).fetchone()
        
    conn.close()
    return render_template('clan_matchmaking.html', clan=user_clan_info, in_queue=bool(in_queue), active_match=active_match, opponent=opponent)

@app.route('/clans/matchmaking/join', methods=['POST'])
def join_clan_queue():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    user_clan_info = conn.execute('SELECT clan_id, role FROM clan_members WHERE user_id = ?', (session['user_id'],)).fetchone()
    
    if not user_clan_info or user_clan_info['role'] != 'owner':
        conn.close()
        return redirect(url_for('clans'))
        
    clan_id = user_clan_info['clan_id']
    
    # Check if anyone else is in queue
    opponent_entry = conn.execute('SELECT * FROM clan_matchmaking_queue WHERE clan_id != ? ORDER BY joined_at ASC LIMIT 1', (clan_id,)).fetchone()
    
    if opponent_entry:
        # Match found!
        opponent_id = opponent_entry['clan_id']
        
        # Remove opponent from queue
        conn.execute('DELETE FROM clan_matchmaking_queue WHERE clan_id = ?', (opponent_id,))
        
        # Create match
        conn.execute('INSERT INTO clan_matches (clan1_id, clan2_id) VALUES (?, ?)', (clan_id, opponent_id))
        conn.commit()
        flash('Матч найден!', 'success')
    else:
        # Add to queue
        try:
            conn.execute('INSERT INTO clan_matchmaking_queue (clan_id) VALUES (?)', (clan_id,))
            conn.commit()
            flash('Вы добавлены в очередь поиска', 'info')
        except sqlite3.IntegrityError:
            pass # Already in queue
            
    conn.close()
    return redirect(url_for('clan_matchmaking'))

@app.route('/clans/matchmaking/leave', methods=['POST'])
def leave_clan_queue():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    user_clan_info = conn.execute('SELECT clan_id, role FROM clan_members WHERE user_id = ?', (session['user_id'],)).fetchone()
    
    if user_clan_info and user_clan_info['role'] == 'owner':
        conn.execute('DELETE FROM clan_matchmaking_queue WHERE clan_id = ?', (user_clan_info['clan_id'],))
        conn.commit()
        flash('Вы покинули очередь', 'info')
        
    conn.close()
    return redirect(url_for('clan_matchmaking'))

# === ADMIN PANEL ===

@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))
        
    conn = get_db_connection()
    
    # Stats for dashboard
    stats = {
        'users_count': conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'clans_count': conn.execute('SELECT COUNT(*) FROM clans').fetchone()[0],
        'matches_count': conn.execute('SELECT COUNT(*) FROM matches').fetchone()[0] + conn.execute('SELECT COUNT(*) FROM clan_matches').fetchone()[0],
    }
    
    # Recent items
    recent_users = conn.execute('SELECT * FROM users ORDER BY user_id DESC LIMIT 5').fetchall()
    recent_clans = conn.execute('SELECT * FROM clans ORDER BY created_at DESC LIMIT 5').fetchall()
    
    conn.close()
    return render_template('admin/dashboard.html', stats=stats, users=recent_users, clans=recent_clans)

@app.route('/admin/download_db')
def download_db():
    if not session.get('is_admin'): return redirect(url_for('index'))
    try:
        return send_file(os.path.join(app.root_path, '..', 'database.db'), as_attachment=True)
    except Exception as e:
        # Fallback for different path structure
        try:
            return send_file('database.db', as_attachment=True)
        except Exception as e2:
            return f"Error downloading database: {e}, {e2}"

@app.route('/admin/users')
def admin_users():
    if not session.get('is_admin'): return redirect(url_for('index'))
    
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users ORDER BY elo DESC').fetchall()
    conn.close()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/<int:user_id>/ban', methods=['POST'])
def admin_ban_user(user_id):
    if not session.get('is_admin'): return redirect(url_for('index'))
    
    conn = get_db_connection()
    conn.execute('UPDATE users SET is_banned = 1 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash(f'Пользователь {user_id} заблокирован', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/unban', methods=['POST'])
def admin_unban_user(user_id):
    if not session.get('is_admin'): return redirect(url_for('index'))
    
    conn = get_db_connection()
    conn.execute('UPDATE users SET is_banned = 0 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash(f'Пользователь {user_id} разблокирован', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/make_admin', methods=['POST'])
def admin_make_admin(user_id):
    if not session.get('is_admin'): return redirect(url_for('index'))
    
    conn = get_db_connection()
    conn.execute('UPDATE users SET is_admin = 1 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash(f'Пользователь {user_id} теперь АДМИНИСТРАТОР', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/revoke_admin', methods=['POST'])
def admin_revoke_admin(user_id):
    if not session.get('is_admin'): return redirect(url_for('index'))
    
    # Prevent removing admin from self (optional safety)
    if user_id == session['user_id']:
        flash('Вы не можете снять админку с самого себя!', 'error')
        return redirect(url_for('admin_users'))
        
    conn = get_db_connection()
    conn.execute('UPDATE users SET is_admin = 0 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash(f'Пользователь {user_id} больше не администратор', 'info')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/edit', methods=['POST'])
def admin_edit_user(user_id):
    if not session.get('is_admin'): return redirect(url_for('index'))
    
    nickname = request.form.get('nickname')
    elo = request.form.get('elo')
    
    conn = get_db_connection()
    try:
        if nickname:
            conn.execute('UPDATE users SET nickname = ? WHERE user_id = ?', (nickname, user_id))
        if elo:
            conn.execute('UPDATE users SET elo = ? WHERE user_id = ?', (elo, user_id))
        conn.commit()
        flash(f'Данные пользователя {user_id} обновлены', 'success')
    except Exception as e:
        flash(f'Ошибка обновления: {e}', 'error')
    finally:
        conn.close()
        
    return redirect(url_for('admin_users'))

@app.route('/admin/clans')
def admin_clans():
    if not session.get('is_admin'): return redirect(url_for('index'))
    conn = get_db_connection()
    clans = conn.execute('SELECT * FROM clans ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('admin/clans.html', clans=clans)

@app.route('/admin/clans/<int:clan_id>/delete', methods=['POST'])
def admin_delete_clan(clan_id):
    if not session.get('is_admin'): return redirect(url_for('index'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM clan_members WHERE clan_id = ?', (clan_id,))
    conn.execute('DELETE FROM clans WHERE id = ?', (clan_id,))
    conn.commit()
    conn.close()
    flash(f'Клан удален', 'success')
    return redirect(url_for('admin_clans'))

# === PLAYER MATCHMAKING ===

@app.route('/play')
def play():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Check if already in match
    active_match = conn.execute('''
        SELECT m.* FROM matches m
        JOIN match_players mp ON m.id = mp.match_id
        WHERE mp.user_id = ? AND m.status = 'active'
    ''', (session['user_id'],)).fetchone()
    
    if active_match:
        conn.close()
        return redirect(url_for('match_room', match_id=active_match['id']))
    
    # Check queue
    in_queue = conn.execute('SELECT * FROM matchmaking_queue WHERE user_id = ?', (session['user_id'],)).fetchone()
    queue_count = conn.execute('SELECT COUNT(*) FROM matchmaking_queue').fetchone()[0]
    
    conn.close()
    return render_template('play.html', in_queue=bool(in_queue), queue_count=queue_count)

@app.route('/play/join_queue', methods=['POST'])
def join_queue():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Check if opponent exists
    opponent = conn.execute('SELECT * FROM matchmaking_queue WHERE user_id != ? ORDER BY joined_at ASC LIMIT 1', (session['user_id'],)).fetchone()
    
    if opponent:
        # Match found!
        opponent_id = opponent['user_id']
        conn.execute('DELETE FROM matchmaking_queue WHERE user_id = ?', (opponent_id,))
        
        # Create match
        cursor = conn.cursor()
        if db.IS_POSTGRES:
            cursor.execute("INSERT INTO matches (mode, status) VALUES ('1x1', 'active') RETURNING id")
            match_id = cursor.fetchone()[0]
        else:
            cursor.execute("INSERT INTO matches (mode, status) VALUES ('1x1', 'active')")
            match_id = cursor.lastrowid
        
        # Add players
        if db.IS_POSTGRES:
            cursor.execute("INSERT INTO match_players (match_id, user_id, accepted) VALUES (%s, %s, 1)", (match_id, session['user_id']))
            cursor.execute("INSERT INTO match_players (match_id, user_id, accepted) VALUES (%s, %s, 1)", (match_id, opponent_id))
        else:
            cursor.execute("INSERT INTO match_players (match_id, user_id, accepted) VALUES (?, ?, 1)", (match_id, session['user_id']))
            cursor.execute("INSERT INTO match_players (match_id, user_id, accepted) VALUES (?, ?, 1)", (match_id, opponent_id))
        
        conn.commit()
        flash('Матч найден!', 'success')
        conn.close()
        return redirect(url_for('match_room', match_id=match_id))
        
    else:
        # Add to queue
        try:
            conn.execute('INSERT INTO matchmaking_queue (user_id) VALUES (?)', (session['user_id'],))
            conn.commit()
        except (sqlite3.IntegrityError, db.IntegrityError):
            pass
            
    conn.close()
    return redirect(url_for('play'))

@app.route('/play/leave_queue', methods=['POST'])
def leave_queue():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM matchmaking_queue WHERE user_id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    return redirect(url_for('play'))

import json
import random

MAP_POOL = ['Cabbleway', 'Pipeline', 'Bridge', 'Pool', 'Temple', 'Yard', 'Desert']

@app.route('/match/<int:match_id>')
def match_room(match_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    match = conn.execute('SELECT * FROM matches WHERE id = ?', (match_id,)).fetchone()
    players = conn.execute('''
        SELECT u.*, mp.accepted 
        FROM match_players mp 
        JOIN users u ON mp.user_id = u.user_id 
        WHERE mp.match_id = ?
    ''', (match_id,)).fetchall()
    
    # Initialize Veto if not started and match is active
    if match['status'] == 'active' and not match['veto_status']:
        veto_status = {m: 'available' for m in MAP_POOL}
        # Random first turn
        first_turn = players[0]['user_id'] if players else session['user_id']
        
        conn.execute('UPDATE matches SET veto_status = ?, current_veto_turn = ? WHERE id = ?',
                     (json.dumps(veto_status), first_turn, match_id))
        conn.commit()
        # Refresh match data
        match = conn.execute('SELECT * FROM matches WHERE id = ?', (match_id,)).fetchone()
        
    conn.close()
    
    # Parse veto status
    veto_data = json.loads(match['veto_status']) if match['veto_status'] else {}
    
    # Get chat messages
    chat_messages = conn.execute('''
        SELECT mc.*, u.nickname, u.avatar_url 
        FROM match_chat mc
        JOIN users u ON mc.user_id = u.user_id
        WHERE mc.match_id = ?
        ORDER BY mc.created_at ASC
    ''', (match_id,)).fetchall()
    
    return render_template('match_room.html', match=match, players=players, veto_data=veto_data, map_pool=MAP_POOL, chat_messages=chat_messages)

@app.route('/match/<int:match_id>/chat', methods=['POST'])
def match_chat(match_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    message = request.form.get('message')
    if message and len(message.strip()) > 0:
        conn = get_db_connection()
        conn.execute('INSERT INTO match_chat (match_id, user_id, message) VALUES (?, ?, ?)',
                     (match_id, session['user_id'], message.strip()))
        conn.commit()
        conn.close()
        
    return redirect(url_for('match_room', match_id=match_id))

@app.route('/match/<int:match_id>/veto', methods=['POST'])
def match_veto(match_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    map_name = request.form.get('map_name')
    conn = get_db_connection()
    match = conn.execute('SELECT * FROM matches WHERE id = ?', (match_id,)).fetchone()
    
    if not match or match['status'] != 'active':
        conn.close()
        return redirect(url_for('match_room', match_id=match_id))
        
    # Check turn
    if match['current_veto_turn'] != session['user_id']:
        flash('Сейчас не ваш ход!', 'error')
        conn.close()
        return redirect(url_for('match_room', match_id=match_id))
        
    veto_data = json.loads(match['veto_status'])
    
    if veto_data.get(map_name) == 'available':
        # Ban map
        veto_data[map_name] = 'banned'
        
        # Check remaining maps
        available_maps = [m for m, s in veto_data.items() if s == 'available']
        
        if len(available_maps) == 1:
            # Last map picked!
            last_map = available_maps[0]
            veto_data[last_map] = 'picked'
            conn.execute('UPDATE matches SET veto_status = ?, map_picked = ? WHERE id = ?',
                         (json.dumps(veto_data), last_map, match_id))
        else:
            # Switch turn
            players = conn.execute('SELECT user_id FROM match_players WHERE match_id = ?', (match_id,)).fetchall()
            next_turn = None
            for p in players:
                if p['user_id'] != session['user_id']:
                    next_turn = p['user_id']
                    break
            
            conn.execute('UPDATE matches SET veto_status = ?, current_veto_turn = ? WHERE id = ?',
                         (json.dumps(veto_data), next_turn, match_id))
                         
        conn.commit()
        
    conn.close()
    return redirect(url_for('match_room', match_id=match_id))

@app.route('/match/<int:match_id>/submit_result', methods=['POST'])
def submit_match_result(match_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    winner_id = request.form.get('winner_id') # user_id of winner
    
    conn = get_db_connection()
    
    # Simple logic: anyone can submit, immediate effect (for prototype)
    # In real app: requires confirmation from both or admin
    
    conn.execute("UPDATE matches SET status = 'finished', winner_team = ? WHERE id = ?", (winner_id, match_id))
    
    # Update ELO (simplified)
    # Winner +25, Loser -25
    players = conn.execute('SELECT user_id FROM match_players WHERE match_id = ?', (match_id,)).fetchall()
    
    for p in players:
        if str(p['user_id']) == str(winner_id):
            conn.execute('UPDATE users SET elo = elo + 25, wins = wins + 1, matches = matches + 1 WHERE user_id = ?', (p['user_id'],))
        else:
            conn.execute('UPDATE users SET elo = elo - 25, matches = matches + 1 WHERE user_id = ?', (p['user_id'],))
            
    conn.commit()
    conn.close()
    
    flash('Результат матча подтвержден!', 'success')
    return redirect(url_for('match_room', match_id=match_id))

if __name__ == '__main__':
    app.run(debug=True, port=5000)