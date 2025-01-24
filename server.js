const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// 创建数据库连接
const db = new sqlite3.Database('users.db');

// 管理员账号配置
const ADMIN_CONFIG = {
    username: 'admin',
    password: 'admin123', // 这里应该使用加密后的密码
    displayName: '系统管理员',
    icon: 'A'
};

// 创建用户表和消息表
db.serialize(() => {
    // 创建用户表
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            display_name TEXT,
            icon TEXT
        )
    `);

    // 检查并创建管理员账号
    db.get('SELECT * FROM users WHERE username = ?', [ADMIN_CONFIG.username], async (err, row) => {
        if (err) {
            console.error('检查管理员账号错误:', err);
            return;
        }

        if (!row) {
            try {
                const hashedPassword = await bcrypt.hash(ADMIN_CONFIG.password, 10);
                db.run(
                    'INSERT INTO users (username, password, is_admin, display_name, icon) VALUES (?, ?, 1, ?, ?)',
                    [ADMIN_CONFIG.username, hashedPassword, ADMIN_CONFIG.displayName, ADMIN_CONFIG.icon],
                    (err) => {
                        if (err) {
                            console.error('创建管理员账号错误:', err);
                        } else {
                            console.log('管理员账号创建成功');
                        }
                    }
                );
            } catch (error) {
                console.error('创建管理员账号错误:', error);
            }
        }
    });

    // 创建消息表
    db.run(`
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT,
            group_id INTEGER,
            content TEXT,
            type TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            filename TEXT,
            fileUrl TEXT,
            fileType TEXT,
            fileSize INTEGER,
            FOREIGN KEY (sender) REFERENCES users(username),
            FOREIGN KEY (group_id) REFERENCES chat_groups(id)
        )
    `);

    // 创建好友关系表
    db.run(`
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1 TEXT NOT NULL,
            user2 TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user1) REFERENCES users(username),
            FOREIGN KEY (user2) REFERENCES users(username),
            UNIQUE(user1, user2)
        )
    `);

    // 创建群组表
    db.run(`
        CREATE TABLE IF NOT EXISTS chat_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            creator TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (creator) REFERENCES users(username)
        )
    `);

    // 创建群组成员表
    db.run(`
        CREATE TABLE IF NOT EXISTS group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES chat_groups(id),
            FOREIGN KEY (username) REFERENCES users(username),
            UNIQUE(group_id, username)
        )
    `);
});

// 中间件配置
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname))); // 添加静态文件服务
app.use('/uploads', express.static('uploads'));

// 确保上传目录存在
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// 文件上传配置
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // 保留原始文件扩展名
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + ext);
    }
});

// 添加文件大小限制和文件类型处理
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 1024 * 1024 * 100 // 限制文件大小为100MB
    },
    fileFilter: (req, file, cb) => {
        // 允许所有文件类型
        cb(null, true);
    }
});

// 活动连接存储
const activeConnections = new Map();

// 广播消息给所有连接的客户端
function broadcast(message, exclude = null) {
    wss.clients.forEach(client => {
        if (client !== exclude && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(message));
        }
    });
}

// 更新在线用户列表
function updateOnlineUsers() {
    const onlineUsers = Array.from(activeConnections.keys());
    broadcast({
        type: 'users',
        users: onlineUsers
    });
}

// 根路由
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// WebSocket连接处理
wss.on('connection', (ws) => {
    console.log('新的WebSocket连接');
    let username = null;

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            
            switch (data.type) {
                case 'auth':
                    username = data.username;
                    activeConnections.set(username, ws);
                    console.log(`用户 ${username} 已认证`);
                    
                    // 发送在线用户列表给所有用户
                    const onlineUsers = Array.from(activeConnections.keys());
                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN) {
                            client.send(JSON.stringify({
                                type: 'users',
                                users: onlineUsers
                            }));
                        }
                    });

                    // 加载历史消息
                    try {
                        let messages = [];
                        if (data.currentChat) {
                            if (data.currentChat.type === 'friend') {
                                messages = await new Promise((resolve, reject) => {
                                    db.all(`
                                        SELECT *, datetime(created_at, 'localtime') as created_at 
                                        FROM messages 
                                        WHERE ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?))
                                        AND group_id IS NULL
                                        ORDER BY created_at DESC LIMIT 100
                                    `, [username, data.currentChat.id, data.currentChat.id, username],
                                    (err, rows) => {
                                        if (err) reject(err);
                                        else resolve(rows || []);
                                    });
                                });
                            } else if (data.currentChat.type === 'group') {
                                messages = await new Promise((resolve, reject) => {
                                    db.all(`
                                        SELECT *, datetime(created_at, 'localtime') as created_at 
                                        FROM messages 
                                        WHERE group_id = ?
                                        ORDER BY created_at DESC LIMIT 100
                                    `, [data.currentChat.id],
                                    (err, rows) => {
                                        if (err) reject(err);
                                        else resolve(rows || []);
                                    });
                                });
                            }
                        } else {
                            messages = await new Promise((resolve, reject) => {
                                db.all(`
                                    SELECT *, datetime(created_at, 'localtime') as created_at 
                                    FROM messages 
                                    WHERE receiver IS NULL AND group_id IS NULL
                                    ORDER BY created_at DESC LIMIT 100
                                `,
                                (err, rows) => {
                                    if (err) reject(err);
                                    else resolve(rows || []);
                                });
                            });
                        }
                        
                        // 确保messages是数组并且有reverse方法
                        if (Array.isArray(messages)) {
                            ws.send(JSON.stringify({
                                type: 'history',
                                messages: messages.reverse()
                            }));
                        } else {
                            ws.send(JSON.stringify({
                                type: 'history',
                                messages: []
                            }));
                        }
                    } catch (error) {
                        console.error('加载历史消息错误:', error);
                        ws.send(JSON.stringify({
                            type: 'history',
                            messages: []
                        }));
                    }

                    // 发送好友列表
                    db.all(`
                        SELECT 
                            CASE 
                                WHEN user1 = ? THEN user2 
                                ELSE user1 
                            END as friend,
                            status
                        FROM friendships 
                        WHERE (user1 = ? OR user2 = ?)
                    `, [username, username, username], (err, rows) => {
                        if (err) {
                            console.error('获取好友列表错误:', err);
                            return;
                        }

                        ws.send(JSON.stringify({
                            type: 'friends',
                            friends: rows
                        }));
                    });

                    // 发送群组列表
                    db.all(`
                        SELECT g.* 
                        FROM chat_groups g
                        JOIN group_members gm ON g.id = gm.group_id
                        WHERE gm.username = ?
                    `, [username], (err, rows) => {
                        if (err) {
                            console.error('获取群组列表错误:', err);
                            return;
                        }

                        ws.send(JSON.stringify({
                            type: 'groups',
                            groups: rows
                        }));
                    });
                    break;

                case 'message':
                case 'file':
                    try {
                        // 保存消息到数据库
                        await new Promise((resolve, reject) => {
                            db.run(`
                                INSERT INTO messages (type, content, sender, receiver, group_id, created_at, filename, fileUrl, fileType, fileSize)
                                VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'), ?, ?, ?, ?)
                            `, [
                                data.type,
                                data.content,
                                data.sender,
                                data.receiver || null,
                                data.group_id || null,
                                data.filename || null,
                                data.fileUrl || null,
                                data.fileType || null,
                                data.fileSize || null
                            ], function(err) {
                                if (err) reject(err);
                                else resolve(this.lastID);
                            });
                        });

                        // 获取消息的创建时间
                        const result = await new Promise((resolve, reject) => {
                            db.get('SELECT datetime("now", "localtime") as created_at', (err, row) => {
                                if (err) reject(err);
                                else resolve(row);
                            });
                        });
                        data.created_at = result.created_at;

                        // 如果是群组消息
                        if (data.group_id) {
                            // 获取群组成员
                            const members = await new Promise((resolve, reject) => {
                                db.all(`
                                    SELECT username FROM group_members 
                                    WHERE group_id = ?
                                `, [data.group_id], (err, rows) => {
                                    if (err) reject(err);
                                    else resolve(rows || []);
                                });
                            });

                            // 向所有在线的群组成员发送消息
                            members.forEach(member => {
                                const memberWs = activeConnections.get(member.username);
                                if (memberWs && memberWs.readyState === WebSocket.OPEN) {
                                    memberWs.send(JSON.stringify(data));
                                }
                            });
                        } else if (data.receiver) {
                            // 私聊消息
                            const receiverWs = activeConnections.get(data.receiver);
                            if (receiverWs && receiverWs.readyState === WebSocket.OPEN) {
                                receiverWs.send(JSON.stringify(data));
                            }
                            // 发送给发送者自己，确保消息显示
                            const senderWs = activeConnections.get(data.sender);
                            if (senderWs && senderWs.readyState === WebSocket.OPEN) {
                                senderWs.send(JSON.stringify(data));
                            }
                        } else {
                            // 公共消息
                            wss.clients.forEach(client => {
                                if (client.readyState === WebSocket.OPEN) {
                                    client.send(JSON.stringify(data));
                                }
                            });
                        }
                    } catch (error) {
                        console.error('处理消息错误:', error);
                    }
                    break;

                case 'screen_share_offer' || 
                  data.type === 'screen_share_answer' || 
                  data.type === 'ice_candidate' ||
                  data.type === 'screen_share_stop':
                    // 处理屏幕共享相关的消息
                    if (data.group_id) {
                        // 群组屏幕共享，转发给所有群成员
                        db.all('SELECT username FROM group_members WHERE group_id = ?', 
                            [data.group_id], (err, members) => {
                                if (err) {
                                    console.error('获取群成员错误:', err);
                                    return;
                                }

                                members.forEach(member => {
                                    if (member.username !== username) { // 不发送给自己
                                        const memberWs = activeConnections.get(member.username);
                                        if (memberWs && memberWs.readyState === WebSocket.OPEN) {
                                            memberWs.send(JSON.stringify({
                                                ...data,
                                                sender: username
                                            }));
                                        }
                                    }
                                });
                            });
                    } else if (data.receiver) {
                        // 私聊屏幕共享，只转发给接收者
                        const receiverWs = activeConnections.get(data.receiver);
                        if (receiverWs && receiverWs.readyState === WebSocket.OPEN) {
                            receiverWs.send(JSON.stringify({
                                ...data,
                                sender: username
                            }));
                        }
                    }
                    break;
            }
        } catch (error) {
            console.error('处理WebSocket消息错误:', error);
        }
    });

    ws.on('close', () => {
        if (username) {
            console.log(`用户 ${username} 断开连接`);
            activeConnections.delete(username);
            // 通知其他用户更新在线用户列表
            const onlineUsers = Array.from(activeConnections.keys());
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify({
                        type: 'users',
                        users: onlineUsers
                    }));
                }
            });
        }
    });
});

// 注册路由
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // 检查用户名是否已存在
    db.get('SELECT username FROM users WHERE username = ?', [username], async (err, row) => {
        if (err) {
            console.error('数据库错误:', err);
            return res.status(500).json({ error: '服务器错误' });
        }

        if (row) {
            return res.status(400).json({ error: '用户名已存在' });
        }

        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
                if (err) {
                    console.error('注册错误:', err);
                    return res.status(500).json({ error: '服务器错误' });
                }
                res.status(201).json({ message: '注册成功' });
            });
        } catch (error) {
            console.error('密码加密错误:', error);
            res.status(500).json({ error: '服务器错误' });
        }
    });
});

// 登录路由
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            console.error('数据库错误:', err);
            return res.status(500).json({ error: '服务器错误' });
        }

        if (!user) {
            return res.status(401).json({ error: '用户名或密码错误' });
        }

        try {
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                res.json({ username });
            } else {
                res.status(401).json({ error: '用户名或密码错误' });
            }
        } catch (error) {
            console.error('密码验证错误:', error);
            res.status(500).json({ error: '服务器错误' });
        }
    });
});

// 文件上传路由
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: '没有文件上传' });
    }

    const fileUrl = `http://${req.headers.host}/uploads/${req.file.filename}`;
    res.json({ url: fileUrl });
});

// 发送好友请求
app.post('/friend-request', async (req, res) => {
    const { from, to } = req.body;

    // 检查是否已经是好友
    db.get('SELECT * FROM friendships WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)',
        [from, to, to, from], (err, row) => {
            if (err) {
                return res.status(500).json({ error: '服务器错误' });
            }

            if (row) {
                return res.status(400).json({ error: '已经是好友或请求待处理' });
            }

            // 创建好友请求
            db.run('INSERT INTO friendships (user1, user2) VALUES (?, ?)',
                [from, to], (err) => {
                    if (err) {
                        return res.status(500).json({ error: '服务器错误' });
                    }

                    // 通知被请求的用户
                    const toWs = activeConnections.get(to);
                    if (toWs) {
                        toWs.send(JSON.stringify({
                            type: 'friend_request',
                            from: from
                        }));
                    }

                    res.json({ message: '好友请求已发送' });
                });
        });
});

// 处理好友请求
app.post('/friend-request/respond', async (req, res) => {
    const { from, to, accept } = req.body;

    if (accept) {
        db.run('UPDATE friendships SET status = ? WHERE user1 = ? AND user2 = ?',
            ['accepted', from, to], (err) => {
                if (err) {
                    return res.status(500).json({ error: '服务器错误' });
                }

                // 通知双方
                const fromWs = activeConnections.get(from);
                const toWs = activeConnections.get(to);

                if (fromWs) {
                    fromWs.send(JSON.stringify({
                        type: 'friend_accepted',
                        friend: to
                    }));
                }

                if (toWs) {
                    toWs.send(JSON.stringify({
                        type: 'friend_accepted',
                        friend: from
                    }));
                }

                res.json({ message: '已接受好友请求' });
            });
    } else {
        db.run('DELETE FROM friendships WHERE user1 = ? AND user2 = ?',
            [from, to], (err) => {
                if (err) {
                    return res.status(500).json({ error: '服务器错误' });
                }
                res.json({ message: '已拒绝好友请求' });
            });
    }
});

// 获取好友列表
app.get('/friends/:username', (req, res) => {
    const { username } = req.params;

    db.all(`
        SELECT 
            CASE 
                WHEN user1 = ? THEN user2 
                ELSE user1 
            END as friend,
            status,
            created_at
        FROM friendships 
        WHERE (user1 = ? OR user2 = ?) 
        AND status = 'accepted'
    `, [username, username, username], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: '服务器错误' });
        }
        res.json(rows);
    });
});

// 创建群组
app.post('/groups', async (req, res) => {
    const { name, creator, members } = req.body;

    db.run('INSERT INTO chat_groups (name, creator) VALUES (?, ?)',
        [name, creator], function(err) {
            if (err) {
                return res.status(500).json({ error: '服务器错误' });
            }

            const groupId = this.lastID;

            // 添加创建者为成员
            const values = [[groupId, creator], ...members.map(m => [groupId, m])];
            const stmt = db.prepare('INSERT INTO group_members (group_id, username) VALUES (?, ?)');
            
            values.forEach(([gid, username]) => {
                stmt.run(gid, username, (err) => {
                    if (err) {
                        console.error('添加群组成员错误:', err);
                    }
                });
            });
            stmt.finalize();

            // 通知所有成员
            members.forEach(member => {
                const ws = activeConnections.get(member);
                if (ws) {
                    ws.send(JSON.stringify({
                        type: 'group_created',
                        group_id: groupId,
                        group_name: name,
                        creator: creator
                    }));
                }
            });

            res.json({
                id: groupId,
                name: name,
                creator: creator
            });
        });
});

// 获取用户的群组列表
app.get('/groups/:username', (req, res) => {
    const { username } = req.params;

    db.all(`
        SELECT 
            g.*,
            COUNT(gm.username) as member_count
        FROM chat_groups g
        JOIN group_members gm ON g.id = gm.group_id
        WHERE g.id IN (
            SELECT group_id 
            FROM group_members 
            WHERE username = ?
        )
        GROUP BY g.id
    `, [username], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: '服务器错误' });
        }
        res.json(rows);
    });
});

// 获取所有已注册用户
app.get('/users', (req, res) => {
    db.all('SELECT username FROM users', [], (err, rows) => {
        if (err) {
            console.error('获取用户列表错误:', err);
            return res.status(500).json({ error: '服务器错误' });
        }
        res.json(rows);
    });
});

// 获取所有用户（管理员专用）
app.get('/admin/users', async (req, res) => {
    const { username } = req.query;
    
    // 验证是否是管理员
    db.get('SELECT is_admin FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row || !row.is_admin) {
            return res.status(403).json({ error: '无权限访问' });
        }

        // 获取所有用户信息
        db.all('SELECT username, is_admin, display_name, icon FROM users', [], (err, rows) => {
            if (err) {
                return res.status(500).json({ error: '服务器错误' });
            }
            res.json(rows);
        });
    });
});

// 删除用户（管理员专用）
app.delete('/admin/users/:targetUser', async (req, res) => {
    const { username } = req.query;
    const { targetUser } = req.params;
    
    // 验证是否是管理员
    db.get('SELECT is_admin FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row || !row.is_admin) {
            return res.status(403).json({ error: '无权限访问' });
        }

        // 不能删除管理员账号
        if (targetUser === ADMIN_CONFIG.username) {
            return res.status(400).json({ error: '不能删除管理员账号' });
        }

        // 删除用户
        db.run('DELETE FROM users WHERE username = ?', [targetUser], (err) => {
            if (err) {
                return res.status(500).json({ error: '服务器错误' });
            }
            res.json({ message: '用户删除成功' });
        });
    });
});

// 更新系统名称和图标（管理员专用）
app.post('/admin/system-info', async (req, res) => {
    const { username, icon, name } = req.body;
    
    // 验证是否是管理员
    db.get('SELECT is_admin FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row || !row.is_admin) {
            return res.status(403).json({ error: '无权限访问' });
        }

        // 将系统信息保存到数据库或配置文件中
        const systemInfo = { icon, name };
        fs.writeFile('system_info.json', JSON.stringify(systemInfo), (err) => {
            if (err) {
                return res.status(500).json({ error: '保存系统信息失败' });
            }
            res.json({ message: '系统信息更新成功' });
        });
    });
});

// 获取系统信息
app.get('/system-info', (req, res) => {
    fs.readFile('system_info.json', 'utf8', (err, data) => {
        if (err) {
            // 如果文件不存在，返回默认值
            return res.json({ icon: 'B', name: '山东众智大数据' });
        }
        try {
            const systemInfo = JSON.parse(data);
            res.json(systemInfo);
        } catch (error) {
            res.json({ icon: 'B', name: '山东众智大数据' });
        }
    });
});

// 优雅关闭
process.on('SIGINT', () => {
    db.close(() => {
        console.log('数据库连接已关闭');
        process.exit(0);
    });
});

// 启动服务器
const PORT = 6655;
server.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
}); 