# LAN Chat - 局域网即时通讯系统

一个基于 WebSocket 的局域网即时通讯系统，支持私聊、群聊、文件传输等功能。

## 功能特点

- 🔐 用户认证
  - 用户注册与登录
  - 密码加密存储
  - 会话持久化

- 💬 即时通讯
  - 公共聊天室（大家庭）
  - 私聊功能
  - 群组聊天
  - 实时在线状态显示
  - 未读消息提醒

- 👥 好友系统
  - 发送/接受好友请求
  - 好友列表管理
  - 在线好友状态显示

- 👥 群组功能
  - 创建群组
  - 群组成员管理
  - 群组消息

- 📎 文件传输
  - 支持图片预览
  - 支持多种文件格式
  - 文件大小限制
  - 文件类型图标显示

- 😊 表情系统
  - 内置表情选择器
  - 支持常用表情

- 👨‍💼 管理功能
  - 管理员账户
  - 用户管理
  - 系统信息设置

## 技术栈

- 前端
  - HTML5
  - CSS3
  - JavaScript (原生)
  - WebSocket
  - Font Awesome 图标

- 后端
  - Node.js
  - WebSocket (ws)
  - SQLite3
  - Express

## 安装说明

1. 克隆仓库
```bash
git clone https://github.com/yourusername/lan-chat.git
cd lan-chat
```

2. 安装依赖
```bash
npm install
```

3. 启动服务器
```bash
node server.js
```

4. 访问应用
在浏览器中打开 `http://localhost:6655`

## 配置说明

### 服务器配置
- 默认端口：6655
- 数据库：SQLite3
- 文件上传限制：100MB

### 管理员账户
首次运行时会自动创建管理员账户：
- 用户名：admin
- 密码：admin123

## 使用说明

### 基本功能
1. 注册/登录账户
2. 在"大家庭"中参与公共聊天
3. 添加好友进行私聊
4. 创建或加入群组
5. 发送文件或表情

### 管理功能
1. 使用管理员账户登录
2. 管理用户账户
3. 设置系统名称和图标

## 开发说明

### 目录结构
```
lan-chat/
├── server.js          # 服务器入口文件
├── index.html         # 前端页面
├── users.db           # SQLite数据库
├── uploads/           # 文件上传目录
└── README.md          # 说明文档
```

### 数据库结构
- users: 用户表
- friends: 好友关系表
- groups: 群组表
- messages: 消息记录表

## 安全特性

- WebSocket 通信加密
- 密码加密存储
- 文件上传类型限制
- 用户认证和授权

## 注意事项

- 仅支持局域网内使用
- 建议使用现代浏览器
- 文件上传大小限制为 100MB
- 需要 Node.js 环境

## 贡献指南

1. Fork 本仓库
2. 创建特性分支
3. 提交更改
4. 发起 Pull Request

## 许可证

MIT License

## 联系方式

- 作者：[baobu]
- Email：[btr17352034242@gmail.com]
- GitHub：[[Your GitHub Profile](https://github.com/17352034242)]

## 更新日志

### v1.0.0 (2024-01)
- 初始版本发布
- 基本聊天功能
- 文件传输功能
- 好友系统
- 群组功能 
