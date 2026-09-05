const express=require("express"),http=require("http"),path=require("path"),crypto=require("crypto"),fs=require("fs");
const session=require("express-session"),SQLiteStore=require("connect-sqlite3")(session),bcrypt=require("bcryptjs");
const rateLimit=require("express-rate-limit"),helmet=require("helmet"),multer=require("multer"),{Server}=require("socket.io");
const sqlite3=require("sqlite3").verbose();

const app=express(),server=http.createServer(app),io=new Server(server);
//const PORT=process.env.PORT||3000;
const PORT=process.env.PORT||8080;
const dbPath=process.env.DB_PATH||path.join(__dirname,"data.sqlite");
const db=new sqlite3.Database(dbPath);
const ADMIN_USER=process.env.ADMIN_USER||"admin";
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||"CHANGE_ME_NOW";
const SESSION_SECRET=process.env.SESSION_SECRET||crypto.randomBytes(32).toString("hex");
const INVITE_CODE=process.env.INVITE_CODE||"CHANGE_ME_NOW";
const socketTokens=new Map();

function q(sql,p=[]){return new Promise((res,rej)=>db.all(sql,p,(e,r)=>e?rej(e):res(r)))} 
function one(sql,p=[]){return new Promise((res,rej)=>db.get(sql,p,(e,r)=>e?rej(e):res(r))}
function run(sql,p=[]){return new Promise((res,rej)=>db.run(sql,p,function(e){e?rej(e):res(this)}))}
(async()=>{
 await run(`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,display_name TEXT,disabled INTEGER DEFAULT 0,created_at INTEGER)`);
 await run(`CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,from_user TEXT,to_user TEXT,text TEXT,created_at INTEGER)`);
 await run(`CREATE TABLE IF NOT EXISTS locations(id INTEGER PRIMARY KEY AUTOINCREMENT,user TEXT,lat REAL,lng REAL,created_at INTEGER)`);
 await run(`CREATE TABLE IF NOT EXISTS uploads(id TEXT PRIMARY KEY,user TEXT,filename TEXT,stored TEXT,created_at INTEGER)`);
 const count=await one("SELECT COUNT(*) n FROM users");
 if(count.n===0 && ADMIN_PASSWORD!=="CHANGE_ME_NOW") console.log("Admin credentials are set by environment variables.");
})();

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));
app.use(session({store:new SQLiteStore({db:"sessions.sqlite",dir:__dirname}),secret:SESSION_SECRET,resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax",secure:"auto",maxAge:1000*60*60*24*7}}));
app.use(rateLimit({windowMs:15*60*1000,max:300}));
const uploadDir=path.join(__dirname,"uploads");fs.mkdirSync(uploadDir,{recursive:true});
const upload=multer({dest:uploadDir,limits:{fileSize:25*1024*1024}});
app.use(express.static(path.join(__dirname,"public")));

async function current(req){if(req.session.user)return req.session.user;return null}
function auth(req,res,next){if(!req.session.user)return res.status(401).json({error:"Login required"});next()}
function admin(req,res,next){if(req.session.user?.role!=="admin")return res.status(403).json({error:"Admin only"});next()}

app.get("/api/health",(req,res)=>res.json({ok:true}));
app.post("/api/login",async(req,res)=>{
 const {username,password}=req.body||{};
 if(username===ADMIN_USER && ADMIN_PASSWORD!=="CHANGE_ME_NOW" && await bcrypt.compare(password||"",await bcrypt.hash(ADMIN_PASSWORD,10)).catch(()=>false)){
   req.session.user={username:ADMIN_USER,role:"admin"}; return res.json({ok:true,user:req.session.user});
 }
 const u=await one("SELECT * FROM users WHERE username=?",[String(username||"")]);
 if(!u||u.disabled||!(await bcrypt.compare(password||"",u.password_hash)))return res.status(401).json({error:"Invalid login"});
 req.session.user={username:u.username,role:"user",id:u.id,displayName:u.display_name};res.json({ok:true,user:req.session.user});
});
app.get("/api/socket-token",auth,(req,res)=>{const t=crypto.randomBytes(24).toString("hex");socketTokens.set(t,{user:req.session.user,expires:Date.now()+60000});res.json({token:t})});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/users",auth,async(req,res)=>{
 let rows=await q("SELECT id,username,display_name displayName,disabled FROM users ORDER BY username");
 if(req.session.user.role!=="admin") rows=rows.filter(x=>x.username!==req.session.user.username&&!x.disabled);
 res.json(rows);
});
app.post("/api/users",auth,admin,async(req,res)=>{
 const {username,password,displayName}=req.body||{};
 if(!username||!password)return res.status(400).json({error:"Username and password required"});
 try{let id=crypto.randomUUID();await run("INSERT INTO users VALUES(?,?,?,?,?,?)",[id,username,await bcrypt.hash(password,12),displayName||username,0,Date.now()]);res.json({ok:true})}
 catch(e){res.status(409).json({error:"Username already exists"})}
});
app.patch("/api/users/:username",auth,admin,async(req,res)=>{await run("UPDATE users SET disabled=? WHERE username=?",[req.body.disabled?1:0,req.params.username]);res.json({ok:true})});
app.post("/api/invite/register",async(req,res)=>{
 const {inviteCode,username,password,displayName}=req.body||{};
 if(inviteCode!==INVITE_CODE)return res.status(403).json({error:"Invalid invite"});
 try{await run("INSERT INTO users VALUES(?,?,?,?,?,?)",[crypto.randomUUID(),username,await bcrypt.hash(password,12),displayName||username,0,Date.now()]);res.json({ok:true})}
 catch(e){res.status(409).json({error:"Username already exists"})}
});

app.get("/api/messages/:peer",auth,async(req,res)=>{
 const me=req.session.user.username,peer=req.params.peer;
 res.json(await q("SELECT id,from_user fromUser,to_user toUser,text,created_at createdAt FROM messages WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?) ORDER BY created_at DESC LIMIT 200",[me,peer,peer,me]).then(a=>a.reverse()));
});
app.post("/api/upload",auth,upload.single("file"),async(req,res)=>{
 if(!req.file)return res.status(400).json({error:"No file"});
 const id=crypto.randomUUID(),ext=path.extname(req.file.originalname).slice(0,12),stored=id+ext;
 fs.renameSync(req.file.path,path.join(uploadDir,stored));
 await run("INSERT INTO uploads VALUES(?,?,?,?,?)",[id,req.session.user.username,req.file.originalname,stored,Date.now()]);
 res.json({id,url:"/files/"+stored,filename:req.file.originalname});
});
app.get("/files/:name",auth,(req,res)=>res.sendFile(path.join(uploadDir,path.basename(req.params.name))));

const sockets=new Map();
io.use((s,next)=>{
 const t=s.handshake.auth?.token, v=socketTokens.get(t);
 if(!v||v.expires<Date.now())return next(new Error("unauthorized"));
 s.data.user=v.user;socketTokens.delete(t);next();
});
io.on("connection",s=>{
 sockets.set(s.data.user.username,s.id);
 s.on("chat:send",async m=>{
   if(!m?.to||!m?.text)return;
   const text=String(m.text).slice(0,10000),id=crypto.randomUUID(),ts=Date.now();
   await run("INSERT INTO messages VALUES(?,?,?,?,?)",[id,s.data.user.username,String(m.to),text,ts]);
   const msg={id,fromUser:s.data.user.username,toUser:String(m.to),text,createdAt:ts};
   const t=sockets.get(String(m.to));if(t)io.to(t).emit("chat:message",msg);s.emit("chat:message",msg);
 });
 s.on("call:signal",m=>{const t=sockets.get(String(m?.to||""));if(t)io.to(t).emit("call:signal",{from:s.data.user.username,data:m.data})});
 s.on("location:share",async m=>{if(!Number.isFinite(m?.lat)||!Number.isFinite(m?.lng))return;await run("INSERT INTO locations(user,lat,lng,created_at) VALUES(?,?,?,?)",[s.data.user.username,m.lat,m.lng,Date.now()]);const t=sockets.get(String(m?.to||""));if(t)io.to(t).emit("location:update",{from:s.data.user.username,lat:m.lat,lng:m.lng,ts:Date.now()})});
 s.on("disconnect",()=>{if(sockets.get(s.data.user.username)===s.id)sockets.delete(s.data.user.username)});
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.use((req,res,next)=>next());
server.on("request",(req,res)=>{});
//server.listen(PORT,"0.0.0.0",()=>console.log("Listening on "+PORT));
server.listen(PORT, '0.0.0.0', () => {console.log(`Server is running on port ${PORT}`);
});
