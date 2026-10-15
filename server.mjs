import http from 'node:http';
import {readFile, writeFile, mkdir} from 'node:fs/promises';
import {randomBytes, pbkdf2Sync, timingSafeEqual} from 'node:crypto';
import {join} from 'node:path';

const PORT=5174, DATA_DIR=join(process.cwd(),'data'), STORE=join(DATA_DIR,'store.json');
const sessions=new Map();
const base={
  users:[
    // Existing demo seller identity. Credentials are intentionally not invented: Aarya sets a password on first registration.
    {id:'seller-aarya',name:'Aarya',email:'aarya@gss.school',role:'seller',shop:'Aarya’s Shop',passwordHash:null,demo:true,createdAt:'2026-10-07T00:00:00.000Z'}
  ], products:[], orders:[], reviews:[], messages:[], notifications:[]
};
async function load(){try{return JSON.parse(await readFile(STORE,'utf8'))}catch{await mkdir(DATA_DIR,{recursive:true});await save(base);return structuredClone(base)}}
async function save(data){await mkdir(DATA_DIR,{recursive:true});await writeFile(STORE,JSON.stringify(data,null,2))}
const hash=p=>{const salt=randomBytes(16).toString('hex');return `${salt}:${pbkdf2Sync(p,salt,210000,32,'sha256').toString('hex')}`};
const check=(p,stored)=>{if(!stored)return false;const [salt,expected]=stored.split(':');const actual=pbkdf2Sync(p,salt,210000,32,'sha256').toString('hex');return timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(expected,'hex'))};
const safeUser=({passwordHash,...u})=>u;
const json=(res,status,body)=>{res.writeHead(status,{'Content-Type':'application/json','Access-Control-Allow-Origin':'http://127.0.0.1:5173','Access-Control-Allow-Headers':'Content-Type, Authorization'});res.end(JSON.stringify(body))};
const body=req=>new Promise((resolve,reject)=>{let raw='';req.on('data',c=>raw+=c);req.on('end',()=>{try{resolve(raw?JSON.parse(raw):{})}catch{reject(new Error('Invalid request body'))}})});
const auth=async req=>{const token=(req.headers.authorization||'').replace('Bearer ','');const id=sessions.get(token);if(!id)return null;const data=await load();return data.users.find(u=>u.id===id)||null};
function validPassword(p){return typeof p==='string'&&p.length>=8&&/[A-Za-z]/.test(p)&&/\d/.test(p)}
const server=http.createServer(async(req,res)=>{try{
 if(req.method==='OPTIONS')return json(res,204,{});
 const url=new URL(req.url,`http://${req.headers.host}`), path=url.pathname;
 if(req.method==='POST'&&path==='/api/auth/register'){
  const {name,email,password}=await body(req);const normalized=String(email||'').trim().toLowerCase();
  if(!name?.trim()||!(/^\S+@gmail\.com$/.test(normalized)||normalized==='aarya@gss.school')||!validPassword(password))return json(res,400,{error:'Use your name, a valid Gmail address, and a password of at least 8 characters with a letter and number.'});
  const data=await load();let user=data.users.find(u=>u.email===normalized);
  if(user&&user.passwordHash)return json(res,409,{error:'An account with this email already exists. Please sign in instead.'});
  if(user&&!user.passwordHash){user={...user,name:name.trim(),passwordHash:hash(password),activatedAt:new Date().toISOString()};data.users=data.users.map(u=>u.id===user.id?user:u)}
  else {user={id:`user-${randomBytes(8).toString('hex')}`,name:name.trim(),email:normalized,role:'buyer',passwordHash:hash(password),demo:false,createdAt:new Date().toISOString()};data.users.push(user)}
  await save(data);const token=randomBytes(32).toString('hex');sessions.set(token,user.id);return json(res,201,{token,user:safeUser(user)});
 }
 if(req.method==='POST'&&path==='/api/auth/login'){
  const {email,password}=await body(req),data=await load(),user=data.users.find(u=>u.email===String(email||'').trim().toLowerCase());
  if(!user||!check(password,user.passwordHash))return json(res,401,{error:'Incorrect email or password.'});const token=randomBytes(32).toString('hex');sessions.set(token,user.id);return json(res,200,{token,user:safeUser(user)});
 }
 if(req.method==='POST'&&path==='/api/auth/logout'){sessions.delete((req.headers.authorization||'').replace('Bearer ',''));return json(res,204,{})}
 const user=await auth(req);if(!user)return json(res,401,{error:'Please sign in to continue.'});
 if(req.method==='GET'&&path==='/api/me'){const data=await load();return json(res,200,{user:safeUser(user),products:user.role==='admin'?data.products:data.products.filter(p=>p.ownerId===user.id||p.status==='Live'),orders:user.role==='admin'?data.orders:data.orders.filter(o=>o.buyerId===user.id||o.sellerId===user.id)})}
 if(req.method==='POST'&&path==='/api/products'){
  if(user.role!=='seller')return json(res,403,{error:'Only approved seller accounts can create product listings.'});const {name,price,description,category,quantity}=await body(req);
  if(!name?.trim()||!description?.trim()||!(Number(price)>0)||!(Number(quantity)>=0))return json(res,400,{error:'Add a name, short description, valid price and available quantity.'});
  const data=await load(),p={id:`product-${randomBytes(7).toString('hex')}`,ownerId:user.id,seller:user.shop||user.name,name:name.trim(),price:Number(price),description:description.trim(),cat:category||'Other',stock:Number(quantity),status:'Pending',isDemo:false,createdAt:new Date().toISOString()};data.products.push(p);await save(data);return json(res,201,{product:p});
 }
 const productMatch=path.match(/^\/api\/products\/([^/]+)$/);
 if(productMatch&&req.method==='DELETE'){const data=await load(),p=data.products.find(x=>x.id===productMatch[1]);if(!p)return json(res,404,{error:'Product not found.'});if(user.role!=='admin'&&p.ownerId!==user.id)return json(res,403,{error:'You can only remove your own listings.'});data.products=data.products.filter(x=>x.id!==p.id);await save(data);return json(res,204,{})}
 return json(res,404,{error:'Route not found.'});
 }catch(err){return json(res,500,{error:err.message||'Something went wrong.'})}
});
server.listen(PORT,'127.0.0.1',()=>console.log(`GSS API listening on http://127.0.0.1:${PORT}`));
