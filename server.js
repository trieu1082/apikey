const express = require("express")
const path = require("path")
const app = express()

app.use(express.json())

const OWNER_KEY = process.env.OWNER_KEY

let KEYS = {}
let RATE = {}
let LOGS = []
let WHITELIST = {}

function now(){ return Date.now() }

function genKey(len=10){
    const c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    let k=""
    for(let i=0;i<len;i++) k+=c[Math.floor(Math.random()*c.length)]
    return k
}

function genScriptKey(){ return genKey(5) }

function rl(ip,limit=10,window=5000){
    let r=RATE[ip]
    if(!r || now()>r.reset){
        RATE[ip]={count:1,reset:now()+window}
        return true
    }
    if(r.count>=limit) return false
    r.count++
    return true
}

function auth(req){
    return req.headers["x-owner-key"]===OWNER_KEY
}

function getExpire(type,h){
    if(type==="24h") return now()+86400000
    if(type==="3d") return now()+259200000
    if(type==="1m") return now()+2592000000
    if(type==="custom") return now()+h*3600000
    if(type==="lifetime") return 0
    return null
}

function stats(){
    let total=0,alive=0,expired=0
    let t=now()
    for(let k in KEYS){
        total++
        let d=KEYS[k]
        if(d.expire && t>d.expire) expired++
        else alive++
    }
    return {total,alive,expired}
}

app.get("/",(req,res)=>{
    res.sendFile(path.join(__dirname,"index.html"))
})

app.post("/create",(req,res)=>{
    if(!rl(req.ip)) return res.send("rate_limited")
    if(!auth(req)) return res.send("no")

    let {type,hours}=req.body
    let expire=getExpire(type,hours)
    if(expire===null) return res.send("bad_type")

    let key
    do{ key=genKey() }while(KEYS[key])

    KEYS[key]={expire,used:false,hwid:null,created:now()}

    LOGS.push({type:"create",key,time:now()})

    res.json({key})
})

app.post("/redeem",(req,res)=>{
    if(!rl(req.ip,20,5000)) return res.send("rate_limited")

    let {key,hwid}=req.body
    let d=KEYS[key]

    if(!d) return res.send("invalid")

    if(d.expire && now()>d.expire){
        delete KEYS[key]
        return res.send("expired")
    }

    if(d.used) return res.send("used")

    d.used=true
    d.hwid=hwid

    let sk=genScriptKey()

    KEYS[sk]={expire:d.expire,hwid,used:true,created:now()}

    delete KEYS[key]

    LOGS.push({type:"redeem",from:key,to:sk,hwid,time:now()})

    res.json({scriptKey:sk})
})

app.post("/verify",(req,res)=>{
    if(!rl(req.ip,30,5000)) return res.send("rate_limited")

    let {key,hwid}=req.body

    if(WHITELIST[hwid]) return res.send("ok")

    let d=KEYS[key]

    if(!d) return res.send("no")

    if(d.expire && now()>d.expire){
        delete KEYS[key]
        return res.send("expired")
    }

    if(d.hwid!==hwid) return res.send("hwid_mismatch")

    res.send("ok")
})

app.get("/keys",(req,res)=>{
    if(!auth(req)) return res.send("no")
    res.json(KEYS)
})

app.get("/logs",(req,res)=>{
    if(!auth(req)) return res.send("no")
    res.json(LOGS.slice(-100))
})

app.get("/stats",(req,res)=>{
    if(!auth(req)) return res.send("no")
    res.json(stats())
})

app.post("/delete",(req,res)=>{
    if(!auth(req)) return res.send("no")
    delete KEYS[req.body.key]
    res.send("ok")
})

app.post("/whitelist",(req,res)=>{
    if(!auth(req)) return res.send("no")
    WHITELIST[req.body.hwid]=true
    res.send("ok")
})

app.post("/unwhitelist",(req,res)=>{
    if(!auth(req)) return res.send("no")
    delete WHITELIST[req.body.hwid]
    res.send("ok")
})

app.listen(process.env.PORT || 3000)
