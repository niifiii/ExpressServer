const secureEnv = require('secure-env');
global.env = secureEnv({secret:'mySecretPasswordisSecret'}); //npx secure-env .env -s mySecretPasswordisSecret
const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
//const { json } = require('express');
const mongo = require('mongodb')
const MongoClient = require('mongodb').MongoClient;
const fs = require('fs');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy
const app = express();
const APP_PORT = global.env.APP_PORT

app.use(cors());

app.use(morgan('combined'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ extended: true }));

// initialize passport after json and form-urlencoded
app.use(passport.initialize())

/* sample
var db = require('db')

db.connect({
  host: global.env.DB_HOST,
  username: global.env.DB_USER,
  password: global.env.DB_PASS
})
*/

//MongoDB
//MongoDb Database Settings
const MONGO_DATABASE = global.env.MONGO_DATABASE;
const MONGO_TWITS_COLLECTION = global.env.MONGO_TWITS_COLLECTION;
const MONGO_USERINFO_COLLECTION = global.env.MONGO_USERINFO_COLLECTION;
const MONGO_URL = global.env.MONGO_URL //Set MongoDb URL

//console.log(MONGO_DATABASE, MONGO_URL, APP_PORT, JSON.stringify(global.env))

//Get an instance of MongoClient
const mongoClient = new MongoClient(
    MONGO_URL, //Pass in the MONGO_URL here
    { useNewUrlParser: true, useUnifiedTopology: true }); //because deprecation
                                //^no explicit connects

//console.log(mongoClient)                                


app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*"); // update to match the domain you will make the request from
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
})

//Test
app.post('/', (req, res) => {
    res.json({
        message: 'Message!'
    })
})

function isValidTwit(twit) {
    //console.log(twit)
    let validity = twit.userName && (twit.userName.toString().trim() !== '') && twit.content && (twit.content.toString().trim() !== '');
    //console.log(twit.userName && (twit.userName.toString().trim() !== '') && twit.content && (twit.content.toString().trim() !== ''))
    return validity
}

app.post('/api/post-twit', 

    (req, res, next) => {
        //res.setHeader('Access-Control-Allow-Origin', 'http://localhost:4200');

        // Request methods you wish to allow
        //res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');

        // Request headers you wish to allow
        //res.setHeader('Access-Control-Allow-Headers', 'Accept, Content-Type, Referer, User-Agent');

        // Set to true if you need the website to include cookies in  requests
        //res.setHeader('Access-Control-Allow-Credentials', false);

        // Check if preflight request
        if (req.method === 'OPTIONS') {
            res.status(200);
            console.log('here is options')
            res.end();
        }
        else {
            // Pass to next layer of middleware
            next();
        }
    },

    async (req, res, next) => {
        //console.log(req.body)   
        if (isValidTwit(req.body)) { 

            console.log(req.body)
            //insert into db
            const twit = {
                name: req.body.userName.toString(),
                content: req.body.content.toString(),
                created: new Date()
            }
            //mongoClient.db(MONGO_DATABASE).collection(MONGO_TWITS_COLLECTION).updateOne({userName: twit.name}, { $set: {"userName" : twit.name, "comment" : twit.content, "created" : twit.created } }, {upsert:true})
            mongoClient.db(MONGO_DATABASE).collection(MONGO_TWITS_COLLECTION).insertOne({"userName" : twit.name, "comment" : twit.content, "created" : twit.created} )
            const find = mongoClient.db(MONGO_DATABASE).collection(MONGO_TWITS_COLLECTION).find({})

            const findResults = []

            await find.forEach(
                function(myDoc) { findResults.unshift(myDoc)}
            )

            res.json({
                message: 'ok', 
                results: findResults
            })

        } else {
            res.status(422)
                .json({
                    message: 'Name and Content are required!'
                })
        }
    }
)

app.get('/api/twits/:userName', async (req, res) => { // /:userName?page=1

    const userName = req.params.userName

    //console.log(userName)

    const find = mongoClient.db(MONGO_DATABASE).collection(MONGO_TWITS_COLLECTION).find({ "userName": userName})
    
    const findResults = []
    
    await find.forEach(
        function(myDoc) { findResults.unshift(myDoc)}
    )

    console.log(findResults)

    res.json({
        message: 'ok', 
        count: find.count(),
        results: findResults
    })

})

function isValidRegistrationDetails(registrationDetails) {
    //console.log(registrationDetails)
    let validity = registrationDetails.userName && (registrationDetails.userName.toString().trim() !== '') && 
        registrationDetails.password && (registrationDetails.password.toString().trim() !== '') &&
        registrationDetails.email && (registrationDetails.password.toString().trim() !== '');
    console.log(validity)
    return validity
}


async function isUserNameInDb(registrationDetails) {
    const find = mongoClient.db(MONGO_DATABASE).collection(MONGO_USERINFO_COLLECTION).find({"userName" : registrationDetails.userName})

    const findResults = [] //forcstruct
    await find.forEach(
        function(myDoc) { findResults.unshift(myDoc)}
    )
    console.log(findResults)

    if (findResults.length < 1) {
        return false
    }

    return true
}

app.post('/api/register', async ( req, res) => {
    console.log(req.body)
    const isUserNameInDbVar = await isUserNameInDb(req.body)
    console.log('isUserNameInDb', isUserNameInDbVar)
    
    if (isUserNameInDbVar) {
        console.log('in here')
        res.status(200)
            .json({
                message: 'UserName is registered. Please choose a different username.'
            }
        )
        return
    }

    if (isValidRegistrationDetails(req.body)) { 

        console.log(req.body)
        //insert into db
        const registrationDetails = {
            userName: req.body.userName.trim().toString(),
            password: req.body.password.trim().toString(),
            email: req.body.email.trim().toString(),
            joined: new Date()
        }
        //mongoClient.db(MONGO_DATABASE).collection(MONGO_TWITS_COLLECTION).updateOne({userName: twit.name}, { $set: {"userName" : twit.name, "comment" : twit.content, "created" : twit.created } }, {upsert:true})
        mongoClient.db(MONGO_DATABASE).collection(MONGO_USERINFO_COLLECTION).insertOne(
            {"userName" : registrationDetails.userName, "password" : registrationDetails.password, "email" : registrationDetails.email, "joined" : registrationDetails.joined} 
        )
        const find = mongoClient.db(MONGO_DATABASE).collection(MONGO_TWITS_COLLECTION).find({"userName" : registrationDetails.userName})

        const findResults = [] //forcstruct

        await find.forEach(
            function(myDoc) { findResults.unshift(myDoc) }
        )

        if (findResults.length > 0) {
            res.json({
                message: 'ok', 
                results: findResults
            })
        }

       

    } else {
        res.status(422)
            .json({
                message: 'userName, password and email are required!'
            })
    }
})


const mkAuth = (passport) => {
    return (req, resp, next) => {
        passport.authenticate('local',
            (err, user, info) => {
                if ((null != err) || (!user)) {
                    resp.status(401)
                    resp.type('application/json')
                    resp.json({ error: err })
                    return
                }
                // attach user to the request object
                req.user = user
                next()
            }
        )(req, resp, next)
    }
}

// configure passport with a strategy
passport.use(
    new LocalStrategy(
        { usernameField: 'userName', passwordField: 'passwordHash' },
        async (user, passwordHash, done) => {
            // perform the authentication
            console.info(`LocalStrategy >>> userName: ${user}, password: ${passwordHash}`)
            try { //check server for username and pw
                const result = mongoClient.db(MONGO_DATABASE).collection(MONGO_USERINFO_COLLECTION).find({ "userName": userName, "passwordHash": passwordHash}) 
                console.info('>>> result: ', result)
                if (result.length > 0)
                    done(null, {
                        username: result[0].userName,
                        avatar: result[0].userAvatar,//
                        loginTime: (new Date()).toString()
                    })
                else
                    done('Incorrect login', false)
            } catch(e) {
                done(e, false)
            } finally {
                //
            }
        }
    )
)

const localStrategyAuth = mkAuth(passport)

app.post('/api/authenticate', localStrategyAuth, (req, res) => {
    //login
    // do something 
    console.info(`user: `, req.user)
    // generate JWT token
    const timestamp = (new Date()).getTime() / 1000
    const token = jwt.sign({
        sub: req.user.username,
        iss: 'myapp',
        iat: timestamp,
        //nbf: timestamp + 30,
        exp: timestamp + (60 * 60),
        data: {
            avatar: req.user.avatar,
            loginTime: req.user.loginTime
        }
    }, TOKEN_SECRET)

    resp.status(200)
    resp.type('application/json')
    resp.json({ message: `Login in at ${new Date()}`, token })
})

//FS
//Set destination directory for multer (multiple part file) upload
const upload = multer({
	dest: process.env.TMP_DIR || '/opt/tmp/uploads'
})

//S3-Compatible DB Store


/* Run Server*/

const mongoConnection = (async () => { return mongoClient.connect()})(); //connect    

const s3Connection = new Promise( //test s3 connection
    (resolve, reject) => {
        if ((!!global.env.AWS_S3_ACCESSKEY_ID) && (!!global.env.AWS_S3_SECRET_ACCESSKEY))
            resolve()
        else
            reject('S3 keys not found')
    }
)
//
Promise.all([s3Connection, mongoConnection])
	.then(() => {
		app.listen(APP_PORT, () => {
			console.info(`Application started on port ${APP_PORT} at ${new Date()}`)
		})
	})
	.catch(err => { console.error('Cannot connect: ', err) })

//app.listen(APP_PORT, () => {
//    console.log('Listening on http://localhost:3000');
//})