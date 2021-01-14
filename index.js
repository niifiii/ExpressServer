//Imports
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
const passport = require('passport'); //Core
const LocalStrategy = require('passport-local').Strategy //Strtegy
const fsPromises = require('fs/promises')
const NewsAPI = require('newsapi');
const AWS = require('aws-sdk');//
//const multerS3 = require('multer-s3');
const md5 = require('md5');

const fetch = require('node-fetch')
const withQuery = require('with-query').default

const EMAIL_ADDRESS = process.env.EMAIL_ADDRESS || global.env.EMAIL_ADDRESS
const EMAIL_PASS = process.env.EMAIL_PASSWORD || global.env.EMAIL_PASSWORD

///////////
const nodemailer = require('nodemailer');

//const transporter = nodemailer.createTransport({
//  service: 'gmail',
//  auth: {
//    user: EMAIL_ADDRESS,
//    pass: EMAIL_PASS
//  }
//});
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: EMAIL_ADDRESS,
        pass: EMAIL_PASS,
    }
})



/*
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      type: 'OAuth2',
      user: global.env.GMAIL_CLIENT_USER, // nifi
      clientId: global.env.GMAIL_CLIENT_ID, // ''
      clientSecret: global.env.GMAIL_CLIENT_SECRET, // ''
      refreshToken: global.env.GMAIL_REFRESH_TOKEN, // ''
      accessToken: global.env.GMAIL_ACCESS_TOKEN, // ??
    },
  });
  */
///////////

const NEWS_API_KEY = process.env.NEWS_API_KEY || global.env.NEWS_API_KEY 

const newsapi = new NewsAPI(NEWS_API_KEY);

const app = express();
const APP_PORT = process.env.APP_PORT || global.env.APP_PORT 

const mkAuth = (passport) => {
    return (req, res, next) => { //cannot return pp(a)=>{}(a), so retun (a)=>{pp(a)=>{}(a)}
        passport.authenticate('local',
            (err, user, info) => {
                if ( (null != err) || (!user) )  { //ch for error is not null or no error
                    res.status(401)
                    res.type('application/json')
                    res.json({ error: err })
                    return
                }
                // attach user to the request object
                req.user = user; //have to attachit ourself due to custome middleware 
                next()
            }
        )(req, res, next)
    }
}

// configure passport with a strategy
passport.use(
    new LocalStrategy(
        { usernameField: 'userName', passwordField: 'password' },
        async (user, password, done) => {   //<--
            // perform the authentication
            //console.info(`|LocalStrategy> userName: ${user}, password: ${password}`)
            
            const findUsernamePassword = async (user) => {
                const find = mongoClient.db(MONGO_DATABASE).collection(MONGO_USERINFO_COLLECTION).find({ "userName": user})

                const findResults = []

                await find.forEach(
                    function(myDoc) { findResults.unshift(myDoc)}
                )

                console.log(findResults)

                return findResults
            }

            //Perform the authentication: query from db
            try {
                const result = await findUsernamePassword(user)

                console.log(result)

                if (result.length > 0)
                    done(null, {
                        userName: result[0].userName,
                        email: result[0].email,
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

app.use(cors());
app.use(morgan('combined'));
app.use(express.urlencoded({ limit:'10mb', extended: true }));
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
const MONGO_DATABASE = process.env.MONGO_DATABASE || global.env.MONGO_DATABASE 
const MONGO_TWITS_COLLECTION = process.env.MONGO_TWITS_COLLECTION || global.env.MONGO_TWITS_COLLECTION
const MONGO_USERINFO_COLLECTION = process.env.MONGO_USERINFO_COLLECTION || global.env.MONGO_USERINFO_COLLECTION
const MONGO_URL = process.env.MONGO_URL || global.env.MONGO_URL //Set MongoDb URL

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
        const auth = req.get('Authorization');
        if (null == auth) {
            res.status(401)
            res.json({message: 'Missing Authorization Header'})
            return
        }
        //Bearere Authoprization
        //Bearer <token>
        const terms = auth.split(' ');
        if (terms.length != 2 || (terms[0] != 'Bearer')) {
            res.status(403)
            res.json( { message: 'Incorrect Authorization'})
            return
        }

        const token = terms[1]
        try {
            const verified = jwt.verify(token, TOKEN_SECRET)
            console.info('Verified token: ', verified)
            req.token = verified; //add token to req for next()
            next()
        } catch(e) {
            res.status(403)
            res.json( { message: 'Incorrect token', error: e})
            return
        }
    },
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
        console.log(">>>>>",req.body.userName, req.token.sub) 
        if (isValidTwit(req.body) && req.body.userName.toString().trim() === req.token.sub) { 

            console.log(req.body)
            //insert into db
            const twit = {
                name: req.body.userName.trim().toString(),
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

app.get('/api/twits/:userName', async (req, res) => { // /:userName?page=1 notyet

    const userName = req.params.userName

    console.log('[/api/twits/:userName]: userName: ', userName)

    const find = mongoClient.db(MONGO_DATABASE).collection(MONGO_TWITS_COLLECTION).find({ "userName": userName})
    
    const findResults = []
    
    await find.forEach(
        function(myDoc) { findResults.unshift(myDoc)}
    )

    console.log('[/api/twits/:userName] findResults: ', findResults)

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
    console.log('isValidRD: ', validity)
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

//implement if have time
const mailRegistered = ( userName, userEmail) => { 
    return {
        from: `Twitta <${EMAIL_ADDRESS}>`,
        to: userEmail,
        subject: `Hello ${userName}, this is Twitta! Your registration is successful!`,
        text: `Hello ${userName}, Thank you for joining us!`
    }
};

app.post('/api/register', async ( req, res) => {
    console.log('a', req.body)
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

        console.log('b', req.body)

        //test if user exists
        const user = req.body.userName.trim().toString();
        const userRecord = mongoClient.db(MONGO_DATABASE).collection(MONGO_TWITS_COLLECTION).find({"userName" : user})
        const userRecordList = []
        await userRecord.forEach(
                function(myDoc) { userRecordList.unshift(myDoc)}
        )
        if (userRecordList.length > 0) {
            res.status(422)
            res.json(
                {message: 'User exists'}
            )
        }

        //insert into db
        const registrationDetails = {
            userName: req.body.userName.trim().toString(),
            password: req.body.password.trim().toString(),
            email: req.body.email.trim().toString(),
            joined: new Date()
        }
        //mongoClient.db(MONGO_DATABASE).collection(MONGO_TWITS_COLLECTION).updateOne({userName: twit.name}, { $set: {"userName" : twit.name, "comment" : twit.content, "created" : twit.created } }, {upsert:true})
        await mongoClient.db(MONGO_DATABASE).collection(MONGO_USERINFO_COLLECTION).insertOne(
            {"userName" : registrationDetails.userName, "password" : registrationDetails.password, "email" : registrationDetails.email, "joined" : registrationDetails.joined} 
        )

        console.log('email', registrationDetails.email)

        const find = await mongoClient.db(MONGO_DATABASE).collection(MONGO_USERINFO_COLLECTION).find({"userName" : registrationDetails.userName})

        const findResults = [] //forcstruct

        await find.forEach(
            function(myDoc) { findResults.unshift(myDoc) }
        )

        console.log('find results: ', findResults)

        if (findResults.length > 0) {
            
            transporter.sendMail(mailRegistered(registrationDetails.userName, registrationDetails.email), function(error, info){
                if (error) {
                    console.log(error);
                } else {
                    console.log('Email sent: ' + info.response);
                    res.status(200).json({ message: `Email sent: ${info.response}`})
                }
            });
            
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

//Passport Routes
const TOKEN_SECRET = process.env.TOKEN_SECRET || global.env.TOKEN_SECRET 

app.post('/api/authenticate', 
  // passport middleware to perform login
    // passport.authenticate('local', { session: false }),
    // authenticate with custom error handling
    localStrategyAuth,
    (req, res) => {
        // do something 
        console.info(`userName: `, req.user.userName)
        console.info(`userName: `, JSON.stringify(req.user))
        // generate JWT token
        const currTimestamp = (new Date()).getTime() / 1000 //get in secs
        const token = jwt.sign({ //whole object is the paylod part of jwt
            sub: req.user.userName,
            iss: 'Twitta',
            iat: currTimestamp, //<- in secs            
            exp: currTimestamp + (60*60), //valid for 1 hr
            //nbf: currTimestamp + 30,
            /*exp: currTimestamp + (45),*/ //effective after 30 secs, then can use for 15 seco
            data: {
                userName: req.user.userName,
                email: req.user.email,
                loginTime: req.user.loginTime
            }
        }, TOKEN_SECRET)

        res.status(200)
        res.type('application/json')
        res.json({ message: `Login in at ${new Date()}`, token})
    }
)

//for ref only unused
/*
app.get('/api/admin', //the secret
    (req, res, next) => {
            const auth = req.get('Authorization');
            if (null == auth) {
                res.status(401)
                res.json({message: 'Missing Authorization Header'})
                return
            }
            //Bearere Authoprization
            //Bearer <token>
            const terms = auth.split(' ');
            if (terms.length != 2 || (terms[0] != 'Bearer')) {
                res.status(403)
                res.json( { message: 'Incorrect Authorization'})
                return
            }

            const token = terms[1]
            try {
                const verified = jwt.verify(token, TOKEN_SECRET)
                console.info('Verified token: ', verified)
                req.token = verified; //add token to req for next()
                next()
            } catch(e) {
                res.status(403)
                res.json( { message: 'Incorrect token', error: e})
                return
            }
    },
    (req, res) => {
        
        res.status(200);
        res.json({ message: 'ok'})
    }
)

*/

const mailResetPassword = (userEmail, newPassword) => { 
    return {
        from: EMAIL_ADDRESS,
        to: userEmail,
        subject: 'This is Twitta! You have resetted your password',
        text: `Your new password is ${newPassword}`
    }
};

/* no need
app.post('/api/send-reset-password-email', (req, res) => {

    const date = new Date();
    const time = date.getMilliseconds();
    const newPassword = md5(time);

    console.log(newPassword)
    
    transporter.sendMail(mailResetPassword(req.body.userEmail, newPassword), function(error, info){
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
})

*/

app.post('/api/reset-password', 

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
    }

    ,
    (req, res) => {

    const emailAddress = req.body.emailAddress
    ///////////////////////////////////////////////////////////////////////////// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    const checkEmailExistsCursor = mongoClient.db(MONGO_DATABASE).collection(MONGO_USERINFO_COLLECTION).find({ 'email': emailAddress} )

    emailExistsCursorList = []

    checkEmailExistsCursor.forEach(
        function(myDoc) { emailExistsCursorList.unshift(myDoc)}
    )

    if (checkEmailExistsCursor.length < 0) {
        res.status(422)
            .json({ message: 'Email does not exist!'})
        return
    }

    const date = new Date();
    const time = date.getMilliseconds();
    const newPassword = md5(time);

    console.log(newPassword)

    const emailCursor = mongoClient.db(MONGO_DATABASE).collection(MONGO_USERINFO_COLLECTION).updateOne({ 'email': emailAddress }, { $set: { 'password': newPassword } },
    { upsert: true } )
     //{ 'password': newPassword }
    //console.log(req.body.userEmail, newPassword)
    transporter.sendMail(mailResetPassword(req.body.emailAddress, newPassword), function(error, info){
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
            res.status(200).json({ message: `Email sent: ${info.response}`})
        }
    });
    
})

 app.get('/api/news', async (req, res) => {    
    //const length =
        
    const country = 'sg'
    let pageSize = null

    if (req.query.numberOfArticles) {
        pageSize = req.query.numberOfArticles;
    } else {
        pageSize = 5;
    }

    var results = await newsapi.v2.topHeadlines({
        pageSize,
        country
    }).then(response => {
        //console.log(response); 
        return response;
    })

    //console.log('results: ', results.articles[0])

    const articles = results.articles
    console.log(articles)
    console.log('pageSize: ', pageSize)
    //const resultObj = results.json()
    //console.log(resultObj)
    //const articles = resultObj.articles

    res.status(200)
        .json(articles)
})


app.get("/api/twits-count/:userName", async (req, res) => { // /numUsers
    
    const userName = req.params.userName

    console.log(userName)

    const usersCursor = mongoClient.db(MONGO_DATABASE).collection(MONGO_TWITS_COLLECTION).aggregate([
        { //works on the desktop dun work here!
            $match: { userName: userName }
        },
        {
            $group: {
                _id: "$userName",
                totalTwits: { $sum: {$toInt: 1} },
            }
        }
//        ,
//        {
//          $sort: { _id: -1 }
//        }
    ])

    const usersRecordsList = []

    await usersCursor.forEach(
            function(myDoc) { usersRecordsList.unshift(myDoc)}
    )

    console.log("hello", usersRecordsList)

    if (usersRecordsList.length < 0) {
        res.status(422)
        res.json(
            {message: 'No user exists'}
        )
    }

    res.status(200).json(usersRecordsList)
})

app.get("/api/browse-users", async (req, res) => { // /numUsers
    
    const usersCursor = mongoClient.db(MONGO_DATABASE).collection(MONGO_USERINFO_COLLECTION).find({})

    const usersRecordsList = []

    await usersCursor.forEach(
            function(myDoc) { usersRecordsList.unshift(myDoc.userName)}
    )

    console.log("hello", usersRecordsList)

    if (usersRecordsList.length < 0) {
        res.status(422)
        res.json(
            {message: 'No user exists'}
        )
    }

    res.status(200).json(usersRecordsList)
})
//FS
//Set destination directory for multer (multiple part file) upload
//const upload = multer({
//	dest: global.env.TMP_DIR || '/opt/tmp/uploads'
//})

//S3-Compatible DB Store/////////////////////////////////////////////////////////////////////

const AWS_S3_HOSTNAME =  process.env.AWS_S3_HOSTNAME || global.env.AWS_S3_HOSTNAME //digitalocean is aws compatible s3 store
const AWS_S3_ACCESSKEY_ID = process.env.AWS_S3_ACCESSKEY_ID || global.env.AWS_S3_ACCESSKEY_ID
const AWS_S3_SECRET_ACCESSKEY = process.env.AWS_S3_SECRET_ACCESSKEY || global.env.AWS_S3_SECRET_ACCESSKEY 
const AWS_S3_BUCKET_NAME = process.env.AWS_S3_BUCKET_NAME || global.env.AWS_S3_BUCKET_NAME 

///////////////////////////////////////////// UPLOAD TO S3
const MONGO_PROFILEPIC_COLLECTION = 'ProfilePic'
/*
ops: [
    {
      ts: 2021-01-12T06:40:17.745Z,
      user: undefined,
      temperature: NaN,
      image: '7a47428fdd6b5b69b04b3c8ed1fa67d6',
      _id: 5ffd4452cb4c5643384b500c
    }
  ],
  insertedCount: 1,
  insertedId: 5ffd4452cb4c5643384b500c
}
*/

//unused
const mkUserProfilePicEntry = (params, imageName) => {
	return {
		timeStamp: new Date(),
		user: params.userName,
		imageName
	}
}

const readFile = (path) => new Promise(
	(resolve, reject) => 
		fs.readFile(path, (err, buff) => {
			if (null != err)
				reject(err)
			else 
				resolve(buff)
		})
)

const putObject = (file, buff, s3) => new Promise(
	(resolve, reject) => {
		const params = {
			Bucket: AWS_S3_BUCKET_NAME,
			Key: file.filename, 
			Body: buff,
			ACL: 'public-read',
			ContentType: file.mimetype,
			ContentLength: file.size
		}
		s3.putObject(params, (err, result) => {
			if (null != err)
				reject(err)
			else
				resolve(result)
		})
	}
)

const s3 = new AWS.S3({
	endpoint: new AWS.Endpoint(AWS_S3_HOSTNAME),
	accessKeyId: AWS_S3_ACCESSKEY_ID,
	secretAccessKey: AWS_S3_SECRET_ACCESSKEY
})

const upload = multer({
	dest: process.env.UPLOADFILE_TMP_DIR || global.env.UPLOADFILE_TMP_DIR || '/opt/tmp/uploads'
})

app.post('/api/upload', upload.single('avatar'), (req, resp) => {

    if (req.file == 'undefined') {
        res.status(422).json({message: 'No file attached to request.'})
    }
	console.info('>>> req.body: ', req.body)
	console.info('>>> req.file: ', req.file)

	resp.on('finish', () => {
		// delete the temp file
		fs.unlink(req.file.path, () => { })
	})

	//const doc = mkUserProfilePicEntry(req.body, req.file.filename)

	readFile(req.file.path)
		.then(buff => 
			putObject(req.file, buff, s3)
		)
        .then((results) => {
            /* pic exists
            const user = req.body.userName.trim().toString();
            const userRecord = mongoClient.db(MONGO_DATABASE).collection(MONGO_PROFILEPIC_COLLECTION).find({"user" : user})
            const userRecordList = []
            await userRecord.forEach(
                    function(myDoc) { userRecordList.unshift(myDoc)}
            )
            if (userRecordList.length > 0) {
                res.status(422)
                res.json(
                    {message: 'User exists'}
                )
            }
            //insert into db 
            //mongoClient.db(MONGO_DATABASE).collection(MONGO_COLLECTION).replaceOne({"userName": req.body.userName}, doc)
            
			mongoClient.db(MONGO_DATABASE).collection(MONGO_COLLECTION)
                .insertOne(doc)
                
            */
           console.log('putObject returns: ', results)

           return mongoClient.db(MONGO_DATABASE).collection(MONGO_PROFILEPIC_COLLECTION).updateOne(
                {"name": req.body.userName},
                { $set: {timeStamp: new Date(), imageName: req.file.filename}},
                {upsert: true}
            )
                     
        })
		.then(results => {
			console.info('insert results: ', results)
			resp.status(200)
			resp.json({ imageName: req.file.filename })
		})
		.catch(error => {
			console.error('insert error: ', error)
			resp.status(500)
			resp.json({ error })
		})
})

app.post('/api/profile-pic', 

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
    }
    ,
    async (req, res) => {
        console.log(req.body.userName)
        let profilePicCursor = mongoClient.db(MONGO_DATABASE).collection(MONGO_PROFILEPIC_COLLECTION).find({'name' : `${req.body.userName}` })
        const profilePicList = []

        await profilePicCursor.forEach(
                function(myDoc) { profilePicList.unshift(myDoc)}
        )

        console.log(MONGO_DATABASE, MONGO_PROFILEPIC_COLLECTION, req.body.userName, profilePicList.length === 0)

        if (profilePicList.length === 0) {
            console.log('here'); res.status(404); res.json({ message: 'No user profile pic exists' });
        } else {

            console.log(profilePicList.length)

            profilePicListObject = profilePicList[0] //this is an obj

            console.log(profilePicListObject.imageName)

            res.status(200).json({ imageName: profilePicListObject.imageName })
        }
    }
)

/* Run Server*/

const mongoConnection = (async () => { return mongoClient.connect()})(); //connect    

const s3Connection = new Promise( //test s3 connection
    (resolve, reject) => {
        if ((!!global.env.AWS_S3_ACCESSKEY_ID || !!process.env.AWS_S3_ACCESSKEY_ID) && (!!global.env.AWS_S3_SECRET_ACCESSKEY || !!process.env.AWS_S3_SECRET_ACCESSKEY)) {
            console.log('s3 keys found!')
            resolve()
        } else {
            reject('S3 keys not found')
        }
    }
)
//
Promise.all([s3Connection, mongoConnection])
	.then(() => {
		app.listen(APP_PORT, () => {
            console.info(`Application started on port ${APP_PORT} at ${new Date()}`)
            //console.log(EMAIL_ADDRESS, EMAIL_PASS)
		})
	})
	.catch(err => { console.error('Cannot connect: ', err) })

//app.listen(APP_PORT, () => {
//    console.log('Listening on http://localhost:3000');
//})