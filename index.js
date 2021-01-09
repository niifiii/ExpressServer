const secureEnv = require('secure-env');
global.env = secureEnv({secret:'mySecretPassword'});
const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const { json } = require('express');

const app = express();

app.use(cors());

app.use(morgan('combined'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ extended: true }));

/* sample
var db = require('db')

db.connect({
  host: global.env.DB_HOST,
  username: global.env.DB_USER,
  password: global.env.DB_PASS
})
*/

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
            console.log('here')
            res.end();
        }
        else {
            // Pass to next layer of middleware
            next();
        }
    },

    (req, res, next) => {
        //console.log(req.body)
        if (isValidTwit(req.body)) { 
            console.log(req.body)
            res.json({
                message: 'ok'
            })
        } else {

            res.status(422)
                .json({
                    message: 'Name and Content are required!'
                })
        }
    })

app.listen(3000, () => {
    console.log('Listening on http://localhost:3000');
})