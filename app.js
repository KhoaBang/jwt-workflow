const express = require('express');
const dotenv = require('dotenv')
const cors = require('cors');


dotenv.config({path:'.env-local'})

const PORT = process.env.port || '8000';

const app = express();

/*
 MIDDLEWARE
*/
// CORS configuration
const corsOptions = {
    origin: '*', // Replace with your frontend URL or '*' to allow all origins
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allowed HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'], // Allowed headers
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({extended:false}));

/*
ROUTES
*/
app.get('/',(req,res)=>{
    res.status(200).json({name:'koba', doing: 'nothing'})
})

const userRouter = require('./routes/user')
app.use('/user',userRouter)
/*
START LISTENING
*/
app.listen(PORT,()=>{
    console.log(`Listening on port ${PORT}`)
})