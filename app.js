const express = require('express');
const dotenv = require('dotenv')


dotenv.config({path:'.env-local'})

const PORT = process.env.port || '8000';

const app = express();

/**
 * MIDDLEWARE
 */
app.use(express.json());
app.use(express.urlencoded({extended:false}));
// app.use(session({

// }))
/**
 * ROUTES
 */
app.get('/',(req,res)=>{
    res.status(200).json({name:'koba', doing: 'nothing'})
})

const userRouter = require('./routes/user')
app.use('/user',userRouter)
/**
 * START LISTENING
 */
app.listen(PORT,()=>{
    console.log(`Listening on port ${PORT}`)
})