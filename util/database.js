const mariadb = require('mariadb');
const pool = mariadb.createPool({
     host: process.env.DB_HOST, 
     user:process.env.DB_USER, 
     password: process.env.DB_PASS,
     database:process.env.DB_NAME,
     connectionLimit: 5
});

// connect and check for error

pool.getConnection((err,connection)=>{
    if(err){
        if(err.code==="PROTOCOL_CONNECTION_LOST")
            console.error("DB connection lost")
        if(err.code==="ERR_CON_COUNT_ERR")
            console.error("DB has too many connection")
        if(err.code==="ECONNREFUSED")
            console.error("DB connection was refused")
    }
    if(connection) connection.release();
    return;
})

module.exports = pool