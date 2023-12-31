const app = require("./src/app");

const PORT = process.env.PORT || 3055

const server = app.listen(3055, () => {
    console.log(`WSV eCommerce with ${PORT}`)
})

process.on('SIGINT', () => {
    server.close(() => {
        console.log('Exit Server Express')
    })
})