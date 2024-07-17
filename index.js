const bcrypt = require('bcrypt');
const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const port = process.env.PORT || 5000;


// app.use(cors());
app.use(
    cors({
        origin: [
            "http://localhost:5173",
            "http://localhost:5000",
            "https://vericash-abrar.firebaseapp.com",
            "https://vericash-abrar.web.app",
            "https://vericash.netlify.app",
        ]
    })
);
app.use(express.json());



const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.1qcsvas.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();
        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
        const userCollection = client.db('VeriCash').collection('users');
        const transactionCollection = client.db('surveyMaster').collection('transactions');


        //JWT releted api
        app.post('/jwt', async (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN, {
                expiresIn: "1h"
            });
            res.send({ token });
        })

        //Middlewares
        const verifyToken = (req, res, next) => {
            if (!req.headers.authorization) {
                return res.status(401).send({ message: "unauthorized access" });
            }
            const token = req.headers.authorization.split(' ')[1];
            jwt.verify(token, process.env.ACCESS_TOKEN, (error, decoded) => {
                if (error) {
                    return res.status(401).send({ message: 'unauthorized access' });
                }
                req.decoded = decoded;
                next();
            })

        }

        //use verify admin after verify token
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await userCollection.findOne(query);
            const isAdmin = user?.role === "admin";
            if (!isAdmin) {
                return res.status(401).send({ message: "forbidden access" });
            }
            next();
        }


        //============user releted api===============


        //get users data
        app.get('/users', verifyToken, async (req, res) => {
            const result = await userCollection.find().toArray();
            res.send(result);
        })

        //Post user to mongodb with hashed PIN
        app.post('/users', async (req, res) => {
            const user = req.body;
            const query = { email: user.email };
            const existingUser = await userCollection.findOne(query);
            if (existingUser) {
                return res.send({ message: "User already exist!", insertedId: null });
            }
            //Hashing the PIN
            const hashedPin = await bcrypt.hash(user.pin, 10);
            user.pin = hashedPin;
            // console.log(user)
            const result = await userCollection.insertOne(user);
            res.send(result);
        })

        //getting user status is admin or not
        app.get('/users/admin/:email', verifyToken, async (req, res) => {
            const email = req.params.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: "forbidden access" });
            }
            const query = { email: email };
            const user = await userCollection.findOne(query);
            let admin = false;
            if (user) {
                admin = user?.role === 'admin'
            }
            res.send({ admin });
        })

        //getting user status is Agent or not
        app.get('/users/agent/:email', verifyToken, async (req, res) => {
            const email = req.params.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: "forbidden access" });
            }
            const query = { email: email };
            const user = await userCollection.findOne(query);
            let agent = false;
            if (user) {
                agent = user?.role === 'agent'
            }
            res.send({ agent });
        })

        //getting user status is user or not
        app.get('/users/user/:email', verifyToken, async (req, res) => {
            const email = req.params.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: "forbidden access" });
            }
            const query = { email: email };
            const userRes = await userCollection.findOne(query);
            let user = false;
            if (userRes) {
                user = userRes?.role === 'user'
            }
            res.send({ user });
        })

        //update user role to surveyor
        // app.patch('/users/admin/:id', verifyToken, verifyAdmin, async (req, res) => {
        //     const id = req.params.id;
        //     const filter = { _id: new ObjectId(id) };
        //     const updateDoc = {
        //         $set: { role: 'surveyor' }
        //     }
        //     const result = await userCollection.updateOne(filter, updateDoc);
        //     res.send(result);
        // })


        //Update normal user role to pro-user from Admin dashboard
        // app.patch('/users/:email', verifyToken, verifyAdmin, async (req, res) => {
        //     const email = req.params.email;
        //     const filter = { email: email };
        //     const updateDoc = {
        //         $set: { role: "pro-user" }
        //     }
        //     const result = await userCollection.updateOne(filter, updateDoc);
        //     res.send(result)
        // })

        //Delete a user by admin 
        app.delete('/users/:id', verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await userCollection.deleteOne(query);
            res.send(result);
        })


        //==================transactions Releted api ==================
        // get all transactions from db
        app.get('/transactions', verifyToken, async (req, res) => {
            const result = await transactionCollection.find().toArray();
            res.send(result);
        })


        // post a survey
        app.post('/transactions', verifyToken, async (req, res) => {
            const survey = req.body;
            const result = await transactionCollection.insertOne(survey);
            console.log(result);
            res.send(result);
        })



        //get survey by id
        // app.get('/surveys/surveyDetails/:id', async (req, res) => {
        //     const id = req.params.id;
        //     const query = { _id: new ObjectId(id) };
        //     const result = await surveyCollection.findOne(query);
        //     res.send(result);
        // })

        //get 10 most recent transaction:
        app.get('/transactions/recent', async (req, res) => {
            const recentTransaction = await transactionCollection.find()
                .sort({ createdOn: -1 })
                .limit(6)
                .toArray();
            console.log(recentTransaction)
            res.send(recentTransaction);
        })

        //get recentTransaction by email
        // app.get('/transaction/:email', verifyToken, async (req, res) => {
        //     const email = req.params.email;
        //     const query = { createdBy: email };
        //     console.log(query)
        //     const result = await recentTransaction.find(query).toArray();
        //     console.log(result)
        //     res.send(result);
        // })


        //Update payment status from Admin dashboard
        // app.patch('/payments/:id', verifyToken, verifyAdmin, async (req, res) => {
        //     const id = req.params.id;
        //     const filter = { _id: new ObjectId(id) };
        //     const updateDoc = {
        //         $set: { status: 'approved' }
        //     }
        //     const result = await paymentCollection.updateOne(filter, updateDoc);
        //     res.send(result);
        // })

    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);



app.get('/', (req, res) => {
    res.send("VeriCash Server is Running")
})
app.listen(port, (req, res) => {
    console.log(`VeriCash Server is running on Port: ${port}`)
})