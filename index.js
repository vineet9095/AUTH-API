const express = require('express');
const mongoose = require('mongoose');
const app = express();

const swaggerJSDoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

var swaggerDefinition = {
  info: {
    title: "VineetPro",
    version: "1.0.0",
    description: "Swagger of Vineet API",
  },
  host: "localhost:4000",
  basePath: "/",
};
const options = {
  swaggerDefinition,
  apis: ["./routes/user.js"],
};

var swaggerSpec = swaggerJSDoc(options);

app.get("/swagger.json", function (req, res) {
  res.setHeader("Content-Type", "application/json");
  res.send(swaggerSpec);
});

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const userRouter = require('./routes/user');
app.use('/api/user', userRouter);

mongoose.connect('mongodb://localhost:27017/SignUp')
  .then(() => console.log("Connected To MongoDB"))
  .catch((error) => console.log(error));;

app.listen(4000, () => {
  console.log(`Server running on port 4000`);
})