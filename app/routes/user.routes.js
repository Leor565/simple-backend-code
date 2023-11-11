module.exports = app => {

    const users = require("../controllers/user.controller.js");
  
    var router = require("express").Router();
  
  
    // Create a new Product
    router.post("/", users.create);
  
    // Retrieve all Products
    router.get("/", users.findAll);
  
    // Retrieve a single Product with id
    router.get("/:id", users.findOne);
  
    // Update a Product with id
    router.put("/:id", users.update);
  
    // Delete a Product with id
    router.delete("/:id", users.delete);
  
    // Delete all Products
    router.delete("/", users.deleteAll);
  
  
    app.use('/api/users', router);
  };