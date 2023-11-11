module.exports = mongoose => {

    var schema = mongoose.Schema(
        {
            title: String,
            author: String,
            year: Number,
            genre: String,
            length: Number
        },
    );

    schema.method("toJSON", function () {
        const { __v, _id, ...object } = this.toObject();
        object.id = _id;

        return object;
    });

    const Products = mongoose.model("product", schema);

    return Products;
};