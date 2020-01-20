/*
 * User Schema model with its helper methods
*/
const mongoose = require('mongoose');
const bcrypt = require('bcrypt-nodejs');
var Schema = mongoose.Schema;
var UserSchema = new Schema({
    email:{ type:String, require: true, unique: true},
    password:{ type:String, required: true},
    mobile: {type: String, required: true},
    pin: {type: String, required: true},
    name: {type: String, required: false},
    city: {type: String, required: false},
    resetPasswordToken: {type: String},
    resetPasswordExpires: {type: Date}
});

/*
* Before saving the user object, salt and encrypt the password
*/
UserSchema.pre('save',function(next){
    var user = this;
    if (this.isModified('password') || this.isNew){
        bcrypt.genSalt(10, function(err,salt){
            if (err){
                return next(err);
            }
            bcrypt.hash(user.password,salt,null,function(err,hash){
                if (err){
                    return next(err);
                }
                user.password = hash;
                next();
            });
        });
    }
});


/*
* Helper method to compare the encrypted password with plain text password
*/
UserSchema.methods.comparePassword = function(passw,cb){
    bcrypt.compare(passw,this.password,function(err,isMatch){
        if (err){
            return cb(err);
        }
        cb(null,isMatch);
    })
}

module.exports = mongoose.model('User',UserSchema);
