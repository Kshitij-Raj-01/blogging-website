import express from 'express';
import mongoose from 'mongoose';
import "dotenv/config";
import bcrypt from 'bcrypt';
import { nanoid } from 'nanoid';
import Jwt from 'jsonwebtoken';
import cors from 'cors'
import admin from 'firebase-admin';
// import { readFileSync } from 'fs';
// const serviceAccountKey = JSON.parse(readFileSync(new URL('./blogging-website-ca8cc-firebase-adminsdk-qvp9e-c2a7c7c700.json', import.meta.url)));
const firebaseServiceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
import { getAuth } from 'firebase-admin/auth';
// import aws from 'aws-sdk';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

//Schema Below
import User from './Schema/User.js'; // Ensure the correct path
import Blog from "./Schema/Blog.js"
import Notification from "./Schema/Notification.js"
import Comment from "./Schema/Comment.js"


const server = express();
let PORT = 3000;

admin.initializeApp({
    credential: admin.credential.cert(firebaseServiceAccount)
})

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());
server.use(cors())

mongoose.connect(process.env.DB_LOCATION, {
    autoIndex: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('Error connecting to MongoDB', err));


const s3 = new S3Client({
    region: 'ap-south-1',
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
  });

const generateUploadURL = async () => {
    const date = new Date();
    const imageName = `${nanoid()}-${date.getTime()}.jpeg`;
    // Create a PutObjectCommand
    const command = new PutObjectCommand({
      Bucket: 'kshitij-blogging-website',
      Key: imageName,
      ContentType: 'image/jpeg',
    });
  
    // Use getSignedUrl to generate the signed URL
    const uploadURL = await getSignedUrl(s3, command, { expiresIn: 1000 });
    
    return uploadURL;
  };

  //upload image url root
  server.get('/get-upload-url', (req,res) => {
      generateUploadURL().then(url => res.status(200).json({ uploadURL : url }))
      .catch(err => {
          console.log(err.message);
          return res.status(500).json({"error": err.message})
      })
  })

const verifyJWT = (req, res, next) => {

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(token == null){
        return res.status(401).json({error: "No access token"})
    }

    Jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if(err){
            return res.status(403).json({ error: "Access token is invalid" })
        }

        req.user = user.id
        next()
    })

}

const formatDatatoSend = (user) => {

    const access_token = Jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_KEY)

    return{
        access_token,
        profile_img: user.personal_info.profile_img,
        username : user.personal_info.username,
        fullname : user.personal_info.fullname
    }
}

const generateUsername = async (email) => {
    let username = email.split("@")[0];

    let isUsernameNotUnique = await User.exists({ "personal_info.username": username }).then((result) => result)

    isUsernameNotUnique ? username += nanoid().substring(0, 5) : "";

    return username

}

server.post("/signup", (req, res) => {
    let { fullname, email, password } = req.body;

    // validating the data from frontend
    if (fullname.length < 3) {
        return res.status(403).json({ "error": "Fullname must be at least 3 letters long" });
    }
    if (!email.length) {
        return res.status(403).json({ "error": "Enter email" });
    }
    if (!emailRegex.test(email)) {
        return res.status(403).json({ "error": "Email is invalid" });
    }
    if (!passwordRegex.test(password)) {
        return res.status(403).json({ "error": "Password should be 6 to 20 characters long with a numeric, 1 lowercase, and 1 uppercase letter" });
    }

    bcrypt.hash(password, 10,async (err, hashed_password) => {
        if (err) {
            return res.status(500).json({ "error": "Error hashing password" });
        }

        let username = await generateUsername(email);

        let user = new User({
            personal_info: { fullname, email, password: hashed_password, username }
        });

        user.save()
        .then((u) => {
            return res.status(200).json(formatDatatoSend(u));
        })
        .catch(err => {

            if(err.code == 11000){
                return res.status(500).json({ "error": "Email already exist" })
            }

            return res.status(500).json({ "error": err.message });
        });

    });
});

server.post("/signin", (req,res) => {
    let {email, password} = req.body;

    User.findOne({ "personal_info.email": email })
    .then((user) => {
        if(!user){
            return res.status(403).json({"error": 'Email not found'})
        }

        if(!user.google_auth){

            bcrypt.compare(password, user.personal_info.password, (err, result) => {
                if(err){
                    return res.status(403).json({"error": "Error occuren while login please try again"})
                }
    
                if(!result){
                    return res.status(403).json({"error": "Incorrect password"})
                }else{
                    return res.status(200).json(formatDatatoSend(user))
                }
            })
        } else{
            return res.status(403).json({"error": "Account was created using Google. Try logging in with google"})
        }

    })
    .catch(err => {
        console.log(err)
        return res.status(500).json({"error": err.message})
    })
})

server.post("/google-auth", async (req, res) => {

    let { access_token } = req.body;

    getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {

        let { email, name, picture } = decodedUser

        picture = picture.replace("s96-c","s384-c")

        let user = await User.findOne({"personal_info.email": email}).select("personal_info.fullname personal_info.username personal_info.profile_img personal_info.google_auth").then((u) => {
            return u || null
        })
        .catch(err => {
            return res.status(500).json({"error": err.message})
        })

        if(user){//login
            if(user.google_auth){
                return res.status(403).json({"error" : "This email was signed up without google. Please log in with password to access the account"})
            }
        }
        else{// sign up

            let username = await generateUsername(email);

            user = new User({
                personal_info: {fullname: name, email, profile_img: picture, username},
                google_auth: true
            })

            await user.save().then((u) => {
                user = u;
            })
            .catch(err => {
                return res.status(500).json({"error": err.message})
            })

        }

        return res.status(200).json(formatDatatoSend(user))

    })
    .catch(err => {
        return res.status(500).json({"error" : "Failed to authenticate you with google. Try with another google account"})
    })

})

server.post('/change-password', verifyJWT, (req,res) => {

    let { currentPassword, newPassword } = req.body;

    if(!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)){
        return res.status(403).json({ error: "Password should be 6 to 20 characters long with a numeric, 1 lowercase, and 1 uppercase letter" })
    }

    User.findOne({ _id: req.user })
    .then((user) => {
        
        if(user.google_auth){
            return res.status(403).json({ error : "You can't change password because you logged in through google" })
        }

        bcrypt.compare(currentPassword, user.personal_info.password, (err, result) => {
            if(err){
                return res.status(500).json({ error: "Some error occured, please try again later" })
            }

            if(!result){
                return res.status(403).json({ error: "Incorrect current password" })
            }

            bcrypt.hash(newPassword, 10, (err, hashed_password) => {
                
                User.findOneAndUpdate({ _id: req.user }, { "personal_info.password": hashed_password })
                .then((u) => {
                    return res.status(200).json({ status: "Password changed" })
                })
                .catch(err => {
                    return res.status(500).json({ error: "Some error occured, please try again later" })
                })

            })
        })

    })
    .catch(err => {
        return res.status(500).json({ error: "User not found" })
    })

})

server.post('/latest-blogs', (req,res) => {

    let { page } = req.body

    let maxLimit = 5;

    Blog.find({ draft : false })
    .populate("author", " personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "publishedAt": -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({ blogs })
    })
    .catch(err => {
        return res.status(500).json({error : err.message})
    })

})

server.post("/all-latest-blogs-count", (req,res) => {

    Blog.countDocuments({ draft: false })
    .then(count => {
        return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
        console.log(err.message)
        return res.status(500).json({ error: err.message })
    })

})

server.get('/trending-blogs', (req,res) => {

    Blog.find({draft : false})
    .populate("author", " personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "activity.total_read": -1, "activity.total_likes": -1 })
    .select("blog_id title publishedAt -_id")
    .limit(5)
    .then(blogs => {
        return res.status(200).json({ blogs })
    })
    .catch(err => {
        return res.status(500).json({error : err.message})
    })

})

server.post("/search-blogs", (req,res) => {

    let { tag, query, author, page, limit, eliminate_blog } = req.body;

    let findQuery;

    if(tag){
        findQuery = { tags: tag, draft: false, blog_id: { $ne: eliminate_blog } };
    } else if(query){
        findQuery = { draft: false, title: new RegExp(query, 'i') }
    } else if(author){
        findQuery = { author, draft: false }
    }

    let maxLimit = limit ? limit : 2;

    Blog.find(findQuery)
    .populate("author", " personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "publishedAt": -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({ blogs })
    })
    .catch(err => {
        return res.status(500).json({error : err.message})
    })

})

server.post("/search-blogs-count", (req, res) => {

    let { tag, author, query } = req.body;

    let findQuery;

    if(tag){
        findQuery = { tags: tag, draft: false };
    } else if(query){
        findQuery = { draft: false, title: new RegExp(query, 'i') }
    } else if(author){
        findQuery = { author, draft: false }
    }

    Blog.countDocuments(findQuery)
    .then(count => {
        return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({ error: err.message })
    })
})

server.post("/search-users", ( req, res ) => {

    let { query } = req.body;

    User.find({ "personal_info.username": new RegExp(query, 'i') })
    .limit(50)
    .select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
    .then(users => {
        return res.status(200).json({ users })
    })
    .catch(err => {
        return res.status(500).json({ error : err.message })
    })

})

server.post('/get-profile', (req,res) => {

    let { username } = req.body;

    User.findOne({ "personal_info.username": username})
    .select("-personal_info.password -google_auth -updateAt -blogs")
    .then(user => {
        return res.status(200).json(user)
    })
    .catch(err => {
        console.log(err)
        return res.status(500).json({"error" : err.message})
    })

})

server.post("/update-profile-image", verifyJWT, (req, res) => {

    let { url } = req.body

    User.findOneAndUpdate({ _id: req.user }, { "personal_info.profile_img": url })
    .then(() => {
        return res.status(200).json({ profile_img: url })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })

})

server.post("/update-profile", verifyJWT, (req, res) => {

    let { username, bio, social_links } = req.body;

    let bioLimit = 150;

    if(username.length < 3){
        return res.status(403).json({ error: "Username should be atleast 3 letter long" })
    }
    if(bio.length > bioLimit){
        return res.status(403).json({ error: `Bio should not be more than ${bioLimit}` })
    }

    let socialLinksArr = Object.keys(social_links)

    try{

        for(let i =0; i < socialLinksArr.length; i++){
            if(social_links[socialLinksArr[i]].length){
                let hostname = new URL(social_links[socialLinksArr[i]]).hostname;

                if(!hostname.includes(`${socialLinksArr[i]}.com`) && socialLinksArr[i] != 'website'){
                    return res.status(403).json({ error: `${socialLinksArr[i]} link is invalid. You must enter a full link` })
                }
            }
        }

    } catch(err){
        return res.status(500).json({ error: "You must provide full social links with http(s) included" })
    }

    let updateObj = {
        "personal_info.username": username,
        "personal_info.bio": bio,
        social_links 
    }

    User.findOneAndUpdate({ _id: req.user }, updateObj, {
        runValidators: true
    })
    .then(() => {
        return res.status(200).json({ username })
    })
    .catch(err => {
        if(err.code == 11000){
            return res.status(409).json({ error: "Username is already taken" })
        }
        return res.status(500).json({ error: err.message })
    })

})

server.post('/create-blog', verifyJWT ,(req,res) => {

    let authorId = req.user;

    let { title, banner, content, des, tags, draft, id } = req.body;

    if(!title.length){
        return res.status(403).json({ error : "You must provide a title" })
    }


    if(!draft){

        if(!des.length || des.length > 200){
            return res.status(403).json({ error : "You must provide blog description under 200 character" })
        }
    
        if(!banner.length){
            return res.status(403).json({ error : "You must provide blog banner to publish the blog" })
        }
    
        if(!content.blocks.length){
            return res.status(403).json({ error : "There must be some blog content to publish it" })
        }
    
        if(!tags.length || tags.length > 10){
            return res.status(403).json({ error : "Provide tags in order to publish the blog, maximum 10" })
        }

    }


    tags = tags.map(tag => tag.toLowerCase());

    let blog_id = id || title.replace(/[^a-zA-Z0-9]/g, " ").replace(/\s+/g, "-").trim() + nanoid();

    if(id){

        Blog.findOneAndUpdate({ blog_id }, { title, des, banner, content, tags, draft: draft ? draft : false })
        .then(() => {
            return res.status(200).json({ id: blog_id })
        })
        .catch(err => {
            return res.status(500).json({ error : "Failed to update the post"})
        })
        
    }
    else{

        let blog = new Blog({
            title, des, banner, content, tags, author: authorId, blog_id, draft: Boolean(draft)
        })
    
        blog.save().then(blog => {
    
            let increamentVal = draft ? 0 : 1;
    
            User.findOneAndUpdate({ _id: authorId }, { $inc: { "account_info.total_posts" : increamentVal }, $push : {"blogs" : blog._id} })
            .then(user => {
                return res.status(200).json({ id : blog.blog_id})
            })
            .catch(err => {
                return res.status(500).json({ error: "Failed to update total posts number" })
            })
    
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })

    }

})

server.post("/get-blog", (req, res) => {

    let { blog_id, draft, mode } = req.body

    let increamentVal = mode!='edit' ? 1 : 0;

    Blog.findOneAndUpdate({ blog_id }, { $inc : { "activity.total_reads": increamentVal } })
    .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
    .select("title des content banner activity publishedAt blog_id tags")
    .then(blog => {

        User.findOneAndUpdate({ "personal_info.username": blog.author.personal_info.username }, {
            $inc : { "account_info.total_reads": increamentVal }
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })

        if(blog.draft && !draft){
            return res.status(500).json({error: 'you can not access draft blogs'})
        }

        return res.status(200).json({ blog })
    })
    .catch(err => {
        return res.status(500).json({ error : err.message })
    })

})

server.post("/like-blog", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { _id, islikedByUser } = req.body

    let increamentVal = !islikedByUser ? 1 : -1

    Blog.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": increamentVal } })
    .then(blog => {

        if(!islikedByUser){
            let like = new Notification({
                type: 'like',
                blog: _id,
                notification_for: blog.author,
                user: user_id 
            })

            like.save().then(notification => {
                return res.status(200).json({ liked_by_user: true })
            })
        }
        else{

            Notification.findOneAndDelete({ user: user_id, blog: _id, type: 'like' })
            .then(data => {
                return res.status(200).json({ liked_by_user: false })
            })
            .catch(err => {
                return res.status(500).json({ error: err.message })
            })

        }

    })

})

server.post("/isliked-by-user", verifyJWT, (req, res) => {

    let user_id = req.user

    let { _id } = req.body;

    Notification.exists({ user: user_id, type: 'like', blog: _id})
    .then(result => {
        return res.status(200).json({ result })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })

})

server.post("/add-comment", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { _id, comment, blog_author, replying_to, notification_id } = req.body

    if(!comment.length){
        return res.status(403).json({ error : "Write something to leave a comment" })
    }

    //creating a comment doc
    let commentObj = {
        blog_id: _id,
        blog_author,
        comment,
        commented_by: user_id,
    }

    if(replying_to){
        commentObj.parent = replying_to;
        commentObj.isReply = true;
    }

    new Comment(commentObj).save().then(async commentFile => {
        
        let { comment, commentedAt, children } = commentFile

        Blog.findOneAndUpdate({ _id }, { $push: { "comments": commentFile._id }, $inc: { "activity.total_comments": 1, "activity.total_parent_comments": replying_to ? 0 : 1 } })
        .then(blog => {console.log("New comment created")})

        let notificationObj = {
            type: replying_to ? "reply" : "comment",
            blog: _id,
            notification_for: blog_author,
            user: user_id,
            comment: commentFile._id
        }

        if(replying_to){

            notificationObj.replied_on_comment = replying_to;

            await Comment.findOneAndUpdate({ _id: replying_to }, { $push: { children: commentFile._id } })
            .then(replyingToCommentDoc => { notificationObj.notification_for = replyingToCommentDoc.commented_by })

            if(notification_id){
                Notification.findOneAndUpdate({ _id: notification_id }, { reply: commentFile._id })
                .then(notification => console.log('notification updated'))
            }

        }

        new Notification(notificationObj).save().then(notification => console.log("new notification created"))

        return res.status(200).json({
            comment, commentedAt, _id: commentFile._id, user_id, children
        })
    })
})

server.post("/get-blog-comments", (req, res) => {
    
    let { blog_id, skip } = req.body;

    let maxLimit = 5;

    Comment.find({ blog_id, isReply: false })
    .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img")
    .skip(skip)
    .limit(maxLimit)
    .sort({
        'commentedAt': -1
    })
    .then(comment => {
        return res.status(200).json(comment)
    })
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({ error: err.message })
    })

})

server.post("/get-replies", (req, res) => {

    let { _id, skip } = req.body;

    let maxLimit = 5;

    Comment.findOne({ _id })
    .populate({ 
        path: "children",
        options: {
            limit: maxLimit,
            skip: skip,
            sort: { 'commentedAt': -1 }
        },
        populate: {
            path: 'commented_by',
            select: 'personal_info.profile_img personal_info.fullname personal_info.username' 
        },
        select: '-blog_id -updatedAt' 
    })
    .select("children")
    .then(doc => {
        return res.status(200).json({ replies: doc.children })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })

})

const deleteComments = (_id) => {
    Comment.findOneAndDelete({ _id })
    .then(comment => {

        if(comment.parent){
            Comment.findOneAndUpdate({ _id: comment.parent }, { $pull: { children: _id } })
            .then(data => console.log('comment delete from parent'))
            .catch(err => console.log(err))
        }

        Notification.findOneAndDelete({ comment: _id })
        .then(notification => console.log('comment notification deleted'))
        
        Notification.findOneAndUpdate({ reply: _id }, { $unset: { reply: 1 } })
        .then(notification => console.log('reply notification deleted'))

        Blog.findOneAndUpdate({ _id: comment.blog_id }, { $pull: { comments: _id }, $inc: { "activity.total_comments": -1, "activity.total_parent_comments": comment.parent ? 0 : -1 } })
        .then(blog => {
            if(comment.children.length){
                comment.children.map(replies => {
                    deleteComments(replies)
                })
            }
        })

    })
    .catch(err => {
        console.log(err)
    })
}

server.post("/delete-comment",verifyJWT ,(req, res) => {

    let user_id = req.user;

    let { _id } = req.body;

    Comment.findOne({ _id })
    .then(comment => {

        if( user_id == comment.commented_by || user_id == comment.blog_author ){
            
            deleteComments(_id)

            return res.status(200).json({ status: 'done' })

        }else{
            return res.status(403).json({ error: "You cannot delete this comment" })
        }

    })

})

server.get("/new-notification", verifyJWT, (req, res) => {

    let user_id = req.user;

    Notification.exists({ notification_for: user_id, seen: false, user: { $ne: user_id } })
    .then(result => {
        if(result){
            return res.status(200).json({ new_notification_available: true })
        } else{
            return res.status(200).json({ new_notification_available: false })
        }
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })

})

server.post("/notifications", verifyJWT, (req, res) => {
    let user_id = req.user 

    let { page, filter, deletedDocCount } = req.body

    let maxLimit = 10;

    let findQuery = { notification_for: user_id, user: { $ne: user_id } }

    let skipDocs = ( page -1 ) * maxLimit;

    if(filter != 'all'){
        findQuery.type = filter;
    }

    if(deletedDocCount){
        skipDocs -= deletedDocCount
    }

    Notification.find(findQuery)
    .skip(skipDocs)
    .limit(maxLimit)
    .populate("blog", "title blog_id")
    .populate("user", "personal_info.fullname personal_info.profile_img personal_info.username")
    .populate("comment", "comment")
    .populate("replied_on_comment", "comment")
    .populate("reply", "comment")
    .sort({ createdAt: -1 })
    .select("createdAt type seen reply")
    .then(notifications => {

        Notification.updateMany(findQuery, { seen: true })
        .skip(skipDocs)
        .limit(maxLimit)
        .then(() => console.log("notification seen"))

        return res.status(200).json({ notifications })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })

})

server.post("/all-notifications-count", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { filter } = req.body

    let findQuery = { notification_for: user_id, user: { $ne: user_id } }

    if(filter != 'all'){
        findQuery.type == filter;
    }

    Notification.find(findQuery)
    .then(count => {
        return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })

})

server.post("/user-written-blogs", verifyJWT, (req, res) => {

    let user_id = req.user;

    let { page, draft, query, deletedDocCount } = req.body;

    let search_query = query ? new RegExp(query, 'i') : /.*/;

    let maxLimit = 5;
    let skipDocs = (page - 1) * maxLimit

    if(deletedDocCount){
        skipDocs -= deletedDocCount
    }

    Blog.find({ author: user_id, draft, title: search_query })
    .skip(skipDocs)
    .limit(maxLimit)
    .sort({ publishedAt: -1 })
    .select(" title banner publishedAt blog_id activity des draft -_id ")
    .then(blogs => {
        return res.status(200).json({ blogs })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })


})

server.post("/user-written-blogs-count", verifyJWT, (req, res) => {

    let user_id = req.user;
    let { draft, query } = req.body;

    console.log("Received draft:", draft, "query:", query);  // Log draft and query

    let searchQuery = query ? new RegExp(query, 'i') : undefined;  // Handle empty query

    Blog.countDocuments({
        author: user_id,
        draft,
        ...(searchQuery && { title: searchQuery })  // Only add title filter if searchQuery is defined
    })
    .then(count => {
        console.log("Total Docs:", count);  // Log the total count
        return res.status(200).json({ totalDocs: count });
    })
    .catch(err => {
        console.log("Error:", err);  // Log any errors
        return res.status(500).json({ error: err.message });
    });
});


server.post("/delete-blog", verifyJWT, async (req, res) => { 
    let user_id = req.user;
    let { blog_id } = req.body;

    try {
        // Attempt to find and delete the blog
        const blog = await Blog.findOneAndDelete({ blog_id });
        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }

        // Delete associated notifications and comments
        await Promise.all([
            Notification.deleteMany({ blog: blog_id }),
            Comment.deleteMany({ blog_id: blog_id }),
            User.findOneAndUpdate({ _id: user_id }, { 
                $pull: { blog: blog_id }, 
                $inc: { "account_info.total_posts": -1 } 
            })
        ]);

        // Send success response
        return res.status(200).json({ status: "done" });

    } catch (err) {
        console.error("Error deleting blog:", err);
        return res.status(500).json({ error: err.message });
    }
});


server.listen(PORT, () => {
    console.log('listening on port -> ' + PORT);
});
