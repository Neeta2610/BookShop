const express = require('express');
const common = require('../lib/common');
const { restrict, checkAccess } = require('../lib/auth');
const escape = require('html-entities').AllHtmlEntities;
const colors = require('colors');
const bcrypt = require('bcryptjs');
const moment = require('moment');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const mime = require('mime-type/with-db');
const csrf = require('csurf');
const { validateJson } = require('../lib/schema');
const ObjectId = require('mongodb').ObjectID;
const router = express.Router();
const csrfProtection = csrf({ cookie: true });
var cloudinary = require('cloudinary').v2;

cloudinary.config({
    cloud_name: 'hoiuqedcf',
    api_key: '849651669432825',
    api_secret: 'FdsuCdcqhNFa-7vCU8GZfExKA_Y'
});

// Regex
const emailRegex = /\S+@\S+\.\S+/;
const numericRegex = /^\d*\.?\d*$/;

// Admin section
router.get('/admin', restrict, (req, res, next) => {
    res.redirect('/admin/dashboard');
});

// logout
router.get('/admin/logout', (req, res) => {
    req.session.user = null;
    req.session.message = null;
    req.session.messageType = null;
    res.redirect('/');
});

// Used for tests only
if (process.env.NODE_ENV === 'test') {
    router.get('/admin/csrf', csrfProtection, (req, res, next) => {
        res.json({
            csrf: req.csrfToken()
        });
    });
}

// login form
router.get('/admin/login', async (req, res) => {
    const db = req.app.db;

    const userCount = await db.users.countDocuments({});
    // we check for a user. If one exists, redirect to login form otherwise setup
    if (userCount && userCount > 0) {
        // set needsSetup to false as a user exists
        req.session.needsSetup = false;
        res.render('login', {
            title: 'Login',
            referringUrl: req.header('Referer'),
            config: req.app.config,
            message: common.clearSessionValue(req.session, 'message'),
            messageType: common.clearSessionValue(req.session, 'messageType'),
            helpers: req.handlebars.helpers,
            showFooter: 'showFooter'
        });
    } else {
        // if there are no users set the "needsSetup" session
        req.session.needsSetup = true;
        res.redirect('/admin/setup');
    }
});

// login the user and check the password
router.post('/admin/login_action', async (req, res) => {
    const db = req.app.db;

    const user = await db.users.findOne({ userEmail: common.mongoSanitize(req.body.adminemail) });
    if (!user || user === null) {
        messages = 'A user with that email does not exist.';
        res.status(400).json({ message: messages });
        return;
    }

    // we have a user under that email so we compare the password
    bcrypt.compare(req.body.adminpassword, user.userPassword)
        .then((result) => {
            if (result) {
                req.session.user = req.body.adminemail;
                req.session.usersName = user.usersName;
                req.session.userId = user._id.toString();
                req.session.isAdmin = user.isAdmin;
                res.status(200).json({ message: 'Login successful' });
                return;
            }
            // password is not correct
            res.status(400).json({ message: 'Access denied. Check password and try again.' });
        });
});

// setup form is shown when there are no users setup in the DB
router.get('/admin/setup', async (req, res) => {
    const db = req.app.db;

    const userCount = await db.users.countDocuments({});
    // dont allow the user to "re-setup" if a user exists.
    // set needsSetup to false as a user exists
    req.session.needsSetup = false;
    if (userCount === 0) {
        req.session.needsSetup = true;
        res.render('setup', {
            title: 'Setup',
            config: req.app.config,
            helpers: req.handlebars.helpers,
            message: common.clearSessionValue(req.session, 'message'),
            messageType: common.clearSessionValue(req.session, 'messageType'),
            showFooter: 'showFooter'
        });
        return;
    }
    res.redirect('/admin/login');
});

// insert a user
router.post('/admin/setup_action', async (req, res) => {
    const db = req.app.db;

    const doc = {
        usersName: req.body.usersName,
        userEmail: req.body.userEmail,
        userPassword: bcrypt.hashSync(req.body.userPassword, 10),
        isAdmin: true,
        isOwner: true
    };

    // check for users
    const userCount = await db.users.countDocuments({});
    if (userCount === 0) {
        // email is ok to be used.
        try {
            await db.users.insertOne(doc);
            res.status(200).json({ message: 'User account inserted' });
            return;
        } catch (ex) {
            console.error(colors.red('Failed to insert user: ' + ex));
            res.status(200).json({ message: 'Setup failed' });
            return;
        }
    }
    res.status(200).json({ message: 'Already setup.' });
});

// dashboard
router.get('/admin/dashboard', csrfProtection, restrict, async (req, res) => {
    const db = req.app.db;

    // Collate data for dashboard
    const dashboardData = {
        productsCount: await db.products.countDocuments({
            productPublished: true
        }),
        ordersCount: await db.orders.countDocuments({}),
        ordersAmount: await db.orders.aggregate([{ $match: {} },
        {
            $group: { _id: null, sum: { $sum: '$orderTotal' } }
        }]).toArray(),
        productsSold: await db.orders.aggregate([{ $match: {} },
        {
            $group: { _id: null, sum: { $sum: '$orderProductCount' } }
        }]).toArray(),
        topProducts: await db.orders.aggregate([
            { $project: { _id: 0 } },
            { $project: { o: { $objectToArray: '$orderProducts' } } },
            { $unwind: '$o' },
            {
                $group: {
                    _id: '$o.v.title',
                    productImage: { $last: '$o.v.productImage' },
                    count: { $sum: '$o.v.quantity' }
                }
            },
            { $sort: { count: -1 } },
            { $limit: 5 }
        ]).toArray()
    };

    // Fix aggregate data
    if (dashboardData.ordersAmount.length > 0) {
        dashboardData.ordersAmount = dashboardData.ordersAmount[0].sum;
    }
    if (dashboardData.productsSold.length > 0) {
        dashboardData.productsSold = dashboardData.productsSold[0].sum;
    } else {
        dashboardData.productsSold = 0;
    }

    res.render('dashboard', {
        title: 'Cart dashboard',
        session: req.session,
        admin: true,
        dashboardData,
        themes: common.getThemes(),
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        csrfToken: req.csrfToken()
    });
});

// settings
router.get('/admin/settings', csrfProtection, restrict, (req, res) => {
    res.render('settings', {
        title: 'Cart settings',
        session: req.session,
        admin: true,
        themes: common.getThemes(),
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        footerHtml: typeof req.app.config.footerHtml !== 'undefined' ? escape.decode(req.app.config.footerHtml) : null,
        googleAnalytics: typeof req.app.config.googleAnalytics !== 'undefined' ? escape.decode(req.app.config.googleAnalytics) : null,
        csrfToken: req.csrfToken()
    });
});

// create API key
router.post('/admin/createApiKey', restrict, checkAccess, async (req, res) => {
    const db = req.app.db;
    const result = await db.users.findOneAndUpdate({
        _id: ObjectId(req.session.userId),
        isAdmin: true
    }, {
        $set: {
            apiKey: new ObjectId()
        }
    }, {
        returnOriginal: false
    });

    if (result.value && result.value.apiKey) {
        res.status(200).json({ message: 'API Key generated', apiKey: result.value.apiKey });
        return;
    }
    res.status(400).json({ message: 'Failed to generate API Key' });
});

// settings update
router.post('/admin/settings/update', restrict, checkAccess, (req, res) => {
    const result = common.updateConfig(req.body);
    if (result === true) {
        req.app.config = common.getConfig();
        res.status(200).json({ message: 'Settings successfully updated' });
        return;
    }
    res.status(400).json({ message: 'Permission denied' });
});

// settings menu
router.get('/admin/settings/menu', csrfProtection, restrict, async (req, res) => {
    const db = req.app.db;
    res.render('settings-menu', {
        title: 'Cart menu',
        session: req.session,
        admin: true,
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        menu: common.sortMenu(await common.getMenu(db)),
        csrfToken: req.csrfToken()
    });
});

// page list
router.get('/admin/settings/pages', csrfProtection, restrict, async (req, res) => {
    const db = req.app.db;
    const pages = await db.pages.find({}).toArray();

    res.render('settings-pages', {
        title: 'Static pages',
        pages: pages,
        session: req.session,
        admin: true,
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        menu: common.sortMenu(await common.getMenu(db)),
        csrfToken: req.csrfToken()
    });
});

// pages new
router.get('/admin/settings/pages/new', csrfProtection, restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    res.render('settings-page', {
        title: 'Static pages',
        session: req.session,
        admin: true,
        button_text: 'Create',
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        menu: common.sortMenu(await common.getMenu(db)),
        csrfToken: req.csrfToken()
    });
});

// pages editor
router.get('/admin/settings/pages/edit/:page', csrfProtection, restrict, checkAccess, async (req, res) => {
    const db = req.app.db;
    const page = await db.pages.findOne({ _id: common.getId(req.params.page) });
    const menu = common.sortMenu(await common.getMenu(db));
    if (!page) {
        res.status(404).render('404', {
            title: '404 Error - Page not found',
            config: req.app.config,
            message: '404 Error - Page not found',
            helpers: req.handlebars.helpers,
            showFooter: 'showFooter',
            menu
        });
        return;
    }

    res.render('settings-page', {
        title: 'Static pages',
        page: page,
        button_text: 'Update',
        session: req.session,
        admin: true,
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        menu,
        csrfToken: req.csrfToken()
    });
});

// insert/update page
router.post('/admin/settings/page', restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    const doc = {
        pageName: req.body.pageName,
        pageSlug: req.body.pageSlug,
        pageEnabled: req.body.pageEnabled,
        pageContent: req.body.pageContent
    };

    if (req.body.pageId) {
        // existing page
        const page = await db.pages.findOne({ _id: common.getId(req.body.pageId) });
        if (!page) {
            res.status(400).json({ message: 'Page not found' });
            return;
        }

        try {
            const updatedPage = await db.pages.findOneAndUpdate({ _id: common.getId(req.body.pageId) }, { $set: doc }, { returnOriginal: false });
            res.status(200).json({ message: 'Page updated successfully', pageId: req.body.pageId, page: updatedPage.value });
        } catch (ex) {
            res.status(400).json({ message: 'Error updating page. Please try again.' });
        }
    } else {
        // insert page
        try {
            const newDoc = await db.pages.insertOne(doc);
            res.status(200).json({ message: 'New page successfully created', pageId: newDoc.insertedId });
            return;
        } catch (ex) {
            res.status(400).json({ message: 'Error creating page. Please try again.' });
        }
    }
});

// delete a page
router.post('/admin/settings/page/delete', restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    const page = await db.pages.findOne({ _id: common.getId(req.body.pageId) });
    if (!page) {
        res.status(400).json({ message: 'Page not found' });
        return;
    }

    try {
        await db.pages.deleteOne({ _id: common.getId(req.body.pageId) }, {});
        res.status(200).json({ message: 'Page successfully deleted' });
        return;
    } catch (ex) {
        res.status(400).json({ message: 'Error deleting page. Please try again.' });
    }
});

// new menu item
router.post('/admin/settings/menu/new', restrict, checkAccess, (req, res) => {
    const result = common.newMenu(req);
    if (result === false) {
        res.status(400).json({ message: 'Failed creating menu.' });
        return;
    }
    res.status(200).json({ message: 'Menu created successfully.' });
});

// update existing menu item
router.post('/admin/settings/menu/update', restrict, checkAccess, (req, res) => {
    const result = common.updateMenu(req);
    if (result === false) {
        res.status(400).json({ message: 'Failed updating menu.' });
        return;
    }
    res.status(200).json({ message: 'Menu updated successfully.' });
});

// delete menu item
router.post('/admin/settings/menu/delete', restrict, checkAccess, (req, res) => {
    const result = common.deleteMenu(req, req.body.menuId);
    if (result === false) {
        res.status(400).json({ message: 'Failed deleting menu.' });
        return;
    }
    res.status(200).json({ message: 'Menu deleted successfully.' });
});

// We call this via a Ajax call to save the order from the sortable list
router.post('/admin/settings/menu/saveOrder', restrict, checkAccess, (req, res) => {
    const result = common.orderMenu(req, res);
    if (result === false) {
        res.status(400).json({ message: 'Failed saving menu order' });
        return;
    }
    res.status(200).json({});
});

// validate the permalink
router.post('/admin/validatePermalink', async (req, res) => {
    // if doc id is provided it checks for permalink in any products other that one provided,
    // else it just checks for any products with that permalink
    const db = req.app.db;

    let query = {};
    if (typeof req.body.docId === 'undefined' || req.body.docId === '') {
        query = { productPermalink: req.body.permalink };
    } else {
        query = { productPermalink: req.body.permalink, _id: { $ne: common.getId(req.body.docId) } };
    }

    const products = await db.products.countDocuments(query);
    if (products && products > 0) {
        res.status(400).json({ message: 'Permalink already exists' });
        return;
    }
    res.status(200).json({ message: 'Permalink validated successfully' });
});

// Discount codes
router.get('/admin/settings/discounts', csrfProtection, restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    const discounts = await db.discounts.find({}).toArray();

    res.render('settings-discounts', {
        title: 'Discount code',
        config: req.app.config,
        session: req.session,
        discounts,
        admin: true,
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        csrfToken: req.csrfToken()
    });
});

// Edit a discount code
router.get('/admin/settings/discount/edit/:id', csrfProtection, restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    const discount = await db.discounts.findOne({ _id: common.getId(req.params.id) });

    res.render('settings-discount-edit', {
        title: 'Discount code edit',
        session: req.session,
        admin: true,
        discount,
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        csrfToken: req.csrfToken()
    });
});

// Update discount code
router.post('/admin/settings/discount/update', restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    // Doc to insert
    const discountDoc = {
        discountId: req.body.discountId,
        code: req.body.code,
        type: req.body.type,
        value: parseInt(req.body.value),
        start: moment(req.body.start, 'DD/MM/YYYY HH:mm').toDate(),
        end: moment(req.body.end, 'DD/MM/YYYY HH:mm').toDate()
    };

    // Validate the body again schema
    const schemaValidate = validateJson('editDiscount', discountDoc);
    if (!schemaValidate.result) {
        res.status(400).json(schemaValidate.errors);
        return;
    }

    // Check start is after today
    if (moment(discountDoc.start).isBefore(moment())) {
        res.status(400).json({ message: 'Discount start date needs to be after today' });
        return;
    }

    // Check end is after the start
    if (!moment(discountDoc.end).isAfter(moment(discountDoc.start))) {
        res.status(400).json({ message: 'Discount end date needs to be after start date' });
        return;
    }

    // Check if code exists
    const checkCode = await db.discounts.countDocuments({
        code: discountDoc.code,
        _id: { $ne: common.getId(discountDoc.discountId) }
    });
    if (checkCode) {
        res.status(400).json({ message: 'Discount code already exists' });
        return;
    }

    // Remove discountID
    delete discountDoc.discountId;

    try {
        await db.discounts.updateOne({ _id: common.getId(req.body.discountId) }, { $set: discountDoc }, {});
        res.status(200).json({ message: 'Successfully saved', discount: discountDoc });
    } catch (ex) {
        res.status(400).json({ message: 'Failed to save. Please try again' });
    }
});

// Create a discount code
router.get('/admin/settings/discount/new', csrfProtection, restrict, checkAccess, async (req, res) => {
    res.render('settings-discount-new', {
        title: 'Discount code create',
        session: req.session,
        admin: true,
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config,
        csrfToken: req.csrfToken()
    });
});

// Create a discount code
router.post('/admin/settings/discount/create', csrfProtection, restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    // Doc to insert
    const discountDoc = {
        code: req.body.code,
        type: req.body.type,
        value: parseInt(req.body.value),
        start: moment(req.body.start, 'DD/MM/YYYY HH:mm').toDate(),
        end: moment(req.body.end, 'DD/MM/YYYY HH:mm').toDate()
    };

    // Validate the body again schema
    const schemaValidate = validateJson('newDiscount', discountDoc);
    if (!schemaValidate.result) {
        res.status(400).json(schemaValidate.errors);
        return;
    }

    // Check if code exists
    const checkCode = await db.discounts.countDocuments({
        code: discountDoc.code
    });
    if (checkCode) {
        res.status(400).json({ message: 'Discount code already exists' });
        return;
    }

    // Check start is after today
    if (moment(discountDoc.start).isBefore(moment())) {
        res.status(400).json({ message: 'Discount start date needs to be after today' });
        return;
    }

    // Check end is after the start
    if (!moment(discountDoc.end).isAfter(moment(discountDoc.start))) {
        res.status(400).json({ message: 'Discount end date needs to be after start date' });
        return;
    }

    // Insert discount code
    const discount = await db.discounts.insertOne(discountDoc);
    res.status(200).json({ message: 'Discount code created successfully', discountId: discount.insertedId });
});

// Delete discount code
router.delete('/admin/settings/discount/delete', restrict, checkAccess, async (req, res) => {
    const db = req.app.db;

    try {
        await db.discounts.deleteOne({ _id: common.getId(req.body.discountId) }, {});
        res.status(200).json({ message: 'Discount code successfully deleted' });
        return;
    } catch (ex) {
        res.status(400).json({ message: 'Error deleting discount code. Please try again.' });
    }
});

// upload the file
const upload = multer({ dest: 'public/uploads/' });
router.post('/admin/file/upload', restrict, checkAccess, upload.single('uploadFile'), async (req, res) => {
    const db = req.app.db;

    if (req.file) {
        const file = req.file;

        // Get the mime type of the file
        const mimeType = mime.lookup(file.originalname);

        // Check for allowed mime type and file size
        console.log(file.size);
        if (!common.allowedMimeType.includes(mimeType) || file.size > common.fileSizeLimit) {
            // Remove temp file
            fs.unlinkSync(file.path);

            // Return error
            req.session.message = 'File Type Not Allowed or too large';
            req.session.messageType = 'danger';
            console.log("Size");
            res.redirect('/admin/product/edit/' + req.body.productId);
            return;

        }

        // get the product form the DB
        const product = await db.products.findOne({ _id: common.getId(req.body.productId) });
        if (!product) {
            // delete the temp file.
            fs.unlinkSync(file.path);

            // Return error
            console.log("Product not found");

            res.status(400).json({ message: "Product Not Found" });
            return;
        }



        cloudinary.uploader.upload(file.path,
            async function (error, result) {
                if (result) {
                    var json_String = JSON.stringify(result);
                    var obj = JSON.parse(json_String);
                    var urlimagepath = obj.secure_url;
                    var image_id = obj.public_id;
                    if (!urlimagepath) {
                        urlimagepath = obj.url;
                    }
                    var imageArray = [];
                    var img_obj = {};
                    img_obj.id = image_id;
                    img_obj.path = urlimagepath;
                    await db.products.updateOne({ _id: common.getId(req.body.productId) }, { $set: { productImage: img_obj } });
                    fs.unlinkSync(file.path);
                    var str = "File uploaded successfully";
                    res.status(200).json({ message: str });
                    return;
                }
                else {
                    console.log(error);
                    fs.unlinkSync(file.path);
                    req.status(400).json({ message: error });
                    return;
                }
            });
        // Return success message
        return;
    }
    // Return error
    req.status(400).json({ message: "File Not Found" });
    return;
});

router.post('/admin/school/file/upload', restrict, checkAccess, upload.single('uploadFile'), async (req, res) => {
    const db = req.app.db;
    console.log("inside req file");
    console.log(req.file);
    if (req.file) {
        const file = req.file;

        // Get the mime type of the file
        const mimeType = mime.lookup(file.originalname);

        // Check for allowed mime type and file size
        console.log(file.size);
        if (!common.allowedMimeType.includes(mimeType) || file.size > common.fileSizeLimit) {
            // Remove temp file
            fs.unlinkSync(file.path);

            // Return error
            req.session.message = 'File Type Not Allowed or too large';
            req.session.messageType = 'danger';
            console.log("Size");
            res.redirect('/admin/product/edit/' + req.body.productId);
            return;

        }

        // get the product form the DB
        const product = await db.schools.findOne({ _id: common.getId(req.body.schoolId) });
        if (!product) {
            // delete the temp file.
            fs.unlinkSync(file.path);

            // Return error
            console.log("Product not found");
            res.status(400).json({ message: "Product Not Found" });
            return;
        }



        cloudinary.uploader.upload(file.path,
            async function (error, result) {
                if (result) {
                    var json_String = JSON.stringify(result);
                    var obj = JSON.parse(json_String);
                    var urlimagepath = obj.secure_url;
                    var image_id = obj.public_id;
                    if (!urlimagepath) {
                        urlimagepath = obj.url;
                    }
                    var imageArray = [];
                    var img_obj = {};
                    img_obj.id = image_id;
                    img_obj.path = urlimagepath;
                    await db.schools.updateOne({ _id: common.getId(req.body.schoolId) }, { $set: { productImage: img_obj } });
                    fs.unlinkSync(file.path);
                    var str = "File uploaded successfully";
                    res.status(200).json({ message: str });
                    return;
                }
                else {
                    console.log(error);
                    fs.unlinkSync(file.path);
                    res.status(400).json({ message: error });
                    return;
                }
            });
        // Return success message
        return;
    }
    // Return error
    res.status(400).json({ message: "File Not Found" });
    return;
});
// delete a file via ajax request
router.post('/admin/testEmail', restrict, (req, res) => {
    const config = req.app.config;
    // TODO: Should fix this to properly handle result
    common.sendEmail(config.emailAddress, 'expressCart test email', 'Your email settings are working');
    res.status(200).json({ message: 'Test email sent' });
});

// School Section
router.get('/admin/schools', restrict, async (req, res) => {
    const db = req.app.db;
    const schools = await db.schools.find({}).toArray();

    res.render('schools', {
        title: 'Schools List',
        session: req.session,
        admin: true,
        schools: schools,
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config
    });
});
router.get('/admin/school/edit/:id', restrict, async (req, res) => {
    const db = req.app.db;
    const user = await db.schools.findOne({ _id: common.getId(req.params.id) });

    // if the user we want to edit is not the current logged in user and the current user is not
    // an admin we render an access denied message
    console.log(user);

    res.render('school-edit', {
        title: 'School edit',
        admin: true,
        school: user,
        session: req.session,
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config
    });
});

// users new
router.get('/admin/school/new', restrict, (req, res) => {
    res.render('school-new', {
        title: 'School - New',
        admin: true,
        session: req.session,
        helpers: req.handlebars.helpers,
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        config: req.app.config
    });
});

// delete a user
router.post('/admin/user/delete', restrict, async (req, res) => {
    const db = req.app.db;

    // userId
    if (req.session.isAdmin !== true) {
        res.status(400).json({ message: 'Access denied' });
        return;
    }

    // Cannot delete your own account
    if (req.session.userId === req.body.userId) {
        res.status(400).json({ message: 'Unable to delete own user account' });
        return;
    }

    const user = await db.users.findOne({ _id: common.getId(req.body.userId) });

    // If user is not found
    if (!user) {
        res.status(400).json({ message: 'User not found.' });
        return;
    }

    // Cannot delete the original user/owner
    if (user.isOwner) {
        res.status(400).json({ message: 'Access denied.' });
        return;
    }

    try {
        await db.users.deleteOne({ _id: common.getId(req.body.userId) }, {});
        res.status(200).json({ message: 'User deleted.' });
        return;
    } catch (ex) {
        console.log('Failed to delete user', ex);
        res.status(200).json({ message: 'Cannot delete user' });
        return;
    };
});

// update a user
router.post('/admin/user/update', restrict, async (req, res) => {
    const db = req.app.db;

    let isAdmin = req.body.userAdmin === 'on';

    // get the user we want to update
    const user = await db.users.findOne({ _id: common.getId(req.body.userId) });

    // If user not found
    if (!user) {
        res.status(400).json({ message: 'User not found' });
        return;
    }

    // If the current user changing own account ensure isAdmin retains existing
    if (user.userEmail === req.session.user) {
        isAdmin = user.isAdmin;
    }

    // if the user we want to edit is not the current logged in user and the current user is not
    // an admin we render an access denied message
    if (user.userEmail !== req.session.user && req.session.isAdmin === false) {
        res.status(400).json({ message: 'Access denied' });
        return;
    }

    // create the update doc
    const updateDoc = {};
    updateDoc.isAdmin = isAdmin;
    if (req.body.usersName) {
        updateDoc.usersName = req.body.usersName;
    }
    if (req.body.userEmail) {
        updateDoc.userEmail = req.body.userEmail;
    }
    if (req.body.userPassword) {
        updateDoc.userPassword = bcrypt.hashSync(req.body.userPassword);
    }

    // Validate update user
    const schemaResult = validateJson('editUser', updateDoc);
    if (!schemaResult.result) {
        res.status(400).json({
            message: 'Failed to create user. Check inputs.',
            error: schemaResult.errors
        });
        return;
    }

    try {
        const updatedUser = await db.users.findOneAndUpdate(
            { _id: common.getId(req.body.userId) },
            {
                $set: updateDoc
            }, { multi: false, returnOriginal: false }
        );

        const returnUser = updatedUser.value;
        delete returnUser.userPassword;
        delete returnUser.apiKey;
        res.status(200).json({ message: 'User account updated', user: updatedUser.value });
        return;
    } catch (ex) {
        console.error(colors.red('Failed updating user: ' + ex));
        res.status(400).json({ message: 'Failed to update user' });
    }
});

// insert a user
router.post('/admin/school/insert', restrict, async (req, res) => {
    const db = req.app.db;

    const userObj = {
        schoolName: req.body.schoolName,
    };
    try {
        const newUser = await db.schools.insertOne(userObj);
        res.status(200).json({
            message: 'New School inserted',
            userId: newUser.insertedId
        });
    } catch (ex) {
        console.error(colors.red('Failed to insert user: ' + ex));
        res.status(400).json({ message: 'New user creation failed' });
    }
});

// School End Section
router.post('/admin/searchall', restrict, async (req, res, next) => {
    const db = req.app.db;
    const searchValue = req.body.searchValue;
    const limitReturned = 5;

    // Empty arrays
    let customers = [];
    let orders = [];
    let products = [];

    // Default queries
    const customerQuery = {};
    const orderQuery = {};
    const productQuery = {};

    // If an ObjectId is detected use that
    if (ObjectId.isValid(req.body.searchValue)) {
        // Get customers
        customers = await db.customers.find({
            _id: ObjectId(searchValue)
        })
            .limit(limitReturned)
            .sort({ created: 1 })
            .toArray();

        // Get orders
        orders = await db.orders.find({
            _id: ObjectId(searchValue)
        })
            .limit(limitReturned)
            .sort({ orderDate: 1 })
            .toArray();

        // Get products
        products = await db.products.find({
            _id: ObjectId(searchValue)
        })
            .limit(limitReturned)
            .sort({ productAddedDate: 1 })
            .toArray();

        return res.status(200).json({
            customers,
            orders,
            products
        });
    }

    // If email address is detected
    if (emailRegex.test(req.body.searchValue)) {
        customerQuery.email = searchValue;
        orderQuery.orderEmail = searchValue;
    } else if (numericRegex.test(req.body.searchValue)) {
        // If a numeric value is detected
        orderQuery.amount = req.body.searchValue;
        productQuery.productPrice = req.body.searchValue;
    } else {
        // String searches
        customerQuery.$or = [
            { firstName: { $regex: new RegExp(searchValue, 'img') } },
            { lastName: { $regex: new RegExp(searchValue, 'img') } }
        ];
        orderQuery.$or = [
            { orderFirstname: { $regex: new RegExp(searchValue, 'img') } },
            { orderLastname: { $regex: new RegExp(searchValue, 'img') } }
        ];
        productQuery.$or = [
            { productTitle: { $regex: new RegExp(searchValue, 'img') } },
            { productDescription: { $regex: new RegExp(searchValue, 'img') } }
        ];
    }

    // Get customers
    if (Object.keys(customerQuery).length > 0) {
        customers = await db.customers.find(customerQuery)
            .limit(limitReturned)
            .sort({ created: 1 })
            .toArray();
    }

    // Get orders
    if (Object.keys(orderQuery).length > 0) {
        orders = await db.orders.find(orderQuery)
            .limit(limitReturned)
            .sort({ orderDate: 1 })
            .toArray();
    }

    // Get products
    if (Object.keys(productQuery).length > 0) {
        products = await db.products.find(productQuery)
            .limit(limitReturned)
            .sort({ productAddedDate: 1 })
            .toArray();
    }

    return res.status(200).json({
        customers,
        orders,
        products
    });
});

// pincode page
router.get('/admin/pincode', restrict, async (req, res) => {
    // console.log("::::::::::: ",req.app);
    const db = req.app.db;
    const pincodes = await db.pincodes.find().toArray();
    console.log("pincodes :::::: ",pincodes);
    // bookshop.collectionNames('pincodes', function(err, names) {
    //     console.log('Exists: ', names.length > 0);
    // });

    res.render('pincode', {
        title: 'Pincodes List',
        session: req.session,
        admin: true,
        pincodes: pincodes,
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config
    });
});

// router.get('/admin/pincode/create', restrict, (req, res) => {
//     res.render('pincode', {
//         title: 'Pincodes',
//         admin: true,
//         session: req.session,
//         helpers: req.handlebars.helpers,
//         message: common.clearSessionValue(req.session, 'message'),
//         messageType: common.clearSessionValue(req.session, 'messageType'),
//         config: req.app.config
//     });
// });

// users new
router.get('/admin/pincode/new', restrict, async (req, res) => {
    const db = req.app.db;
    const pincodes = await db.pincodes.find({}).toArray();
    console.log(pincodes);
    res.render('pincode-new', {
        title: 'Pincode - New',
        session: req.session,
        pincodes: pincodes,
        pincode: common.clearSessionValue(req.session, 'pincode'),
        delivery_charge: common.clearSessionValue(req.session, 'delivery_charge'),
        editor: true,
        admin: true,
        helpers: req.handlebars.helpers,
        config: req.app.config
    });
});


// insert a pincode
router.post('/admin/pincode/insert', restrict, async (req, res) => {
    const db = req.app.db;

    const pincodeObj = {
        pincode: req.body.pincode,
        delivery_charge: req.body.deliveryCharge
    };
    try {
        const newPincode = await db.pincodes.insertOne(pincodeObj);
        res.status(200).json({
            message: 'New Pincode inserted',
            userId: newPincode.insertedId
        });
    } catch (ex) {
        console.error(colors.red('Failed to insert pincode: ' + ex));
        res.status(400).json({ message: 'New Pincode creation failed' });
    }
});

// update pincode
router.get('/admin/pincode/edit/:id', restrict, async (req, res) => {
    const db = req.app.db;
    const pincodes = await db.pincodes.findOne({ _id: common.getId(req.params.id) });

    console.log("edit pincode",pincodes);

    res.render('pincode-edit', {
        title: 'Pincode Edit',
        admin: true,
        pincode: pincodes,
        session: req.session,
        message: common.clearSessionValue(req.session, 'message'),
        messageType: common.clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        config: req.app.config
    });
});

router.post('/admin/pincode/update',restrict,(req,res) =>{
    const db = req.app.db;
    console.log("req.body ::: ",req.body,req.body.id,ObjectId(req.body.id));
    // const pincodes = await db.pincodes.findOne({ _id: ObjectId(req.body.id) });

    // console.log("update pincode",pincodes);
    var pincodeObj = { $set:{
        pincode : req.body.pincode,
        delivery_charge : req.body.deliveryCharge
    }
}

    try{
      db.pincodes.updateOne({ _id: ObjectId(req.body.id) }, pincodeObj, function(err, resp) {
            if (err) throw err;
            console.log("1 document updated");
            res.status(200).json({
                message: 'Pincode updated'
            });
          });
       
    }catch(ex){
        res.status(400).json({ message: 'Failed to save. Please try again' });
    }
})

// delete pincode

router.get('/admin/pincode/delete/:id',restrict,(req,res) =>{
    const db = req.app.db;
    console.log("Delete ::: ",req.params.id,ObjectId(req.body.id));
    // const pincodes = await db.pincodes.findOne({ _id: ObjectId(req.body.id) });



    try{
        db.pincodes.deleteOne({ _id: ObjectId(req.params.id) }, function(err, obj) {
            if (err) throw err;
            console.log("1 document deleted");
       
            res.redirect('/admin/pincode')
          });
       
    }catch(ex){
        res.status(400).json({ message: 'Failed to save. Please try again' });
    }
})
router.post('/admin/pincode/selected-pincode',async(req,res) =>{
    const db = req.app.db;
    console.log("req.body ::: ",req.body);
    const pincodes =  await db.pincodes.findOne({ pincode: req.body.pincode });
    let total = Number(req.body.priceTotal) + Number(pincodes.delivery_charge)
    // /customer/confirm
    console.log("get pincode",pincodes,Number(req.body.priceTotal),Number(pincodes.delivery_charge),total);
    let resultObj = {
        subTotal : req.body.priceTotal,
        delivery_charge : pincodes.delivery_charge,
        totalPrice : total.toString(),
    }

    req.session['price_breakdown'] = resultObj

    try{
        res.status(200).json({ message: 'Success', delivery_charge : pincodes.delivery_charge,totalPrice : total.toString() });
       
    }catch(ex){
        res.status(400).json({ message: 'Failed to save. Please try again' });
    }
})


module.exports = router;
