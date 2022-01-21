require('dotenv').config()
const express = require('express');
const router = express.Router();
const colors = require('colors');
const randtoken = require('rand-token');
const bcrypt = require('bcryptjs');
const {
    getId,
    clearSessionValue,
    getCountryList,
    mongoSanitize,
    sendEmail,
    clearCustomer
} = require('../lib/common');
const rateLimit = require('express-rate-limit');
const { indexCustomers } = require('../lib/indexing');
const { validateJson } = require('../lib/schema');
const { restrict } = require('../lib/auth');

//*********************************//

const authy = require('authy')('MMl9PINH3y4OQdLzIGxxqo7Yk9T4bYGY');

const apiLimiter = rateLimit({
    windowMs: 300000, // 5 minutes
    max: 5
});

router.post('/customer/register',async function(req, res) {
    const config = req.app.config;
    const db = req.app.db;
	console.log('New register request...');

	//var isSuccessful = false;

	//var email = req.body.shipEmail;
	var phone = req.body.shipPhoneNumber;;
    var countryCode = '+91';
    const customer =  await db.customers.findOne({ phone: phone });
    console.log(customer);
            if(customer){
                req.session.message = "Customer with that Phone Already Exist";
                req.session.messageType = 'danger';
                res.redirect('/');
                return;
            } 
            const customerObj = {
              //  email: req.session.customerEmail,
                phone: phone,
                password: bcrypt.hashSync(req.body.password, 10),
                created: new Date()
            };
    
            // email is ok to be used.
            try{
                const newCustomer = await db.customers.insertOne(customerObj);
                indexCustomers(req.app)
                .then(async () => {
                    // Return the new customer
                    const customerReturn = newCustomer.ops[0];
                    delete customerReturn.password;
        
                    // Set the customer into the session
                    req.session.customerPresent = true;
                    req.session.customerId = customerReturn._id;
                   // req.session.customerEmail = customerReturn.email;
                    req.session.customerPhone = customerReturn.phone;
                //    req.session.orderComment = req.body.orderComment;
    
                    // Return customer oject

                    const db = req.app.db;

                    const customer = await db.customers.findOne({ phone: req.session.customerPhone });
                    // check if customer exists with that email
                    if(customer === undefined || customer === null){
                        res.status(400).json({
                            message: 'A customer with that phone does not exist.'
                        });
                        return;
                    }
                    // we have a customer under that email so we compare the password

                      /*  res.render(`${config.themeViews}checkout-information`, {
                            message: 'Account verified! 🎉',
                            title: 'Success',
                            config: req.app.config,
                            helpers: req.handlebars.helpers,
                            showFooter: true
                          });  */
                        //  res.send('Verified Account');
                        req.session.message = "User Created";
                        req.session.messageType = 'success';
                          res.redirect('/');
                          return;
                    })
                    .catch((err) => {
                        res.status(400).json({
                            message: 'Access denied. Check password and try again.'
                        });
                    });
            }catch(ex){
                console.error(colors.red('Failed to insert customer: ', ex));
                res.status(400).json({
                    message: 'Customer creation failed.'
                });
            }
	/*authy.register_user(email, phone, countryCode, function (regErr, regRes) {
    	console.log('In Registration...');
    	if (regErr) {
       		console.log(regErr);
               res.redirect('/customer/login');
               return;
    	} else if (regRes) {
			console.log(regRes);
			console.log("Here we go for the practice part"+regRes.user.id);

            // Set the customer into the sessions



    		authy.request_sms(regRes.user.id, function (smsErr, smsRes) {
				console.log('Requesting SMS...');
    			if (smsErr) {
    				console.log(smsErr);
                    req.session.message = smsErr;
                    req.session.messageType = 'danger';
                    res.redirect('/customer/login');
                    return;
    			} else if (smsRes) {
                    req.session.customerPhone = phone;
                    res.redirect('/checkout/information');
                    return;
    			}
			});
    	}
       });*/
       
});


router.post('/customer/confirm', async (req, res)=> {
	console.log('New verify request...' , req.body);
    const config = req.app.config;

	const id = req.body.requestId;
	const token = req.body.pin;

	authy.verify(id, token, async (verifyErr, verifyRes)=> {
		console.log('In Verification...');
		if (verifyErr) {
			console.log(verifyErr);
            res.send('OTP verification failed.');
            res.redirect('/checkout/information');
            return;
		} else if (verifyRes) {
            console.log("Is session working properly"+req.session.customerEmail);
            const db = req.app.db;
    
            const customerObj = {
                email: req.session.customerEmail,
                firstName: req.session.customerFirstname,
                lastName: req.session.customerLastname,
                address1: req.session.customerAddress1,
                state: req.session.customerState,
                postcode: req.session.customerPostcode,
                phone: req.session.customerPhone,
                password: bcrypt.hashSync(req.body.shipPassword, 10),
                created: new Date()
            };
        
            const schemaResult = validateJson('newCustomer', customerObj);
            if(!schemaResult.result){
                console.log("validation occur due to deleted some items here");
                res.status(400).json(schemaResult.errors);
                return;
            }
        
            // check for existing customer
            const customer =  await db.customers.findOne({ email: req.session.customerEmail });
            if(customer){
                res.status(400).json({
                    message: 'A customer already exists with that email'
                });
                return;
            } 
            // email is ok to be used.
            try{
                const newCustomer = await db.customers.insertOne(customerObj);
                indexCustomers(req.app)
                .then(async () => {
                    // Return the new customer
                    const customerReturn = newCustomer.ops[0];
                    delete customerReturn.password;
        
                    // Set the customer into the session
                    req.session.customerPresent = true;
                    req.session.customerId = customerReturn._id;
                    req.session.customerEmail = customerReturn.email;
                    req.session.customerFirstname = customerReturn.firstName;
                    req.session.customerLastname = customerReturn.lastName;
                    req.session.customerAddress1 = customerReturn.address1;
                    req.session.customerState = customerReturn.state;
                    req.session.customerPostcode = customerReturn.postcode;
                    req.session.customerPhone = customerReturn.phone;
                //    req.session.orderComment = req.body.orderComment;
    
                    // Return customer oject

                    const db = req.app.db;

                    const customer = await db.customers.findOne({ email: mongoSanitize(req.session.customerEmail ) });
                    // check if customer exists with that email
                    if(customer === undefined || customer === null){
                        res.status(400).json({
                            message: 'A customer with that email does not exist.'
                        });
                        return;
                    }
                    // we have a customer under that email so we compare the password
                    bcrypt.compare(req.body.shipPassword, customer.password)
                    .then((result) => {
                        if(!result){
                            // password is not correct
                            res.status(400).json({
                                message: 'Access denied. Check password and try again.'
                            });
                            return;
                        }
                      /*  res.render(`${config.themeViews}checkout-information`, {
                            message: 'Account verified! 🎉',
                            title: 'Success',
                            config: req.app.config,
                            helpers: req.handlebars.helpers,
                            showFooter: true
                          });  */
                        //  res.send('Verified Account');
                          res.redirect('/checkout/information');
                          return;
                    })
                    .catch((err) => {
                        res.status(400).json({
                            message: 'Access denied. Check password and try again.'
                        });
                    });
                });
            }catch(ex){
                console.error(colors.red('Failed to insert customer: ', ex));
                res.status(400).json({
                    message: 'Customer creation failed.'
                });
            }
            } else {
              res.status(401).send(result.error_text);
              res.redirect('/checkout/information');
              return;
            }
	});
});


//*************************************//

// insert a customer
router.post('/customer/create', async (req, res) => {
    const db = req.app.db;

    const customerObj = {
        email: req.body.email,
        company: req.body.company,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        address1: req.body.address1,
        address2: req.body.address2,
        country: req.body.country,
        state: req.body.state,
        postcode: req.body.postcode,
        phone: req.body.phone,
        password: bcrypt.hashSync(req.body.password, 10),
        created: new Date()
    };

    const schemaResult = validateJson('newCustomer', customerObj);
    if(!schemaResult.result){
        res.status(400).json(schemaResult.errors);
        return;
    }

    // check for existing customer
    const customer = await db.customers.findOne({ email: req.body.email });
    if(customer){
        res.status(400).json({
            message: 'A customer already exists with that email address'
        });
        return;
    }
    // email is ok to be used.
    try{
        const newCustomer = await db.customers.insertOne(customerObj);
        indexCustomers(req.app)
        .then(() => {
            // Return the new customer
            const customerReturn = newCustomer.ops[0];
            delete customerReturn.password;

            // Set the customer into the session
            req.session.customerPresent = true;
            req.session.customerId = customerReturn._id;
            req.session.customerEmail = customerReturn.email;
            req.session.customerCompany = customerReturn.company;
            req.session.customerFirstname = customerReturn.firstName;
            req.session.customerLastname = customerReturn.lastName;
            req.session.customerAddress1 = customerReturn.address1;
            req.session.customerAddress2 = customerReturn.address2;
            req.session.customerCountry = customerReturn.country;
            req.session.customerState = customerReturn.state;
            req.session.customerPostcode = customerReturn.postcode;
            req.session.customerPhone = customerReturn.phone;
            req.session.orderComment = req.body.orderComment;

            // Return customer oject
            res.status(200).json(customerReturn);
        });
    }catch(ex){
        console.error(colors.red('Failed to insert customer: ', ex));
        res.status(400).json({
            message: 'Customer creation failed.'
        });
    }
});

router.post('/customer/save', async (req, res) => {
    const customerObj = {
        email: req.body.email,
        company: req.body.company,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        address1: req.body.address1,
        address2: req.body.address2,
        country: req.body.country,
        state: req.body.state,
        postcode: req.body.postcode,
        phone: req.body.phone
    };

    const schemaResult = validateJson('saveCustomer', customerObj);
    if(!schemaResult.result){
        res.status(400).json(schemaResult.errors);
        return;
    }

    // Set the customer into the session
    req.session.customerPresent = true;
    req.session.customerEmail = customerObj.email;
    req.session.customerCompany = customerObj.company;
    req.session.customerFirstname = customerObj.firstName;
    req.session.customerLastname = customerObj.lastName;
    req.session.customerAddress1 = customerObj.address1;
    req.session.customerAddress2 = customerObj.address2;
    req.session.customerCountry = customerObj.country;
    req.session.customerState = customerObj.state;
    req.session.customerPostcode = customerObj.postcode;
    req.session.customerPhone = customerObj.phone;
    req.session.orderComment = req.body.orderComment;

    res.status(200).json(customerObj);
});

// Get customer orders
router.get('/customer/account', async (req, res) => {
    const db = req.app.db;
    const config = req.app.config;

    if(!req.session.customerPresent){
        res.redirect('/customer/login');
        return;
    }

    const orders = await db.orders.find({
        orderCustomer: getId(req.session.customerId)
    })
    .sort({ orderDate: -1 })
    .toArray();
    res.render(`${config.themeViews}customer-account`, {
        title: 'Orders',
        session: req.session,
        orders,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        countryList: getCountryList(),
        config: req.app.config,
        helpers: req.handlebars.helpers
    });
});

// Update a customer
router.post('/customer/update', async (req, res) => {
    const db = req.app.db;

    if(!req.session.customerPresent){
        res.redirect('/customer/login');
        return;
    }

    const customerObj = {
        company: req.body.company,
        email: req.body.email,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        address1: req.body.address1,
        address2: req.body.address2,
        country: req.body.country,
        state: req.body.state,
        postcode: req.body.postcode,
        phone: req.body.phone
    };

    const schemaResult = validateJson('editCustomer', customerObj);
    if(!schemaResult.result){
        console.log('errors', schemaResult.errors);
        res.status(400).json(schemaResult.errors);
        return;
    }

    // check for existing customer
    const customer = await db.customers.findOne({ _id: getId(req.session.customerId) });
    if(!customer){
        res.status(400).json({
            message: 'Customer not found'
        });
        return;
    }
    // Update customer
    try{
        const updatedCustomer = await db.customers.findOneAndUpdate(
            { _id: getId(req.session.customerId) },
            {
                $set: customerObj
            }, { multi: false, returnOriginal: false }
        );
        indexCustomers(req.app)
        .then(() => {
            // Set the customer into the session
            req.session.customerEmail = customerObj.email;
            req.session.customerCompany = customerObj.company;
            req.session.customerFirstname = customerObj.firstName;
            req.session.customerLastname = customerObj.lastName;
            req.session.customerAddress1 = customerObj.address1;
            req.session.customerAddress2 = customerObj.address2;
            req.session.customerCountry = customerObj.country;
            req.session.customerState = customerObj.state;
            req.session.customerPostcode = customerObj.postcode;
            req.session.customerPhone = customerObj.phone;
            req.session.orderComment = req.body.orderComment;

            res.status(200).json({ message: 'Customer updated', customer: updatedCustomer.value });
        });
    }catch(ex){
        console.error(colors.red('Failed updating customer: ' + ex));
        res.status(400).json({ message: 'Failed to update customer' });
    }
});

// Update a customer
router.post('/admin/customer/update', restrict, async (req, res) => {
    const db = req.app.db;

    const customerObj = {
        company: req.body.company,
        email: req.body.email,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        address1: req.body.address1,
        address2: req.body.address2,
        country: req.body.country,
        state: req.body.state,
        postcode: req.body.postcode,
        phone: req.body.phone
    };

    // Handle optional values
    if(req.body.password){ customerObj.password = bcrypt.hashSync(req.body.password, 10); }

    const schemaResult = validateJson('editCustomer', customerObj);
    if(!schemaResult.result){
        console.log('errors', schemaResult.errors);
        res.status(400).json(schemaResult.errors);
        return;
    }

    // check for existing customer
    const customer = await db.customers.findOne({ _id: getId(req.body.customerId) });
    if(!customer){
        res.status(400).json({
            message: 'Customer not found'
        });
        return;
    }
    // Update customer
    try{
        const updatedCustomer = await db.customers.findOneAndUpdate(
            { _id: getId(req.body.customerId) },
            {
                $set: customerObj
            }, { multi: false, returnOriginal: false }
        );
        indexCustomers(req.app)
        .then(() => {
            const returnCustomer = updatedCustomer.value;
            delete returnCustomer.password;
            res.status(200).json({ message: 'Customer updated', customer: updatedCustomer.value });
        });
    }catch(ex){
        console.error(colors.red('Failed updating customer: ' + ex));
        res.status(400).json({ message: 'Failed to update customer' });
    }
});

// Delete a customer
router.delete('/admin/customer', restrict, async (req, res) => {
    const db = req.app.db;

    // check for existing customer
    const customer = await db.customers.findOne({ _id: getId(req.body.customerId) });
    if(!customer){
        res.status(400).json({
            message: 'Failed to delete customer. Customer not found'
        });
        return;
    }
    // Update customer
    try{
        await db.customers.deleteOne({ _id: getId(req.body.customerId) });
        indexCustomers(req.app)
        .then(() => {
            res.status(200).json({ message: 'Customer deleted' });
        });
    }catch(ex){
        console.error(colors.red('Failed deleting customer: ' + ex));
        res.status(400).json({ message: 'Failed to delete customer' });
    }
});

// render the customer view
router.get('/admin/customer/view/:id?', restrict, async (req, res) => {
    const db = req.app.db;

    const customer = await db.customers.findOne({ _id: getId(req.params.id) });

    if(!customer){
         // If API request, return json
        if(req.apiAuthenticated){
            return res.status(400).json({ message: 'Customer not found' });
        }
        req.session.message = 'Customer not found';
        req.session.message_type = 'danger';
        return res.redirect('/admin/customers');
    }

    // If API request, return json
    if(req.apiAuthenticated){
        return res.status(200).json(customer);
    }

    return res.render('customer', {
        title: 'View customer',
        result: customer,
        admin: true,
        session: req.session,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        countryList: getCountryList(),
        config: req.app.config,
        editor: true,
        helpers: req.handlebars.helpers
    });
});

// customers list
router.get('/admin/customers', restrict, async (req, res) => {
    const db = req.app.db;

    const customers = await db.customers.find({}).limit(20).sort({ created: -1 }).toArray();

    // If API request, return json
    if(req.apiAuthenticated){
        return res.status(200).json(customers);
    }

    return res.render('customers', {
        title: 'Customers - List',
        admin: true,
        customers: customers,
        session: req.session,
        helpers: req.handlebars.helpers,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        config: req.app.config
    });
});

// Filtered customers list
router.get('/admin/customers/filter/:search', restrict, async (req, res, next) => {
    const db = req.app.db;
    const searchTerm = req.params.search;
    const customersIndex = req.app.customersIndex;

    const lunrIdArray = [];
    customersIndex.search(searchTerm).forEach((id) => {
        lunrIdArray.push(getId(id.ref));
    });

    // we search on the lunr indexes
    const customers = await db.customers.find({ _id: { $in: lunrIdArray } }).sort({ created: -1 }).toArray();

    // If API request, return json
    if(req.apiAuthenticated){
        return res.status(200).json({
            customers
        });
    }

    return res.render('customers', {
        title: 'Customer results',
        customers: customers,
        admin: true,
        config: req.app.config,
        session: req.session,
        searchTerm: searchTerm,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers
    });
});

router.post('/admin/customer/lookup', restrict, async (req, res, next) => {
    const db = req.app.db;
    const customerEmail = req.body.customerEmail;

    // Search for a customer
    const customer = await db.customers.findOne({ email: customerEmail });

    if(customer){
        req.session.customerPresent = true;
        req.session.customerId = customer._id;
        req.session.customerEmail = customer.email;
        req.session.customerCompany = customer.company;
        req.session.customerFirstname = customer.firstName;
        req.session.customerLastname = customer.lastName;
        req.session.customerAddress1 = customer.address1;
        req.session.customerAddress2 = customer.address2;
        req.session.customerCountry = customer.country;
        req.session.customerState = customer.state;
        req.session.customerPostcode = customer.postcode;
        req.session.customerPhone = customer.phone;

        return res.status(200).json({
            message: 'Customer found',
            customer
        });
    }
    return res.status(400).json({
        message: 'No customers found'
    });
});

router.get('/customer/login', async (req, res, next) => {
    const config = req.app.config;

    res.render(`${config.themeViews}customer-login`, {
        title: 'Customer login',
        config: req.app.config,
        session: req.session,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers
    });
});

// Extra Pages
router.get('/customer/contact', async (req, res, next) => {
    const config = req.app.config;

    res.render(`${config.themeViews}customer-contact`, {
        title: 'Contact',
        config: req.app.config,
        session: req.session,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        showFooter: true
    });
});
// router.get('/customer/aboutus', async (req, res, next) => {
//     const config = req.app.config;

//     res.render(`${config.themeViews}aboutus`, {
//         title: 'About Us',
//         config: req.app.config,
//         session: req.session,
//         message: clearSessionValue(req.session, 'message'),
//         messageType: clearSessionValue(req.session, 'messageType'),
//         helpers: req.handlebars.helpers,
//         showFooter: true
//     });
// });
router.get('/customer/forgot-password', async (req, res, next) => {
    const config = req.app.config;

    res.render(`${config.themeViews}customer-forgot-password`, {
        title: 'Forgot Password',
        config: req.app.config,
        session: req.session,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        helpers: req.handlebars.helpers,
        showFooter: true
    });
});

router.get('/customer/privacy', (req, res) => {
    const config = req.app.config;

    res.render(`${config.themeViews}privacy`, {
      title: 'Privacy Policy',
      page: req.query.path,
      config,
      session: req.session,
      message: clearSessionValue(req.session, 'message'),
      messageType: clearSessionValue(req.session, 'messageType'),
      helpers: req.handlebars.helpers,
      showFooter: 'showFooter'
    });
});

router.get('/customer/delivery', (req, res) => {
    const config = req.app.config;

    res.render(`${config.themeViews}delivery`, {
      title: 'Delivery Information',
      page: req.query.path,
      config,
      session: req.session,
      message: clearSessionValue(req.session, 'message'),
      messageType: clearSessionValue(req.session, 'messageType'),
      helpers: req.handlebars.helpers,
      showFooter: 'showFooter'
    });
});

router.get('/customer/terms', (req, res) => {
    const config = req.app.config;

    res.render(`${config.themeViews}terms`, {
      title: 'Terms & Conditions',
      page: req.query.path,
      config,
      session: req.session,
      message: clearSessionValue(req.session, 'message'),
      messageType: clearSessionValue(req.session, 'messageType'),
      helpers: req.handlebars.helpers,
      showFooter: 'showFooter'
    });
});

// login the customer and check the password
router.post('/customer/login_action', async (req, res) => {
    const db = req.app.db;
    console.log("Req phone Number",req.body.loginPhone);
    const customer = await db.customers.findOne({ phone: req.body.loginPhone });
    // check if customer exists with that email
    if(customer === undefined || customer === null){
        res.status(400).json({
            message: 'A customer with that Phone does not exist.'
        });
        return;
    }
    // we have a customer under that email so we compare the password
    bcrypt.compare(req.body.loginPassword, customer.password)
    .then((result) => {
        if(!result){
            // password is not correct
            res.status(400).json({
                message: 'Access denied. Check password and try again.'
            });
            return;
        }

        // Customer login successful
        req.session.customerPresent = true;
        req.session.customerId = customer._id;
       // req.session.customerEmail = customer.email;
        req.session.customerCompany = customer.company;
        req.session.customerFirstname = customer.firstName;
        req.session.customerLastname = customer.lastName;
        req.session.customerAddress1 = customer.address1;
        req.session.customerAddress2 = customer.address2;
        req.session.customerCountry = customer.country;
        req.session.customerState = customer.state;
        req.session.customerPostcode = customer.postcode;
        req.session.customerPhone = customer.phone;

        res.status(200).json({
            message: 'Successfully logged in',
            customer: customer
        });
    })
    .catch((err) => {
        res.status(400).json({
            message: 'Access denied. Check password and try again.'
        });
    });
});

// customer forgotten password
router.get('/customer/forgotten', (req, res) => {
    res.render('forgotten', {
        title: 'Forgotten',
        route: 'customer',
        forgotType: 'customer',
        config: req.app.config,
        helpers: req.handlebars.helpers,
        message: clearSessionValue(req.session, 'message'),
        messageType: clearSessionValue(req.session, 'messageType'),
        showFooter: 'showFooter'
    });
});

// forgotten password
router.post('/customer/forgotten_action', apiLimiter, async (req, res) => {
    const db = req.app.db;
    const config = req.app.config;
    const passwordToken = randtoken.generate(30);

    // find the user
    const customer = await db.customers.findOne({ email: req.body.email });
    try{
        if(!customer){
            // if don't have an email on file, silently fail
            res.status(200).json({
                message: 'If your account exists, a password reset has been sent to your email'
            });
            return;
        }
        const tokenExpiry = Date.now() + 3600000;
        await db.customers.updateOne({ email: req.body.email }, { $set: { resetToken: passwordToken, resetTokenExpiry: tokenExpiry } }, { multi: false });
        // send forgotten password email
        const mailOpts = {
            to: req.body.email,
            subject: 'Forgotten password request',
            body: `You are receiving this because you (or someone else) have requested the reset of the password for your user account.\n\n
                Please click on the following link, or paste this into your browser to complete the process:\n\n
                ${config.baseUrl}/customer/reset/${passwordToken}\n\n
                If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        // send the email with token to the user
        // TODO: Should fix this to properly handle result
        sendEmail(mailOpts.to, mailOpts.subject, mailOpts.body);
        res.status(200).json({
            message: 'If your account exists, a password reset has been sent to your email'
        });
    }catch(ex){
        res.status(400).json({
            message: 'Password reset failed.'
        });
    }
});

// reset password form
router.get('/customer/reset/:token', async (req, res) => {
    const db = req.app.db;

    // Find the customer using the token
    const customer = await db.customers.findOne({ resetToken: req.params.token, resetTokenExpiry: { $gt: Date.now() } });
    if(!customer){
        req.session.message = 'Password reset token is invalid or has expired';
        req.session.message_type = 'danger';
        res.redirect('/forgot');
        return;
    }

    // show the password reset form
    res.render('reset', {
        title: 'Reset password',
        token: req.params.token,
        route: 'customer',
        config: req.app.config,
        message: clearSessionValue(req.session, 'message'),
        message_type: clearSessionValue(req.session, 'message_type'),
        show_footer: 'show_footer',
        helpers: req.handlebars.helpers
    });
});

// reset password action
router.post('/customer/reset/:token', async (req, res) => {
    const db = req.app.db;

    // get the customer
    const customer = await db.customers.findOne({ resetToken: req.params.token, resetTokenExpiry: { $gt: Date.now() } });
    if(!customer){
        req.session.message = 'Password reset token is invalid or has expired';
        req.session.message_type = 'danger';
        return res.redirect('/forgot');
    }

    // update the password and remove the token
    const newPassword = bcrypt.hashSync(req.body.password, 10);
    try{
        await db.customers.updateOne({ email: customer.email }, { $set: { password: newPassword, resetToken: undefined, resetTokenExpiry: undefined } }, { multi: false });
        const mailOpts = {
            to: customer.email,
            subject: 'Password successfully reset',
            body: 'This is a confirmation that the password for your account ' + customer.email + ' has just been changed successfully.\n'
        };

        // TODO: Should fix this to properly handle result
        sendEmail(mailOpts.to, mailOpts.subject, mailOpts.body);
        req.session.message = 'Password successfully updated';
        req.session.message_type = 'success';
        return res.redirect('/checkout/payment');
    }catch(ex){
        console.log('Unable to reset password', ex);
        req.session.message = 'Unable to reset password';
        req.session.message_type = 'danger';
        return res.redirect('/forgot');
    }
});

// logout the customer
router.post('/customer/logout', (req, res) => {
    // Clear our session
    clearCustomer(req);
    res.status(200).json({});
});

// logout the customer
router.get('/customer/logout', (req, res) => {
    // Clear our session
    clearCustomer(req);
    res.redirect('/customer/login');
});

module.exports = router;
