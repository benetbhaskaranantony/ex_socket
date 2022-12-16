require('rootpath')();
const express = require('express');
const app = express();
var server = require('http').Server(app);
var io = require('socket.io')(server);
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const errorHandler = require('_middleware/error-handler');
var methods = require('./models/methods');
var ExamUser = require('./models/examuser');
var SubUser = require('./models/subuser');
var Exam = require('./models/exam')
var Pid = require('./models/pid')
var jwt = require('jsonwebtoken');
var ExamService = require('./Service/examuser');
const dotenv = require('dotenv')
dotenv.config()
const url = 'https://www.pmgdisha.in/app/login';
const { PendingXHR } = require('pending-xhr-puppeteer');
const mongoose = require("mongoose");
const axios = require('axios')
const puppeteer = require('puppeteer');
const fs = require('fs');
var builder = require('xmlbuilder');
var appurl = 'ravatti.ddns.net'
const xxurl = 'http://'+appurl+':7000/'

var mongoDB = 'mongodb://pmg:123456@'+appurl+':27017/pmg?authSource=pmg';
var SECRET_HASH ='YmVuZXRiaGFza2FyYW5hbnRvbnkhQMKjJCVeJiooKQ=='
const createTestUser = require('_helpers/create-test-user');
const Server = require('socket.io');
const bcrypt = require('bcryptjs');
const { result } = require('@hapi/joi/lib/base');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors({ origin: (origin, callback) => callback(null, true), credentials: true }));
app.use('/users', require('./users/users.controller'));
app.use('/api-docs', require('_helpers/swagger'));
app.use(errorHandler);



async function run(examID,Epassword,parent,socket){
await io.to(socket).emit('exam','Get Started...')
    if (parent != null) {
        ExamUser.findOne({ email: parent },async (err, Sub) => {
            //console.log(Sub)
           await io.to(socket).emit('exam','Authenicating....')
            if (Sub != null) {
                Exam.findOne({ username: examID }, async(err, exam) => {
                    if (exam != null) {
                      //  res.sendFile(path.join(__dirname, '/public/progressbar.html'));

                       const response= await benet(examID, Epassword,socket);
                            ////console.log(`vdjvhvhchvch ${response}`)
                           // res.redirect(response);
                        
                        //io.emit('exam', 'Pmg Login')
                       await io.to(socket).emit('exam', response)
                        await io.to(socket).emit('examResult',response)

                    } else {

                        if (Sub.bal > 1) {
                            var newbal = Sub.bal - 1;
                            ExamUser.updateOne({ email: parent }, { $set: { bal: newbal } }, async(err, balu) => {
                                const exam = new Exam({
                                    username : examID,
                                    password:Epassword,
                                    subAdmin:parent

                                })
                                exam.save()
                                const response = await benet(examID, Epassword,socket);
                               // io.emit('exam', 'Pmg Login')
                                await io.to(socket).emit('exam', response)
                                await io.to(socket).emit('examResult',response)
                           // res.redirect(response);
                            })


                        } else {
                            await io.to(socket).emit('exam', 'Get More Tokens')
                         //   io.emit('examResult',response)
                        }
                    }
                })
            } else {
                await io.to(socket).emit('exam','Something went wrong')
            }
        })



    } else {
       await io.to(socket).emit('exam','Restart the App')
    }
}
async function benet(username, password,socket) {
    return new Promise(function(resolve, reject) {

  // await io.to(socket).emit('exam','Automation Start')
    try {
        puppeteer.launch({
            headless: true,
            devtools: true,
            args: ['--no-sandbox'],

        }).then(async browser => {

            process.on('uncaughtException',async (err) => {
       await io.to(socket).emit('exam', 'Error Start Again')
      await browser.close();
    })
    process.on('ProtocolError',async (err) => {
       await io.to(socket).emit('exam', 'Error Start Again')
      await  browser.close();
    })
    process.on('ProtocolError',async (Error) => {
       await io.to(socket).emit('exam', 'Error Start Again')
      await  browser.close();
    })

            const page = await browser.newPage();
            const pendingXHR = new PendingXHR(page);
            await page.setViewport({ width: 1366, height: 768 })
            await page.goto(url).catch(() => { });
            await io.to(socket).emit('exam','Launch URL')
            await page.setExtraHTTPHeaders({
                'Accept-Language': 'en-US,en;q=0.9'
            });
           await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36');
            await page.waitForSelector('#inputEmail')
            await page.type('#inputEmail', username, { delay: 100 })
            
            await page.waitForSelector('#lgpass1')
            await page.type('#lgpass1', password, { delay: 100 })
            const logi = await page.waitForSelector('#loginForm > input.btn.btn-default.btn-block', {
                timeout: 1000
            })

            await page.click('#loginForm > input.btn.btn-default.btn-block')
            if (logi) {
               await io.to(socket).emit('exam','Entering Login credentials')
            } else {
               await io.to(socket).emit('exam','Logged Failed')
            }
            await io.to(socket).emit('exam','Pmg Login Form Process')
            await page.waitForTimeout(2000);
            await page.goto('https://www.pmgdisha.in/app/student/dashboard')
            const [button] = await page.$x("//a[contains(., 'TAKE TEST')]");
            if (button) {
                await button.click();
                await io.to(socket).emit('exam','Successfully Logged IN')
            } else {
                await io.to(socket).emit('exam', 'LoggIn Failed')
                await browser.close();
            }
            await page.waitForTimeout(2000);
            const [button1] = await page.$x("//button[contains(., 'VERIFY')]");
            if (button1) {
                await button1.click();
                await io.to(socket).emit('exam','Photo verified')
            } else {
                await io.to(socket).emit('exam','Pmg Login Form Process')
            }
            
            await page.waitForTimeout(9000);

            let pages = await browser.pages();
            const page1 = await pages[2]
            await page1.waitForSelector('#submit')
            await page1.click('#submit')
            await page1.waitForTimeout(2000);
            await page1.evaluate(() => {
                document.querySelector('select[name="invigilatorId"] > option:nth-child(2)').selected = true;
            });
            //console.log('Select Invaligator')
            await page1.waitForSelector('#submit')
            await page1.click('#submit')
            await page1.waitForTimeout(1000);
            await page1.waitForSelector('button[type="button"]')
            await page1.click('button[type="button"]')
            await io.to(socket).emit('exam','Invaligator selected')
            await page1.setRequestInterception(true)
            //console.log('Invalicator Thumb Staart')
            page1.on('request', async request => {
                //console.log(request.url())
                const logout = request.url() === 'https://pmgdisha.in/app/logout'
                const isGraphQL = request.url() === 'http://localhost:11101/'
                const capture = request.url() === 'http://localhost:11101/rd/capture'
                const capture_url = 'http://localhost:11101/rd/capture/' // + data._id;
                const capture_urlop = 'http://localhost:11101/rd/captureop/' // + data._id;
                const callb = request.url() === 'https://csc-gov.pmgdisha.in/browser-callback'
                const texturl = request.url() === 'https://www.pmgdisha.in/app/student/take-testt'
                const msb = 'https://tests.mettl.com/take-test?'

                if(request.url().includes(msb)){
                    resolve(request.url());
                    await browser.close();
                   // io.emit('exam','Pmg Login')
                }


                if (callb) {
                    const post_data = request.postData()
                    let result = post_data.substring(9);
                    let result1 = result.slice(0, -25)
                    const response1 = await axios.get(xxurl + result1);
                    if (response1.data == 1) {
                        page.goto(__dirname + '/error.html')
                    }
                    return request.continue({
                        url: request.url(),
                        method: request.method(),
                        headers: request.headers(),
                        postData: 'res_data=' + response1.data + '&client_id=CSC-PMG&param='
                    });
                }
                if (isGraphQL) {
                    try {
                        return request.continue({
                            url: 'http://localhost:11101',
                            method: 'GET',
                            headers: {
                                'Content-Type': 'text/xml' // replace headers
                            }
                        });
                        request.respond({
                            method: 'RDSERVICE',
                            body: data
                        });
                    } catch {}
                }
                if (capture && request.method() == 'CAPTURE') {
                    try {
                        return request.continue({
                            url: capture_url,
                            method: 'GET',
                            headers: {
                                'Content-Type': 'text/xml' // replace headers
                            }
                        });
                        request.respond({
                            method: 'CAPTURE',
                            body: data
                        });
                    } catch {}
                }
                if (capture && request.method() == 'OPTIONS') {
                    try {
                        return request.continue({
                            url: capture_urlop,
                            method: 'GET',
                            headers: {
                                'Content-Type': 'text/xml' // replace headers
                            }
                        });
                        request.respond({
                            method: 'CAPTURE',
                            body: data
                        });
                    } catch {}
                }
                if (logout) {
                    browser.close()
                    kickstart();
                } else {
                    request.continue();
                }
            })
            const [button2] = await page.$x("//button[contains(., 'Next')]");
            if (button2) {
                await button2.click();
                await io.to(socket).emit('exam','Starting Thumb Authentication')
            } else {
                await io.to(socket).emit('exam','Thumb Authentication In process')
            }
            await page1.waitForTimeout(5000)
            await page1.waitForSelector('#check')
            await page1.click('#check')
            await io.to(socket).emit('exam','Invaligator Thumbp Check')
            await page1.waitForTimeout(1000)
            await page1.waitForSelector('#start_cap')
            await page1.click('#start_cap')
            await page1.waitForTimeout(5000);
            await io.to(socket).emit('exam','Invaligator Thumbp Capture')
            await page1.waitForSelector('button[type="button"]')
            await page1.click('button[type="button"]')
            await io.to(socket).emit('exam','Invaligator Thumbp Captured')
            await page1.waitForTimeout(5000)
            //console.log('Student Thumb Start')
            await page1.waitForSelector('#check')
            await io.to(socket).emit('exam','student thumb check')
            await page1.click('#check')
            await page1.waitForTimeout(2000)
            await page1.waitForSelector('#start_cap')
            await page1.click('#start_cap')
            await io.to(socket).emit('exam','student thumb Captured')
            await page1.waitForTimeout(5000)
//await page1.waitForNavigation()
            //console.log('ssss')
            await page1.waitForTimeout(3000)

            await io.to(socket).emit('exam','Generating Exam Link')
                await page1.click('#titlewebcam')
                await page1.waitForTimeout(2000)

              const code1 = await page1.$x('//script[contains(., "sebs")]')
  const content = await page1.evaluate(el => el.innerHTML, code1[0]);
  var s = content;
  s = s.substring(0, s.indexOf('&agent=chrome,'));
  var str = s;
  str = str.substring(str.indexOf("launchUri(") + 11);
  //console.log(str)
            resolve(str)
            //await browser.close();
             
           
            
            
        })
    } catch {
        return 1
    }
})
}


app.get('/rd/capture/', (req, res) => {

    Pid.findOne({},(err,result)=>{
        //console.log(result.key)
    
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "RDSERVICE,DEVICEINFO,CAPTURE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    res.status(200);
    res.send(result.key);
})
 //   res.send('<?xml version="1.0"?><PidData><Resp errCode="0" errInfo="Success." fCount="1" fType="0" nmPoints="35" qScore="60" /><DeviceInfo dpId="MANTRA.MSIPL" rdsId="MANTRA.WIN.001" rdsVer="1.0.6" mi="MFS100" mc="MIIEGDCCAwCgAwIBAgIEAehIADANBgkqhkiG9w0BAQsFADCB6jEqMCgGA1UEAxMhRFMgTWFudHJhIFNvZnRlY2ggSW5kaWEgUHZ0IEx0ZCA3MUMwQQYDVQQzEzpCIDIwMyBTaGFwYXRoIEhleGEgb3Bwb3NpdGUgR3VqYXJhdCBIaWdoIENvdXJ0IFMgRyBIaWdod2F5MRIwEAYDVQQJEwlBaG1lZGFiYWQxEDAOBgNVBAgTB0d1amFyYXQxHTAbBgNVBAsTFFRlY2huaWNhbCBEZXBhcnRtZW50MSUwIwYDVQQKExxNYW50cmEgU29mdGVjaCBJbmRpYSBQdnQgTHRkMQswCQYDVQQGEwJJTjAeFw0yMjEwMjIxMDI0MzJaFw0yMjExMjExMDM5MzJaMIGwMSUwIwYDVQQDExxNYW50cmEgU29mdGVjaCBJbmRpYSBQdnQgTHRkMR4wHAYDVQQLExVCaW9tZXRyaWMgTWFudWZhY3R1cmUxDjAMBgNVBAoTBU1TSVBMMRIwEAYDVQQHEwlBSE1FREFCQUQxEDAOBgNVBAgTB0dVSkFSQVQxCzAJBgNVBAYTAklOMSQwIgYJKoZIhvcNAQkBFhVzdXBwb3J0QG1hbnRyYXRlYy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOkIxh+uKzyzqXd4NSKktopkglZsOTL1GcAUT/ZX17SNj/ndhdWlVhUh+PnpZ0f1AicqHhSZaYanVsAqEXfdSfiX7Uz5IY8O6DyI+lBgoXZnaUNCSXnl4ekMfcSAhWnLxK8OzYyGHuJMX7t/MKvhgaJWCTNZc0Mpr59tgmVgEYXJm01WbaxVrKMWPqK2AzAChAPcexbqilJK9THfAp5/VxR349zrgTtCyOB+SD4fIprTPPNb8PzEW36XzwLOOka/UrjygIit57QNgyQDG+PPKtZoHVW1xIf1cl4gAQYKjyTG1BgHrpAUiQTHpEjK100fLqAwU2q7UPB3TjFg7UzaujAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAL++y8o+MFJB2S1DI7SJ1gZLvfCGMWpxC+BOh1IdDSd7rj8XuXdG3hDDqmSYAlXJiGgafsoDHXw4EAgIF3iMRGMmBhSe/BGbQh5as9N4YgGcIdcDiNtvuo4mJT66BMFP5orP4ASC0XDEd41FXtChWm4gVUDEpKfzdWoT85TaQDZ1rB/sKcF5ZKFixDodgfkG+9jJRklV8apmq680a0OXmdP/HGHbsj+5b4WgX4qb4tF9BA+K8EnHjnD+sIT33MihxyEEDKoL4GUGSjVFya4QurxZB5cDqBiNB/0xgJfXWwKnrJMSA6nbA9roSl94O0o6tFYVqBhYoBmcTX+SQajMJFs=" dc="d988d827-aefc-49b9-bfbe-9191029d2fe1"><additional_info><Param name="srno" value="4201609" /><Param name="sysid" value="6EAFEBF2C55D837FBFF0" /><Param name="ts" value="2022-10-22T16:10:29+05:30" /></additional_info></DeviceInfo><Skey ci="20250923">mu3yHu/ksgRs3Uu8ep1kAR/Cd0xEm4TPqLY2P38tii7PcJFIHFgzfclRwuFmG5iFPuxQH55Tz+dt/oqMaO6om4lKKKffj0N4CGpPkUc5grGig0Nk7Lp3eHHiEB2EYwnDmNw2z45nreNYKsUGEoIXs98xA+DcI9UVhE8wGM0io6OAlTS8OVUQtIP2AMjDSj8QnIRu44Lh963rQqb32y37hsVZ69kI2kC/2gBFyDbDf6Twc90OlmpcnuVDcZArLuhpak5zF4MkQ3CSluqg6tUWJZT/Ea9JLhAAM3CSA7+zGoex5LRBLqsJ/95qS5kXoFGX5CqzRW+KPpA8+npVw5JoMw==</Skey><Hmac>USLfGV5HB95D6+L7doQHgZEruI6h36fyWY4gp2fn3HiHFP2EFinCcDXNcrEYplZB</Hmac><Data type="X">MjAyMi0xMC0yMlQxNjoxMDoyOdZzXsHvWvfINsrAbYJJECl++6S6GHF6hBsukk+UmJmxfhGMMJssBbb8BbsGwyqT69f+fRC6UIcoepTrPw8q5h0e96vOXmHP5ZymSBT6O5rNN1VhVsASJc66D0BtdlKGqbfzvvBVHfjB6H9ag8yMFkkRtv72vWUjUE0vbPwo8B8tdv1JXgO7xmhdeTfNF2kvhwu6lbQOUB7muOPgmydegakqEaS3fTvN99TCHKRzo4AhZ42O17U2bCA57pQ4Zyx4SYrfwDEDBYrFnD2dXeVtpr1H2zpu42D80aV7NWvWjRY4T+5xrhIOBUUGd8FJWSEsQJ8FwjDVlLin9367x4xAd+y6zS/x48l2AseXlTgGJ6cwXhXi95ZsRiUYabN70Dj7VxQaaezM/BCiRH76xWhEJQgIVnVvOukWWt7ImimcCG2ZWy7taUHX7Ud9uF4QRQ/ceGQJbsORc5aCZoIYDCaOovvMNq93tar/XqMGmw9yEjYT6pD37S6GwNw92Gx2qriJlmmWVDXNSyoKsIMpPctJ8isYDZJumRWDSV520/sni41TwzJOf/5YU12B2zwsUxlHALbQLPuZ/D5b3ehilTs+HniB5F6YcoDxXlGWG1au5b0hGK/g1N2aOsNKm9NnDfwY6gOrJdDEauOlJDdFx1k/a+5lS0qmioz1bHMIg/OFtbg3QRPURkv6DTloXAIGNIuDX7If6w846qohrhxqz4wo0sLDdqGECyVLff5NMtkaTq4U7mi6xDz9l+en1mBweMATEZTzzFGVY+ay6oqaWbnKetUdeiIl72PoGN4hA5jAOTJDLfKVWyOrqbEZZvmn86fIM1t03MHyVgx3MpDSdTNekZsjPzw+V4TWO4Hl97IjWsES0r5xAa3x2MHYb9DqE9umHaHiTmSqPqkL5Zz1gDMBqEryzLJl/txkrEmTYCEi/9qegf1nZwNnQKJnyaV1f4UO86IGCG1DeBha7PBrDfZixfL1Mc9i/1cCRrCW0mUP7mDHl8Up0g3BjeUrLlCPtMPt76dEBmzV4qxQkMzmzCrs/umdqckMA3OsZR3rHbTh5OzDMMD++ngi/8843R+3uUQOuDFQDJsy2o7rZQe7I7PvXiRYmYD7fj26ar6qOA17WBJGR5RyQIxhh6IaT5RoiAalS1cx6rU=</Data></PidData>');

});
app.get('/rd/captureop/', (req, res) => {
Pid.findOne({},(err,result)=>{
    //console.log(result.key)

    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "RDSERVICE,DEVICEINFO,CAPTURE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    res.status(200);
    res.send(result.key);
})

});

app.get('/', (req, res) => {
    var xml1 = builder.create('RDService').att({ 'status': 'READY', 'info': 'Secure Mantra Authentication Vendor Device Manager' })
        .ele('Interface', { 'id': 'DEVICEINFO', 'path': '/rd/info' })
        .up()
        .ele('Interface', { 'id': 'CAPTURE', 'path': '/rd/capture' })
        .end({ pretty: true });
    res.set('Access-Control-Allow-Origin', '*')
    res.set('Access-Control-Allow-Methods', 'RDSERVICE,DEVICEINFO,CAPTURE')
    res.header('Access-Control-Allow-Header', 'Content-Type')
    res.set('Content-Type', 'text/xml');
    res.status(200);
    res.send(xml1);
})

app.get('/resp', (req, res) => {
    axios.get(uri, { headers: { "Authorization": token, "Accept": "application/json" } })
        .then((response => {
            res.send(response.data)
        }))
        .catch((error) => {
            //console.log(error);
        })

})


io.on('connection',async function (socket) {
   
    
    
    // socket.on('login', async function (data) {
    //     const getMac = await methods.getMac(data.token)
    //     //console.log(data.userName)
    //    ExamUser.findOne({ "mac": getMac.toString() }, async (err, result) => {
    //        if (!err && result != null) {
    //            if (result.isActive == 1) {
    //                if (data.userName === result.username) {
    //                    var hash = bcrypt.compareSync(data.password, result.password);
    //                    if (hash) {
    //                        socket.join(data.userName);
    //                      //   socket.join(room.name);
    //     console.log(socket.id)
    //     console.log(io.sockets.adapter.rooms);
    //     const clients = io.sockets.adapter.rooms[data.userName];
    //     console.log(clients)
    //   //  to get the number of clients in this room
    //     const numClients = clients ? Object.keys(clients).length : 0;
    //     console.log(numClients)
    //     // to just emit the same event to all members of a room
    //     // io.to('benet').emit('message', 'kunna');
    //                        var jsonData = JSON.stringify({ "status": true, "msg": "Sucess", "data": result });
    //                        var token = jwt.sign(jsonData, SECRET_HASH);
    //                        io.to(socket.id).emit('login', token)
    //                    } else {
    //                        var jsonData = JSON.stringify({ "status": false, "msg": "Wrong Password", "data": null });
    //                        var token = jwt.sign(jsonData, SECRET_HASH);

    //                        io.to(socket.id).emit('login', token)
    //                    }
    //                } else {
    //                    var jsonData = JSON.stringify({ "status": false, "msg": "Wrong PC or Wrong User name", "data": null });
    //                    var token = jwt.sign(jsonData, SECRET_HASH);

    //                    io.to(socket.id).emit('login', token)
    //                }
    //            } else {
    //                 var jsonData = JSON.stringify({ "status": false, "msg": "User Blocked - Contact Admin", "data": null });
    //                    var token = jwt.sign(jsonData, SECRET_HASH);

    //                    io.to(socket.id).emit('login', token)
    //            }
                
    //        } else if (result == null) {
    //                                   var jsonData = JSON.stringify({"status":false,"msg":"User not Registered","data":null});
    //            var token = jwt.sign(jsonData, SECRET_HASH);

    //            io.to(socket.id).emit('login',token)
    //        }
    //        else {
    //                    var jsonData = JSON.stringify({"status":false,"msg":"User not Registered","data":null});
    //                    var token = jwt.sign(jsonData, SECRET_HASH);
    //             io.to(socket.id).emit('login',token)
    //         }
    //     })
        
    // })

    // socket.on('adminlogin', async function (data) {
    //     const getMac = await methods.getMac(data.token)
    //    ExamUser.findOne({ "mac": getMac.toString() }, async (err, result) => {
    //        if (!err && result != null) {
               
    //                if (data.userName === result.username) {
    //                    var hash = bcrypt.compareSync(data.password, result.password);
    //                    if (hash) {
    //                        var jsonData = JSON.stringify({ "status": true, "msg": "Sucess", "data": result });
    //                        var token = jwt.sign(jsonData, SECRET_HASH);
    //                        socket.emit('adminlogin', token)
    //                    } else {
    //                        var jsonData = JSON.stringify({ "status": false, "msg": "Wrong Password", "data": null });
    //                        var token = jwt.sign(jsonData, SECRET_HASH);

    //                        socket.emit('adminlogin', token)
    //                    }
    //                } else {
    //                    var jsonData = JSON.stringify({ "status": false, "msg": "Wrong PC or Wrong User name", "data": null });
    //                    var token = jwt.sign(jsonData, SECRET_HASH);

    //                    socket.emit('adminlogin', token)
    //                }
               
                
    //        } else if (result == null) {
    //            var jsonData = JSON.stringify({"status":false,"msg":"User not Registered","data":null});
    //            var token = jwt.sign(jsonData, SECRET_HASH);

    //            socket.emit('adminlogin',token)
    //        }
    //        else {
    //                    var jsonData = JSON.stringify({"status":false,"msg":"User not Registered","data":null});
    //                    var token = jwt.sign(jsonData, SECRET_HASH);
    //             socket.emit('adminlogin',token)
    //         }
    //     })
        
    // })

    socket.on('exam', async function (data) {
        
                   await run(data.examID,data.Epassword,data.parent,socket.id)
            
    })
    
    socket.on('check1', async function (data) {
       // console.log(data);
      //  const getMac = await methods.getMac(data.token)
        ExamUser.findOne({ "username": data.username }, async (err, result) => {
           // console.log(result)
             if (!err && result != null) {
               if (result.isActive == 1) {
                       var hash = bcrypt.compareSync(data.password, result.password);
                   if (hash) {
                            socket.join(data.userName);
                         //   socket.join(room.name);
      //  console.log(socket.id)
      //  console.log(io.sockets.adapter.rooms);
        const clients = io.sockets.adapter.rooms[data.userName];
                       console.log(clients) 
                       if (clients.length > 1) {
                        var client = clients.sockets;
                        var clientKey = Object.keys(client)
                       //  console.log(client)
                        for (i = 0; i <= clientKey.length; i++) {
                         //   console.log(clientKey[i])
                            if (clientKey[i] != socket.id) {
                               
                                await io.to(clientKey[i]).emit('logout', 'now')
                            }
                        }
                    } else {
                        //  console.log(socket.id)
                    }
      //  to get the number of clients in this room
        const numClients = clients ? Object.keys(clients).length : 0;
       // console.log(numClients)
                           var jsonData = JSON.stringify({ "status": true, "msg": "Sucess", "data": result });
                           var token = jwt.sign(jsonData, SECRET_HASH);
                           io.to(socket.id).emit('login', token)
                       } else {
                           var jsonData = JSON.stringify({ "status": false, "msg": "Wrong Password", "data": null });
                           var token = jwt.sign(jsonData, SECRET_HASH);

                           io.to(socket.id).emit('login', token)
                       }
                  
               } else {
                    var jsonData = JSON.stringify({ "status": false, "msg": "User Blocked - Contact Admin", "data": null });
                       var token = jwt.sign(jsonData, SECRET_HASH);

                       io.to(socket.id).emit('login', token)
               }
                
           } else if (result == null) {
              var jsonData = JSON.stringify({"status":false,"msg":"1","data":null});
               var token = jwt.sign(jsonData, SECRET_HASH);

               io.to(socket.id).emit('login',token)
           }
           else {
                       var jsonData = JSON.stringify({"status":false,"msg":"User not Registered","data":null});
                       var token = jwt.sign(jsonData, SECRET_HASH);
                       io.to(socket.id).emit('login',token)
            }
        })
        
})       

    socket.on('enroll', async function (data) {
        //console.log(data)
        var salt = bcrypt.genSaltSync(10);
        var hash = bcrypt.hashSync(data.password, salt);
        ExamUser.findOne({ "email": data.parent, "role": "sub" }, (err, result)=>{
            if (!err && result != null) {
                ExamUser.findOne({ "username": data.userName }, (err, res) => {
                    if (!err && res == null) {
                        const examuser = new ExamUser({
                        "username": data.userName,
                        "password": hash,
                        "isActive": 0,
                            "email": data.parent,
                            "role": "user",
                        "socket":socket.id
        })
                        examuser.save();
                        var jsonData = JSON.stringify({ "status": true, "msg": "Sucess", "data": null });
                        var token = jwt.sign(jsonData, SECRET_HASH);
                        io.to(socket.id).emit('enroll',token)
                    } else {
                        var jsonData = JSON.stringify({ "status": false, "msg": "User Not Available", "data": null });
                        var token = jwt.sign(jsonData, SECRET_HASH);
                        io.to(socket.id).emit('enroll',token)
                    }
                })
                
            } else {
                var jsonData = JSON.stringify({ "status": false, "msg": "Enter Correct Supervoiser Email", "data": null });
                        var token = jwt.sign(jsonData, SECRET_HASH);
                        io.to(socket.id).emit('enroll',token)
                
            }
        })
        
})      
//     socket.on('exam', async function (data) {
//         const getMac = await methods.getMac(data.token)
//         ExamUser.findOne({ "mac": getMac.toString() }, async (err, result) => {
//             if (!err && result != null) { }
//             else if (result == null) {
//             var jsonData = JSON.stringify({"status":false,"msg":"User not Registered","data":null});
//             var token = jwt.sign(jsonData, SECRET_HASH);
//             socket.emit('exam',token)
//            }
//            else {
//            var jsonData = JSON.stringify({"status":false,"msg":"User not Registered","data":null});
//            var token = jwt.sign(jsonData, SECRET_HASH);
//            socket.emit('exam',token)
//             }
//         })
// })       

      socket.on('connect', async function (data) {
        //console.log(data);
        const getMac = await methods.getMac(data)
        //console.log(`sgdfgsdf ${getMac}`)
    })  
    
    //receive message
    // socket.on('message', async function(msg) {
    //     //console.log(msg);
    //    // const getMac = await methods.getMac(msg.valv)
    //     //console.log(`sgdfgsdf ${getMac}`)
    //     ExamUser.findOne({ mac: getMac }, (err, result)=>{
    //         if (!err && result != null) {
                
    //             ExamUser.updateOne({ mac: getMac }, { $set: { socket: socket.id } }, (err, resu)=> {
    //                 //console.log(resu);
    //             })
    //         }
    //     })


   // });

    // socket.emit('message', 'Updates');
});

// start server
const port = process.env.NODE_ENV === 'production' ? (process.env.PORT || 80) : 11101;
server.listen(port, () => {
   // console.log('Server listening on port ' + port);
});
