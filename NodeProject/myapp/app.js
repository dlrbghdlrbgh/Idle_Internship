/**
 * --------------------------------------------------------------------------------------------------------
 * 모듈/필드 변수 부분
 * --------------------------------------------------------------------------------------------------------
 */
const express = require("express")
const cookieParser = require("cookie-parser")
const mailer = require("./config/mail_config.js")
const databaseConfig = require("./config/database_config.js")
const sessionConfig = require("./config/session_config.js")
const crypto = require("./config/crypto_config.js")
const app = express()
const port = 3000
const transporter = mailer.init()
const conn = databaseConfig.init()
databaseConfig.connect(conn)
app.use(express.json())
app.use(sessionConfig.init())
app.use(cookieParser())

/**
 * --------------------------------------------------------------------------------------------------------
 * 함수 구현 부분
 * --------------------------------------------------------------------------------------------------------
 */

/**
 * 이메일 인증 메일 발송 함수
 * @param receiverEmail : 수신 이메일
 * @param contents : string url
 */
async function sendEmail(receiverEmail, contents) {
    return await new Promise((resolve, reject) => {
        resolve({
            from: mailer.senderEmail(),
            to: receiverEmail,
            subject: "[idea platform] Regarding email authentication.",
            text: contents
        })
    })
}

/**
 * 회원 중복조회 함수
 * @param isEmail 회원 테이블에서 조회한 결과
 * @returns {number} 200 = 중복된 이메일 없음, 401 = 이메일 중복
 */
async function memberCheck(isEmail) {
    return await new Promise((resolve, reject) => {
        resolve(isEmail === null ? 200 : 401)
    })
}

/**
 * 특수 문자 제거
 * @param str
 * @returns {*}
 */
async function regExp(str) {
    return await new Promise((resolve, reject) => {
        let reg = /[\{\}\[\]\/?.,;:|\)*~`!^\-_+<>@\#$%&\\\=\(\'\"]/gi
        resolve(reg.test(str) ? str.replace(reg, "") : str)
    })
}

/**
 * --------------------------------------------------------------------------------------------------------
 * API 구현 부분
 * --------------------------------------------------------------------------------------------------------
 */

/**
 * 사용자 API
 */
// 1. 회원가입 이용 약관
app.post("/member/agree", (req, res) => {
    let chosenAgree = req.body.chosen_agree
    if (chosenAgree === undefined)
        res.status(401).send(false)
    else
        // TODO 회원 가입 페이지로 redirect.
        res.cookie("chosen_agree", chosenAgree, {}).status(200).send(true)
})

// 2. 이메일 인증메일 보내기
app.post("/member/email", (req, res) => {
    let tempMemberEmail = req.body.rec_email
    if (tempMemberEmail === undefined || req.cookies.chosen_agree === undefined)
        res.status(401).send(false)
    else {
        let emailCheckQuery = "select member_email, member_secede, member_ban from member where member_email = ?;"
        let selectParam = [tempMemberEmail]
        conn.query(emailCheckQuery, selectParam, function (error, rows, fields) {
            if (error)
                console.error(error)
            else {
                let isEmail = rows.length === 0 ? null : rows[0].member_email
                memberCheck(isEmail).then(memberCheckValue => {
                    // 최초 가입.
                    if (memberCheckValue === 200) {
                        crypto.generateKey().then(keyValue => {
                            crypto.getSalt().then(salt => {
                                crypto.encryptByHash(keyValue, salt).then(tempAuthKey => {
                                    regExp(tempAuthKey).then(authKey => {
                                        let today = new Date()
                                        let tomorrow = new Date(today.setDate(today.getDate() + 1))
                                        let urlAuthEmail = "http://localhost:3000/member/email-check/" + authKey
                                        let insertEmailAuth = "insert into email_auth(email_key, email_auth_flag, email_date, email_dispose, rec_email, temp_chosen_agree) values(?, ?, ?, ?, ?, ?);"
                                        let insertParam = [authKey, 0, tomorrow, 0, tempMemberEmail, req.cookies.chosen_agree]
                                        conn.query(insertEmailAuth, insertParam, function (error, rows, fields) {
                                            if (error)
                                                console.error(error)
                                            else
                                                console.log("Success insert emailAuthData")
                                        })
                                        sendEmail(tempMemberEmail, urlAuthEmail).then(mailContents => {
                                            transporter.sendMail(mailContents, function (error, info) {
                                                if (error)
                                                    console.error(error)
                                                else {
                                                    // 이메일 인증 코드 전송 완료.
                                                    res.clearCookie("chosen_agree").status(200).send(true)
                                                    console.log(info.response)
                                                }
                                            })
                                        })
                                    })
                                })
                            })
                        })
                    }  // 탈퇴 후 가입.
                    else if (memberCheckValue === 401 && rows[0].member_secede === 1) {
                        // 탈퇴 전 정지된 사용자인 경우.
                        if (rows[0].member_ban === 1)
                            res.status(401).send(false)
                        // 탈퇴 전 정지된 사용자가 아닌 경우(재가입).
                        else {
                            crypto.generateKey().then(keyValue => {
                                crypto.getSalt().then(salt => {
                                    crypto.encryptByHash(keyValue, salt).then(tempAuthKey => {
                                        regExp(tempAuthKey).then(authKey => {
                                            let today = new Date()
                                            let tomorrow = new Date(today.setDate(today.getDate() + 1))
                                            let urlAuthEmail = "http://localhost:3000/member/email-check/" + authKey
                                            let insertEmailAuth = "insert into email_auth(email_key, email_auth_flag, email_date, email_dispose, rec_email, temp_chosen_agree) values(?, ?, ?, ?, ?, ?);"
                                            let insertParam = [authKey, 0, tomorrow, 0, tempMemberEmail, req.cookies.chosen_agree]
                                            conn.query(insertEmailAuth, insertParam, function (error, rows, fields) {
                                                if (error)
                                                    console.error(error)
                                                else
                                                    console.log("Success insert emailAuthData")
                                            })
                                            sendEmail(tempMemberEmail, urlAuthEmail).then(mailContents => {
                                                transporter.sendMail(mailContents, function (error, info) {
                                                    if (error)
                                                        console.error(error)
                                                    else {
                                                        // 이메일 인증 코드 전송 완료.
                                                        res.clearCookie("chosen_agree").status(200).send(true)
                                                        console.log(info.response)
                                                    }
                                                })
                                            })
                                        })
                                    })
                                })
                            })
                        }
                    }
                    // 이미 가입 되어 있고, 탈퇴하지 않은 회원.
                    else
                        // memberCheckValue === 401 && rows[0].member_secede === 0
                        res.status(memberCheckValue).send(false)
                })
            }
        })
    }
})

// 3. 이메일 인증
app.get(/email-check/, (req, res) => {
    let parse = req.path.split("/")
    let authKey = parse[3]
    if (authKey === undefined)
        res.status(401).send(false)
    else {
        // 폐기 처리 되어 있는 인증 코드에 다시 접근하지 못하도록 구현.
        let disPoseCheck = "select email_key, email_dispose, email_date from email_auth where email_key = ?"
        let authKeyParam = [authKey]
        conn.query(disPoseCheck, authKeyParam, function (error, rows, fields) {
            if (error)
                console.error(error)
            else {
                if (rows.length === 0) {
                    res.status(401).send(false)
                } else {
                    if (rows[0].email_dispose === 1)
                        res.status(401).send(false)
                    else {
                        // 이메일 인증 url을 클릭 하면, 해당 키의 인증 여부, 유효기간 체크. 현재 날짜보다 작으면 폐기 처리.
                        let today = new Date()
                        let emailDate = rows[0].email_date
                        if (emailDate < today) {
                            let disposeUpdate = "update email_auth set email_dispose = ? where email_key = ?;"
                            let disposeParam = [1, rows[0].email_key]
                            conn.query(disposeUpdate, disposeParam, function (error, rows, fields) {
                                if (error)
                                    console.error(error)
                                else {
                                    console.log("Update Dispose Query is Executed.")
                                    res.status(401).send(false)
                                }
                            })
                        } else {
                            // 정상 접근 시 전송된 email의 url을 클릭하면, 해당 키에 해당하는 인증 여부, 폐기 처리 업데이트.
                            let updateSql = "update email_auth set email_auth_flag = ?, email_dispose = ? where email_key = ?;"
                            let updateParam = [1, 1, rows[0].email_key]
                            conn.query(updateSql, updateParam, function (error, rows, fields) {
                                if (error)
                                    console.error(error)
                                else
                                    console.log("Update Flag and Dispose Query is Executed.")

                            })

                            // 키가 일치하면 회원가입 페이지로 redirect
                            if (authKey === rows[0].email_key) {
                                req.session.auth_key = authKey
                                //TODO 회원 가입 페이지로 redirect.
                                req.session.save(function (error) {
                                    if (error)
                                        console.error(error)
                                    else
                                        res.status(200).send(true)
                                })
                            } else // 키 불일치.
                                res.status(401).send(false)
                        }
                    }
                }
            }
        })
    }
})

// 4. 회원가입
app.post("/member", (req, res) => {
    let authKey = req.session.auth_key
    if (authKey === undefined || Object.keys(req.body).length === 0)
        res.status(401).send(false)
    else {
        let memberName = req.body.member_name
        let memberSex = req.body.member_sex
        let memberBirth = req.body.member_birth
        let memberCompany = req.body.member_company
        let memberState = req.body.member_state
        let memberPw = req.body.member_pw
        let memberPhone = req.body.member_phone
        // 인증 키에 해당하는 사용자 이메일로 사용자 테이블 조회.
        let recEmailSql = "select rec_email, temp_chosen_agree from email_auth where email_key = ?;"
        let recEmailParam = [authKey]
        conn.query(recEmailSql, recEmailParam, function (error, rows, fields) {
            if (error)
                console.error(error)
            else {
                if (rows.length === 0)
                    res.status(401).send(false)
                else {
                    let tempEmail = rows[0].rec_email
                    let chosenAgreeValue = rows[0].temp_chosen_agree
                    // 이메일 인증 없이 인증 키를 우연히 맞춰서 회원 가입 페이지를 우회해서 들어 왔을 때
                    // 이미 있는 이메일로 가입 하면 primary key 중복으로 서버 죽을 수 있으므로. 사용자 조회 한번 더 할 필요가 있음.
                    let memberCheckSql = "select member_email, member_secede from member where member_email = ?;"
                    let memberCheckParam = [tempEmail]
                    conn.query(memberCheckSql, memberCheckParam, function (error, rows, fields) {
                        if (error)
                            console.error(error)
                        else {
                            let isEmail = rows.length === 0 ? null : rows[0].member_email
                            memberCheck(isEmail).then(memberCheckValue => {
                                crypto.getSalt().then(salt => {
                                    crypto.encryptByHash(memberPw, salt).then(encryptedPw => {
                                        crypto.encryption(memberPhone).then(encryptedPhone => {
                                            // 없으면 최초 가입.
                                            if (memberCheckValue === 200) {
                                                let insertSql = "insert into member(member_email, member_name, member_sex, member_birth, member_company, member_state, member_pw, member_phone, member_ban, chosen_agree, member_salt, member_secede) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
                                                let insertParam = [tempEmail, memberName, memberSex, memberBirth, memberCompany, memberState, encryptedPw, encryptedPhone, 0, chosenAgreeValue, salt, 0]
                                                conn.query(insertSql, insertParam, function (error, rows, fields) {
                                                    if (error)
                                                        console.error(error)
                                                    else {
                                                        console.log("Insert Into member Query is Executed.")
                                                        req.session.member_email = tempEmail
                                                        req.session.member_pw = encryptedPw
                                                        req.session.save(function (error) {
                                                            if (error)
                                                                console.error(error)
                                                            else
                                                                // TODO 메인 페이지로 redirect
                                                                res.redirect(307, "/")
                                                        })

                                                        delete req.session.auth_key
                                                        req.session.save(function (error) {
                                                            if (error)
                                                                console.error(error)
                                                        })
                                                    }
                                                })

                                                // log 추가.
                                                let memberLogInsert = "insert into member_log(member_email, member_log_join, member_login_lately) values(?, ?, ?);"
                                                let today = new Date()
                                                let memberLogInsertParam = [tempEmail, today, today]
                                                conn.query(memberLogInsert, memberLogInsertParam, function (error, rows, fields) {
                                                    if (error)
                                                        console.error(error)
                                                    else
                                                        console.log("Success.")
                                                })

                                                // log 추가.
                                                let memberLoginLogInsert = "insert into member_login_log(member_email, member_login) values(?, ?);"
                                                let memberLoginLogParam = [tempEmail, today]
                                                conn.query(memberLoginLogInsert, memberLoginLogParam, function (error, rows, fields) {
                                                    if (error)
                                                        console.error(error)
                                                    else
                                                        console.log("Success.")
                                                })
                                            }
                                            // 이메일이 있고, 탈퇴 여부 1 이면 재가입.
                                            else if (memberCheckValue === 401 && rows[0].member_secede === 1) {
                                                let newEmail = rows[0].member_email
                                                let updateSql = "update member set member_name = ?, member_sex = ?, member_birth = ?, member_company = ?, member_state = ?, member_pw = ?, member_phone = ?, member_ban = ?, chosen_agree = ?, member_salt = ?, member_secede = ? where member_email = ?"
                                                let updateParam = [memberName, memberSex, memberBirth, memberCompany, memberState, encryptedPw, encryptedPhone, 0, chosenAgreeValue, salt, 0, newEmail]
                                                conn.query(updateSql, updateParam, function (error, rows, fields) {
                                                    if (error)
                                                        console.error(error)
                                                    else {
                                                        console.log("update query is executed.")
                                                        req.session.member_email = newEmail
                                                        req.session.member_pw = encryptedPw
                                                        req.session.save(function (error) {
                                                            if (error)
                                                                console.error(error)
                                                            else
                                                                // TODO 메인 페이지로 redirect
                                                                res.redirect(307, "/")
                                                        })

                                                        delete req.session.auth_key
                                                        req.session.save(function (error) {
                                                            if (error)
                                                                console.error(error)
                                                        })
                                                    }
                                                })

                                                // log 추가.
                                                let memberLogInsert = "insert into member_log(member_email, member_log_join, member_login_lately) values(?, ?, ?);"
                                                let today = new Date()
                                                let memberLogInsertParam = [newEmail, today, today]
                                                conn.query(memberLogInsert, memberLogInsertParam, function (error, rows, fields) {
                                                    if (error)
                                                        console.error(error)
                                                    else {
                                                        req.session.join_lately = today
                                                        req.session.save(function (err) {
                                                            if (err)
                                                                console.error(err)
                                                        })
                                                        console.log("Success.")
                                                    }
                                                })

                                                // log 추가.
                                                let memberLoginLogInsert = "insert into member_login_log(member_email, member_login) values(?, ?);"
                                                let memberLoginLogParam = [newEmail, today]
                                                conn.query(memberLoginLogInsert, memberLoginLogParam, function (error, rows, fields) {
                                                    if (error)
                                                        console.error(error)
                                                    else
                                                        console.log("Success.")
                                                })
                                            }
                                            // 이메일이 있고, 탈퇴 여부 0 이면 이미 있는 사용자
                                            else
                                                // memberCheckValue === 401 && rows[0].member_secede === 0
                                                res.status(401).send(false)
                                        })
                                    })
                                })
                            })
                        }
                    })
                }
            }
        })
    }
})

// 5. 로그인
app.post("/member/login", (req, res) => {
    let memberEmail = req.body.member_email
    let tempPw = req.body.member_pw
    if (memberEmail === undefined || tempPw === undefined)
        res.status(401).send(false)
    else {
        let selectSql = "select member_email, member_pw, member_ban, member_salt, member_secede from member where member_email = ?;"
        let selectParam = [memberEmail]
        conn.query(selectSql, selectParam, function (error, rows, fields) {
            let isEmail = rows.length === 0 ? null : rows[0].member_email
            memberCheck(isEmail).then(memberCheckValue => {
                // 회원 테이블에 중복된 이메일이 없으면.
                if (memberCheckValue === 200)
                    res.status(401).send(false)
                // 회원 테이블에 입력한 이메일이 있고 탈퇴 여부가 0이면(탈퇴하지 않았으면).
                else if (memberCheckValue === 401 && rows[0].member_secede === 0) {
                    // 정지된 회원인 경우.
                    if (rows[0].member_ban === 1)
                        // TODO 로그인 실패(정지된 회원인 경우). 다시 로그인 화면으로 redirect
                        res.redirect(401, "/")
                    else {
                        crypto.encryptByHash(tempPw, rows[0].member_salt).then(memberPw => {
                            // 입력한 비밀번호 해시 암호화 한 값과 회원 테이블에 해당 이메일의 비밀번호 값 비교 및 정지여부 확인.
                            if (memberPw === rows[0].member_pw) {
                                req.session.member_email = rows[0].member_email
                                req.session.member_pw = rows[0].member_pw
                                req.session.save(function (error) {
                                    if (error)
                                        console.error(error)
                                    else
                                        // TODO 메인 페이지로 이동
                                        res.redirect(307, "/")
                                })

                                let memberLogUpdate = "update member_log set member_login_lately = ? where member_log.member_email = ?;"
                                let today = new Date()
                                let memberLogParam = [today, rows[0].member_email]
                                conn.query(memberLogUpdate, memberLogParam, function (error, rows, fields) {
                                    if (error)
                                        console.error(error)
                                    else
                                        console.log("update query is executed.")
                                })

                                let memberLoginLogInsert = "insert into member_login_log(member_email, member_login) values(?, ?);"
                                let memberLoginLogParam = [rows[0].member_email, today]
                                conn.query(memberLoginLogInsert, memberLoginLogParam, function (error, rows, fields) {
                                    if (error)
                                        console.error(error)
                                    else
                                        console.log("insert query is executed.")
                                })
                            } else {
                                // TODO 로그인 실패(비밀번호가 틀린 경우). 다시 로그인 화면으로 redirect
                                res.redirect(401, "/")
                            }
                        })
                    }
                } else {
                    // TODO 로그인 실퍠(탈퇴회원인 경우). 다시 로그인 화면으로 redirect
                    res.redirect(401, "/")
                }
            })
        })
    }
})

// 6. 로그아웃
app.post("/member/logout", (req, res) => {
    req.session.destroy(function (error) {
        if (error)
            console.error(error)
        else
            // TODO 로그인 페이지로 이동
            res.redirect(307, "/")
    })
})

// 7. 회원탈퇴
app.delete("/member/secede", (req, res) => {
    let sessionEmail = req.session.member_email
    if (sessionEmail === undefined)
        res.status(401).send(false)
    else {
        let compareSql = "select member_email from member where member_email = ?;"
        let compareParam = [sessionEmail]
        conn.query(compareSql, compareParam, function (error, rows, fields) {
            if (error)
                console.error(error)
            else {
                if (rows.length === 0)
                    res.status(401).send(false)
                else {
                    if (sessionEmail === rows[0].member_email) {
                        let updateSql = "update member set member_secede = ? where member_email = ?;"
                        let updateParam = [1, rows[0].member_email]
                        conn.query(updateSql, updateParam, function (error, rows, fields) {
                            if (error)
                                console.error(error)
                            else {
                                console.log("update query is executed.")
                                req.session.destroy(function (error){
                                    if (error)
                                        console.error(error)
                                    else
                                        // TODO 메인 페이지로 이동
                                        res.status(200).send("Success secede.")
                                })
                            }
                        })
                    } else {
                        res.status(401).send(false)
                    }
                }
            }
        })
    }
})

// 8. 비밀번호 찾기
app.post("/member/pw/find", (req, res) => {
    let tempEmail = req.body.member_email
    if (tempEmail === undefined)
        res.status(401).send(false)
    else {
        let selectSql = "select member_email, member_ban, member_secede from member where member_email = ?;"
        let selectParma = [tempEmail]
        conn.query(selectSql, selectParma, function (error, rows, fields) {
            if (error)
                console.error(error)
            else {
                // 사용자 중복 조회.
                let isEmail = rows.length === 0 ? null : rows[0].member_email
                memberCheck(isEmail).then(memberCheckValue => {
                    // 중복된 이메일이 없음.
                    if (memberCheckValue === 200)
                        res.status(401).send(false)
                    // 이메일이 있음.
                    else {
                        // 정지, 탈퇴 여부 체크
                        if (rows[0].member_ban === 0 && rows[0].member_secede === 0) {
                            crypto.generateKey().then(authKey => {
                                crypto.getSalt().then(salt => {
                                    crypto.encryptByHash(authKey, salt).then(tempKey => {
                                        regExp(tempKey).then(key => {
                                            let today = new Date()
                                            let tomorrow = new Date(today.setDate(today.getDate() + 1))
                                            let insertSql = "insert into pw_find(pw_key, pw_edit, pw_date, pw_dispose, member_email) values(?, ?, ?, ?, ?)"
                                            let insertParam = [key, 0, tomorrow, 0, rows[0].member_email]
                                            conn.query(insertSql, insertParam, function (error, rows, fields) {
                                                if (error)
                                                    console.error(error)
                                                else
                                                    console.log("insert query is executed.")
                                            })

                                            let urlPassword = "http://localhost:3000/member/pw/reset-redirect/" + key
                                            sendEmail(isEmail, urlPassword).then(mailContents => {
                                                transporter.sendMail(mailContents, function (error, info) {
                                                    if (error)
                                                        console.error(error)
                                                    else {
                                                        // 이메일 인증 코드 전송 완료.
                                                        res.status(200).send(true)
                                                        console.log(info.response)
                                                    }
                                                })
                                            })
                                        })
                                    })
                                })
                            })
                        } else
                            // 정지 혹은 탈퇴한 사용자.
                            res.status(401).send(false)
                    }
                })
            }
        })
    }
})

// 9. 비밀번호 재설정 바로가기
app.get(/reset-redirect/, (req, res) => {
    let parse = req.path.split("/")
    let pwKey = parse[4]
    if (pwKey === undefined)
        res.status(401).send(false)
    else {
        let compareSql = "select pw_key, pw_edit, pw_date, pw_dispose, member_email from pw_find where pw_key = ?"
        let compareParam = [pwKey]
        conn.query(compareSql, compareParam, function (error, rows, fields) {
            if (error)
                console.error(error)
            else {
                if (rows.length === 0)
                    res.status(401).send(false)
                else {
                    // 키가 일치할 경우
                    if (pwKey === rows[0].pw_key) {
                        // 폐기 여부 조회 폐기 됬으면 접근 불가
                        if (rows[0].pw_dispose === 1)
                            res.status(401).send(false)
                        // 폐기 되지 않았을 때
                        else {
                            // 유효기간이 지났으면 폐기 처리 후 접근 불가
                            let today = new Date()
                            if (rows[0].pw_date < today) {
                                let updateDispose = "update pw_find set pw_dispose = ? where pw_key = ?"
                                let updateParam = [1, rows[0].pw_key]
                                conn.query(updateDispose, updateParam, function (error, rows, fields) {
                                    if (error)
                                        console.error(error)
                                    else {
                                        console.log("pw_dispose update")
                                        res.status(401).send(false)
                                    }
                                })
                            }
                            // TODO 정상 접근, 재설정 페이지로 바로가기.
                            else {
                                req.session.pwKey = rows[0].pw_key
                                req.session.save(function (error) {
                                    if (error)
                                        console.error(error)
                                    else
                                        res.status(200).send(true)
                                })
                            }
                        }
                    }
                    // 키 불일치.
                    else {
                        res.status(401).send(false)
                    }
                }
            }
        })
    }
})

// 10. 비밀번호 재설정
app.patch("/member/pw/reset", (req, res) => {
    let newPw = req.body.member_pw
    let pwKey = req.session.pwKey
    if (newPw === undefined || pwKey === undefined)
        res.status(401).send(false)
    else {
        let selectSql = "select member_email from pw_find where pw_key = ?"
        let selectParam = [pwKey]
        // 세션에 있는 키 값으로 사용자 이메일 조회.
        conn.query(selectSql, selectParam, function (error, rows, fields) {
            if (error)
                console.error(error)
            else {
                if (rows.length === 0)
                    res.status(401).send(false)
                else {
                    // 해당 이메일과 일치하는 사용자 테이블의 패스워드 암호화 후 업데이트.
                    let memberCheckSql = "select member_email, member_ban, member_secede from member where member_email = ?;"
                    let memberCheckParam = [rows[0].member_email]
                    conn.query(memberCheckSql, memberCheckParam, function (error, rows, fields) {
                        if (error)
                            console.error(error)
                        else {
                            let isEmail = rows.length === 0 ? null : rows[0].member_email
                            memberCheck(isEmail).then(memberCheckValue => {
                                // 해당 사용자가 없음.
                                if (memberCheckValue === 200)
                                    res.status(401).send(false)
                                else if (memberCheckValue === 401 && rows[0].member_ban === 0 && rows[0].member_secede === 0) {
                                    crypto.getSalt().then(salt => {
                                        crypto.encryptByHash(newPw, salt).then(encryptedNewPw => {
                                            let tempEmail = rows[0].member_email
                                            let memberUpdateSql = "update member set member_pw = ?, member_salt = ? where member_email = ?;"
                                            let memberUpdateParam = [encryptedNewPw, salt, tempEmail]
                                            conn.query(memberUpdateSql, memberUpdateParam, function (error, rows, fields) {
                                                if (error)
                                                    console.error(error)
                                                else {
                                                    // TODO 메인 페이지로 redirect
                                                    res.status(200).send(true)
                                                }
                                            })
                                            // 재설정 여부, 폐기 여부 update 후 세션 삭제.
                                            let pwUpdateSql = "update pw_find set pw_edit = ?, pw_dispose = ? where pw_key = ?;"
                                            let pwUpdateParam = [1, 1, pwKey]
                                            conn.query(pwUpdateSql, pwUpdateParam, function (error, rows, fields) {
                                                if (error)
                                                    console.error(error)
                                                else {
                                                    console.log("update pw log query is executed.")
                                                    delete req.session.pwKey
                                                    req.session.save(function (err) {
                                                        if (err)
                                                            console.error(err)
                                                    })
                                                }
                                            })
                                        })
                                    })
                                } else
                                    res.status(401).send(false)
                            })
                        }
                    })
                }
            }
        })
    }
})

// 11. 회원정보 수정
app.post("/member/update", (req, res) => {
    let memberPw = req.body.member_pw
    let memberEmail = req.session.member_email
    if (memberPw === undefined || memberEmail === undefined)
        res.status(401).send(false)
    else {
        let compareSql = "select member_pw, member_salt from member where member_email = ?"
        let compareParam = [memberEmail]
        conn.query(compareSql, compareParam, function (error, rows, fields) {
            if (error)
                console.error(error)
            else {
                if (rows.length === 0)
                    res.status(401).send(false)
                else {
                    crypto.encryptByHash(memberPw, rows[0].member_salt).then(encryptedPw => {
                        if (encryptedPw !== rows[0].member_pw)
                            res.status(401).send(false)
                        else
                            // TODO 회원정보 상세 페이지로 redirect.
                            res.redirect(307, "/")
                    })
                }
            }
        })
    }
})

// 12. 회원정보 수정 상세
app.patch("/member/update-detail", (req, res) => {
    let memberEmail = req.session.member_email
    if (memberEmail === undefined || Object.keys(req.body).length === 0)
        res.status(401).send(false)
    else {
        let memberName = req.body.member_name
        let memberPw = req.body.member_pw
        let memberSex = req.body.member_sex
        let memberBirth = req.body.member_birth
        let memberPhone = req.body.member_phone
        let memberCompany = req.body.member_company
        let memberState = req.body.member_state
        let updateSql = "update member set member_name = ?, member_pw = ?, member_sex = ?, member_birth = ?, member_phone = ?, member_company = ?, member_state = ?, member_salt = ? where member_email = ?"
        let updateParam
        crypto.getSalt().then(salt => {
            crypto.encryptByHash(memberPw, salt).then(encryptedPw => {
                crypto.encryption(memberPhone).then(encryptedPhone => {
                    updateParam = [memberName, encryptedPw, memberSex, memberBirth, encryptedPhone, memberCompany, memberState, salt, memberEmail]
                    conn.query(updateSql, updateParam, function (error, rows, fields) {
                        if (error)
                            console.error(error)
                        else {
                            req.session.member_pw = encryptedPw
                            req.session.save(function (err) {
                                if (err)
                                    console.error(err)
                                else
                                    // TODO 마이페이지로 redirect.
                                    res.status(201).send(true)
                            })
                        }
                    })
                })
            })
        })
    }
})

// 13. 사용자 아이디어 조회
app.get("/member/myidea", (req, res) => {
    let sessionEmail = req.session.member_email
    if (sessionEmail === undefined)
        res.status(401).send(false)
    else {
        let ideaSql = "select idea_title, idea_date from idea where member_email = ?"
        let ideaParam = [sessionEmail]
        conn.query(ideaSql, ideaParam, function (error, rows, fields) {
            if (error)
                console.error(error)
            else {
                if (rows.length === 0)
                    res.status(401).send(false)
                else {
                    res.send(rows)
                }
            }
        })
    }
})

// 14. 관심 사업 조회
app.get("/member/marked", (req, res) => {
    let sessionEmail = req.session.member_email
    if (sessionEmail === undefined)
        res.status(401).send(false)
    else {
        let markedSql = "select ia.anno_id, anno_title, anno_date from inter_anno as ia join anno as a on ia.anno_id = a.anno_id where member_email = ?;"
        let markedParam = [sessionEmail]
        conn.query(markedSql, markedParam, function (error, rows, fields) {
            if (error)
                console.error(error)
            else {
                if (rows.length === 0)
                    res.status(401).send(false)
                else {
                    let annoInfo = []
                    for (let i=0; i<rows.length; i++) {
                        annoInfo[i] = {
                            "anno_id": rows[i].anno_id - 1233,
                            "anno_title": rows[i].anno_title,
                            "anno_date": rows[i].anno_date
                        }
                    }
                    res.status(201).send(annoInfo)
                }
            }
        })
    }
})

/**
 * 관리자 API
 */
// 1. 사용자 조회
app.post("/admin/member-check", (req, res) => {
    let checkEmail = req.body.member_email
    if (checkEmail === undefined)
        res.status(401).send(false)
    else {
        let emailCheckSql = "select member_email, member_secede, member_ban from member where member_email = ?;"
        let selectParam = [checkEmail]
        conn.query(emailCheckSql, selectParam, function (error, rows, fields) {
            if (error)
                console.error(error)
            else {
                let isEmail = rows.length === 0 ? null : rows[0].member_email
                memberCheck(isEmail).then(value => {
                    // 중복된 이메일이 없음
                    if (value === 200)
                        res.status(200).send("empty")
                    else if (value === 401 && rows[0].member_secede === 0) {
                        // 정지되지 않은 회원.(정상적인 회원)
                        if (rows[0].member_ban === 0)
                            res.status(200).send("OK")
                        else
                            // member_ban === 1 정지된 회원
                            res.status(401).send("ban")
                    } else {
                        // 탈퇴한 회원
                        res.status(401).send("secede")
                    }
                })
            }
        })
    }
})

/**
 * 문의게시판 API
 */

/**
 * 공지사항 API
 */

/**
 * 고객센터 API
 */

/**
 * 아이디어 API
 */

/**
 * 공고정보게시판 API
 */

/**
 * 포인트 API
 */

/**
 * 페이지네이션 API
 */

//임시 라우터
app.post("/", (req, res) => {
    res.send(req.body)
})

app.listen(port, () => {
    console.log(`access port at ${port}`)
})