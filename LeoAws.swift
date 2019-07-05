//
//  LeoAws.swift
//  CognitoApplication
//
//  Created by tecH on 10/04/19.
//  Copyright © 2019 David Tucker. All rights reserved.
//

import Foundation
import AWSCognitoIdentityProvider

struct LeoAwsError {
    var type : String?
    var message : String?
}


struct LeoAwsUserSession {
    var token : String?
    var expirationTime : Date?
    

}

protocol LeoAwsAuthResponsable {
    
}

extension LeoAwsError :  LeoAwsAuthResponsable {
    
}

extension LeoAwsUserSession :  LeoAwsAuthResponsable {
    
}

extension AWSCognitoIdentityUserSession : LeoAwsAuthResponsable {
    
}

extension AWSCognitoIdentityUserPoolSignUpResponse : LeoAwsAuthResponsable {
    
}

extension AWSCognitoIdentityUserConfirmSignUpResponse : LeoAwsAuthResponsable {
    
}
extension AWSCognitoIdentityUserResendConfirmationCodeResponse : LeoAwsAuthResponsable {
    
}

let userPoolID = "us-east-1_p71HyTStm"

class  LeoAwsAuth : NSObject{
    
    static var shared = LeoAwsAuth()
    
    var cognitoConfig:LeoCognitoConfig?
    
    var passwordAuthenticationCompletion: AWSTaskCompletionSource<AWSCognitoIdentityPasswordAuthenticationDetails>?
    
    
    class func defaultUserPool() -> AWSCognitoIdentityUserPool {
        return AWSCognitoIdentityUserPool(forKey: userPoolID)
    }
    
    override init(){
        super.init()
        
        self.cognitoConfig = LeoCognitoConfig()
        self.setupCognitoUserPool()
    }
    
    func setupCognitoUserPool() {
        
        let clientId:String = self.cognitoConfig!.getClientId()
        
        let poolId:String = self.cognitoConfig!.getPoolId()
        
        let clientSecret:String = self.cognitoConfig!.getClientSecret()
        
        let region:AWSRegionType = self.cognitoConfig!.getRegion()
        
        let serviceConfiguration:AWSServiceConfiguration = AWSServiceConfiguration(region: region, credentialsProvider: nil)
        let cognitoConfiguration:AWSCognitoIdentityUserPoolConfiguration = AWSCognitoIdentityUserPoolConfiguration(clientId: clientId, clientSecret: clientSecret, poolId: poolId)
        AWSCognitoIdentityUserPool.register(with: serviceConfiguration, userPoolConfiguration: cognitoConfiguration, forKey: userPoolID)
        
        let pool:AWSCognitoIdentityUserPool = LeoAwsAuth.defaultUserPool()
        
        pool.delegate = self
    }
    
    func confirm(user :AWSCognitoIdentityUser , text : String , completionHandler : ((LeoAwsAuthResponsable) -> Void)? = nil) {
        
        user.confirmSignUp(text)
            .continueWith { (task) -> Any? in
                DispatchQueue.main.async(execute: {
                    if let error = task.error as NSError? {
                        let leoAwsError = LeoAwsError(type: error.userInfo["__type"] as? String,
                                                      message: error.userInfo["message"]as? String)
                        completionHandler?(leoAwsError)
                        //self?.present(alertController, animated: true, completion:  nil)
                    } else if let result = task.result  {
                        // handle the case where user has to confirm his identity via email / SMS
                        completionHandler?(result)
                        
                    }
                    
                })
                return nil
                
        }
        
    }
    func resend(user :AWSCognitoIdentityUser , completionHandler : ((LeoAwsAuthResponsable) -> Void)? = nil) {
        
        user.resendConfirmationCode()
            .continueWith { (task) -> Any? in
                DispatchQueue.main.async(execute: {
                    if let error = task.error as NSError? {
                        let leoAwsError = LeoAwsError(type: error.userInfo["__type"] as? String,
                                                      message: error.userInfo["message"]as? String)
                        completionHandler?(leoAwsError)
                        //self?.present(alertController, animated: true, completion:  nil)
                    } else if let result = task.result  {
                        // handle the case where user has to confirm his identity via email / SMS
//                        let leoAwsError = LeoAwsError(type: "Code Resent" ,
//                                                      message:  "Code resent to \(result.codeDeliveryDetails?.destination! ?? " no message")")
                        completionHandler?(result)
                        
                    }
                    
                })
                return nil
                
        }
        
    }
    
    func sign(user :AWSCognitoIdentityUser , username : String , password : String , completionHandler : ((LeoAwsAuthResponsable) -> Void)? = nil ){
        user.getSession(username, password: password, validationData: [])
            .continueWith { (task) -> Any? in
                DispatchQueue.main.async(execute: {
                    if let error = task.error as NSError? {
                        
                        
                        let leoAwsError = LeoAwsError(type: error.userInfo["__type"] as? String,
                                                      message: error.userInfo["message"]as? String)
                        
                        completionHandler?(leoAwsError)
                        
                        //self?.present(alertController, animated: true, completion:  nil)
                    } else if let result = task.result  {
                        // handle the case where user has to confirm his identity via email / SMS
                        let session = task.result! as AWSCognitoIdentityUserSession
//                        let token = session.idToken!.tokenString
//                       let expirationTime = session.expirationTime
                       let sesseion =  LeoAwsUserSession(token: session.idToken!.tokenString, expirationTime: session.expirationTime)
                       
                        
                        
                        completionHandler?(sesseion)
                     
                    }
                    
                })
                return nil
        }

    
    }
    
    func signup( phoneNumber : String , password : String , email : String , completionHandler : ((LeoAwsAuthResponsable) -> Void)? = nil ) {
        
        let  phone1 = AWSCognitoIdentityUserAttributeType(name: "phone_number", value: phoneNumber)
        let  email1 = AWSCognitoIdentityUserAttributeType(name: "email", value: email)
        
        LeoAwsAuth.defaultUserPool().signUp(email,
                                            password: password,
                                            userAttributes: [phone1,email1],
                                            validationData: [])
            .continueWith { (task) -> Any? in
                
                // guard let strongSelf = self else { return nil }
                
                DispatchQueue.main.async(execute: {
                    if let error = task.error as NSError? {
                        
                        
                        let leoAwsError = LeoAwsError(type: error.userInfo["__type"] as? String,
                                                      message: error.userInfo["message"]as? String)
                        
                        completionHandler?(leoAwsError)
                        
                        //self?.present(alertController, animated: true, completion:  nil)
                    } else if let result = task.result  {
                        // handle the case where user has to confirm his identity via email / SMS
                        
                        completionHandler?(result)
                        
                        if (result.user.confirmedStatus != AWSCognitoIdentityUserStatus.confirmed) {
                            
                            //    strongSelf.sentTo = result.codeDeliveryDetails?.destination
                            //  strongSelf.performSegue(withIdentifier: "confirmSignUpSegue", sender:sender)
                        } else {
                            
                            //   let _ = strongSelf.navigationController?.popToRootViewController(animated: true)
                        }
                    }
                    
                })
                return nil
                
        }
        
    }
    
    static func confirm () {
        var user:AWSCognitoIdentityUser? =   AWSCognitoIdentityUser()
        // user.c
    }
}

func some() {
    AWSDDLog.sharedInstance.logLevel = .verbose
    AWSDDLog.add(AWSDDTTYLogger.sharedInstance)
    
}

extension LeoAwsAuth : AWSCognitoIdentityInteractiveAuthenticationDelegate {
    public func getDetails(_ authenticationInput: AWSCognitoIdentityPasswordAuthenticationInput, passwordAuthenticationCompletionSource: AWSTaskCompletionSource<AWSCognitoIdentityPasswordAuthenticationDetails>) {
        self.passwordAuthenticationCompletion = passwordAuthenticationCompletionSource
        DispatchQueue.main.async {
//            if (self.usernameText == nil) {
//                self.usernameText = authenticationInput.lastKnownUsername
//            }
        }
    }
    
    public func didCompleteStepWithError(_ error: Error?) {
//        DispatchQueue.main.async {
//            if let error = error as NSError? {
//                let alertController = UIAlertController(title: error.userInfo["__type"] as? String,
//                                                        message: error.userInfo["message"] as? String,
//                                                        preferredStyle: .alert)
//                let retryAction = UIAlertAction(title: "Retry", style: .default, handler: nil)
//                alertController.addAction(retryAction)
//
//                self.present(alertController, animated: true, completion:  nil)
//            } else {
//                self.username.text = nil
//                self.dismiss(animated: true, completion: nil)
//            }
//        }
    }
}

