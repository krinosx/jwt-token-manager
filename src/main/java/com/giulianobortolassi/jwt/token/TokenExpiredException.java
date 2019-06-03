package com.giulianobortolassi.jwt.token;

public class TokenExpiredException extends  Exception {


    TokenExpiredException(){
        super();
    }

    TokenExpiredException(String message){
        super(message);
    }
    TokenExpiredException(String message, Throwable e){
        super(message, e);
    }
}
