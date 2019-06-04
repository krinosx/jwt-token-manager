package com.giulianobortolassi.jwt.token;

import java.util.Date;
import java.util.List;

public class Token {

    private String id;
    private String token;
    private String user;
    private List<String> roles;
    private Date issuedTime;
    private Date expirationTime;
    /** Sign key used to this token. This information must never leave the server */
    private String signKey;


    public Token() {
    }

    public Token(String id, String token, String user, List<String> roles, Date issuedTime, Date expirationTime, String signKey) {
        this.id = id;
        this.token = token;
        this.user = user;
        this.roles = roles;
        this.issuedTime = issuedTime;
        this.expirationTime = expirationTime;
        this.signKey = signKey;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public void setIssuedTime(Date issuedTime) {
        this.issuedTime = issuedTime;
    }

    public Date getIssuedTime() {
        return issuedTime;
    }

    public void setExpirationTime(Date expirationTime) {
        this.expirationTime = expirationTime;
    }

    public Date getExpirationTime() {
        return expirationTime;
    }

    public void setSignKey(String signKey) {
        this.signKey = signKey;
    }

    public String getSignKey() {
        return signKey;
    }
}
