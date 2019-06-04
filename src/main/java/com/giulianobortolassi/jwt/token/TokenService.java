package com.giulianobortolassi.jwt.token;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Component to handle main token functions.
 */
@Service
public class TokenService {

    @Value("${jwt.default.expirationtime}")
    private long EXPIRATION_TIME = 600_000; // default to 10min

    @Value("${jwt.signkey}")
    private String SIGN_KEY = "myKey";

    @Autowired
    private TokenRepository repository;

    /**
     * Generate a new JWT token and register into database.
     *
     * @param username the subject for JWT claims
     * @param roles a custom claim. The claim is named ROLES and will be set into body part of generated token
     * @return a {@link Token} object.
     */
    public Token generateToken(String username, List<String> roles) {

        // TODO: Improve the SIGN_KEY usage. It can be usefull to delegate the key generation to a external class in
        // order to implement different key generation strategies.

        String roles_names;

        StringBuilder builder = new StringBuilder();
        for(String role_id:roles){
            builder.append(role_id).append(",");
        }
        builder.deleteCharAt(builder.lastIndexOf(","));

        roles_names = builder.toString();


        UUID uuid = UUID.randomUUID();
        Date issuedDate = new Date();
        Date expiryDate = new Date(issuedDate.getTime() + EXPIRATION_TIME);

        String tokenString = Jwts.builder()
                .setId(uuid.toString())
                .setSubject(username)
                .signWith(SignatureAlgorithm.HS256, SIGN_KEY)
                .setIssuedAt(issuedDate)
                .setExpiration(expiryDate)
                .claim("ROLES", roles_names)
                .compact();

        Token token = new Token();
        token.setId(uuid.toString());
        token.setRoles(roles);
        token.setUser(username);
        token.setToken(tokenString);
        token.setIssuedTime(issuedDate);
        token.setExpirationTime(expiryDate);

        return repository.registerToken( token );
    }

    /**
     * Check if the given token is valid:
     * 1 - Check if its registered in database
     * 2 - Check expiration time
     *
     * @param tokenStr the full JWT token. It will be parsed and checkToken(Token token) method will be invoked.
     * @return the valid token. It it configured to auto renew, so the token returned will have the new expiry date.
     * @throws TokenExpiredException exception if the token was expired. It can be returned if the expiredDate was
     *          in the past or if the token was not found in repository
     */
    public Token checkToken(String tokenStr) throws TokenExpiredException {
        Token token = parseToken(tokenStr);
        return checkToken( token );
    }

    /**
     * Check if the given token is valid:
     * 1 - Check if its registered in database
     * 2 - Check expiration time
     *
     * @param token a {@link Token} object to be validated
     * @return the valid token. It it configured to auto renew, so the token returned will have the new expiry date.
     * @throws TokenExpiredException exception if the token was expired. It can be returned if the expiredDate was
     *          in the past or if the token was not found in repository
     *
     */
    public Token checkToken(Token token) throws TokenExpiredException {
        try {
            token = repository.getTokenById(token.getId());
        } catch (TokenNotFoundException e) {
            throw new TokenExpiredException("Invalid token.",e);
        }

        Date now = new Date(System.currentTimeMillis());
        if( token.getExpirationTime().before(now) ){
            throw new TokenExpiredException();
        }
        return token;
    }


    /**
     * Remove token from database in order to invalidate it
     *
     * @param tokenStr the full JWT token. It will be parsed and revokeToken(Token token) method will be invoked.
     * @throws TokenNotFoundException if given token does not exists
     */
    public void revokeToken(String tokenStr) throws TokenNotFoundException {
        revokeToken ( parseToken(tokenStr) );
    }

    /**
     * Remove token from database in order to invalidate it
     *
     * @param token a {@link Token} object to be removed from database
     * @throws TokenNotFoundException if given token does not exists
     */
    public void revokeToken(Token token) throws TokenNotFoundException {
        Token tokenById = repository.getTokenById( token.getId() );

        if( tokenById == null ) {
            throw new TokenNotFoundException();
        }
        repository.removeToken( tokenById );
    }

    /**
     * Return all active tokens
     *
     * @return a list with all active tokens or a empty list if none.
     */
    public List<Token> listActiveTokens() {

        try {
            List<Token> tokens = repository.listTokens();
            if( tokens == null ){
                tokens = new ArrayList<>();
            }
            return tokens;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Parse JWT string to a {@link Token} object
     * @param tokenStr a full JWT token to be parsed into a Token object.
     * @return a {@link Token} object
     */
    Token parseToken(String tokenStr){
        Claims claims = Jwts.parser()
                .setSigningKey(SIGN_KEY)
                .parseClaimsJws(tokenStr)
                .getBody();
        List<String> roles = null;
        if( claims.get("roles") != null ) {
            roles = Arrays.asList(claims.get("roles").toString().split(","));
        }

        return new Token(claims.getId(),tokenStr,claims.getSubject(),roles,claims.getIssuedAt(),claims.getExpiration(), SIGN_KEY);
    }


}
