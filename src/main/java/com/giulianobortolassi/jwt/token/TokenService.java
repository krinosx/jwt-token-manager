package com.giulianobortolassi.jwt.token;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;


@Service
public class TokenService {

    @Value("${jwt.default.expirationtime}")
    private long EXPIRATION_TIME = 600_000; // default to 10min

    @Value("${jwt.signkey}")
    private String SIGN_KEY = "myKey";

    @Autowired
    private TokenRepository repository;

    public Token generateToken(String username, List<String> roles) throws Exception {

        String roles_names = "";

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
     * @param tokenStr
     * @return
     * @throws Exception
     */
    public Token checkToken(String tokenStr) throws Exception {
        Token token = parseToken(tokenStr);
        return checkToken( token );
    }

    public Token checkToken(Token token) throws Exception {
        try {
            token = repository.getTokenById(token.getId());
        } catch (TokenNotFoundExcpetion e) {
            throw new TokenExpiredException("Invalid token.",e);
        }

        Date now = new Date(System.currentTimeMillis());
        if( token.getExpirationTime().before(now) ){
            throw new TokenExpiredException();
        }

        return token;
    }


    /**
     * Remove token from database
     * @param tokenStr
     * @throws Exception
     */


    public void revokeToken(String tokenStr) throws  TokenNotFoundExcpetion {
        revokeToken ( parseToken(tokenStr) );
    }
    public void revokeToken(Token token) throws  TokenNotFoundExcpetion {
        Token tokenById = repository.getTokenById( token.getId() );

        if( tokenById == null ) {
            throw new TokenNotFoundExcpetion();
        }
        repository.removeToken( tokenById );
    }


    public List<Token> listActiveTokens() {

        try {
            return repository.listTokens();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Parse JWT string to a {@link Token} object
     * @param tokenStr
     * @return
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

        return new Token(claims.getId(),tokenStr,claims.getSubject(),roles,claims.getIssuedAt(),claims.getExpiration());
    }


}
