package com.giulianobortolassi.jwt.token;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Component to handle main token functions.
 */
@Service
public class TokenService {

    private static final Logger log = Logger.getLogger(TokenService.class.getCanonicalName());

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
        Token token = generateTokenObject(username, roles);
        return repository.registerToken( token );
    }

    /**
     * Internal method to generate tokens. Refactored to allow testing without depending on the repository.
     * @param username the subject for JWT claims
     * @param roles a custom claim. The claim is named ROLES and will be set into body part of generated token
     * @return a {@link Token} object.
     */
    Token generateTokenObject(String username, List<String> roles) {
        // TODO: Improve the SIGN_KEY usage. It can be useful to delegate the key generation to a external class in
        //  order to implement different key generation strategies.

        String roles_names = "";
        if ( roles != null && !roles.isEmpty() ) {
            StringBuilder builder = new StringBuilder();
            for (String role_id : roles) {
                builder.append(role_id).append(",");
            }
            builder.deleteCharAt(builder.lastIndexOf(","));
            roles_names = builder.toString();
        }

        UUID uuid = UUID.randomUUID();
        Date issuedDate = new Date();
        Date expiryDate = new Date(issuedDate.getTime() + EXPIRATION_TIME);


        Map<String, Object> extraClaims = new HashMap<>();
        if( !roles_names.isEmpty() ){
            extraClaims.put(Token.ROLES_KEY, roles_names);
        }

        String tokenString = Jwts.builder()
                .claims().add(extraClaims).and()
                .id(uuid.toString())
                .subject(username)
                .signWith(getSignatureKey(), Jwts.SIG.HS256)
                .issuedAt(issuedDate)
                .expiration(expiryDate)
                .compact();

        Token token = new Token();
        token.setId(uuid.toString());
        token.setRoles(roles);
        token.setUser(username);
        token.setToken(tokenString);
        token.setIssuedTime(issuedDate);
        token.setExpirationTime(expiryDate);
        token.setSignKey(SIGN_KEY);

        return token;
    }



    private SecretKey getSignatureKey() {
        // TODO: Store the encoded key on application.yml file
        String encodedKey =  Encoders.BASE64.encode(SIGN_KEY.getBytes());
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(encodedKey));
    }


    /**
     * Check if the given token is valid:
     * 1 - Check if it is registered in database
     * 2 - Check expiration time
     *
     * @param tokenStr the full JWT token. It will be parsed and checkToken(Token token) method will be invoked.
     * @return the valid token. It is configured to auto-renew, so the token returned will have the new expiry date.
     * @throws TokenExpiredException exception if the token was expired. It can be returned if the expiredDate was
     *          in the past or if the token was not found in repository
     */
    public Token checkToken(String tokenStr) throws TokenExpiredException {
        Token token = parseToken(tokenStr);
        return checkToken( token );
    }

    /**
     * Check if the given token is valid:
     * 1 - Check if it is registered in database
     * 2 - Check expiration time
     *
     * @param token a {@link Token} object to be validated
     * @return the valid token. It is configured to auto-renew, so the token returned will have the new expiry date.
     * @throws TokenExpiredException exception if the token was expired. It can be returned if the expiredDate was
     *          in the past or if the token was not found in repository
     *
     */
    public Token checkToken(final Token token) throws TokenExpiredException {

        try {
            Token storedToken = repository.getTokenById(token.getId());

            Date now = new Date(System.currentTimeMillis());
            if( storedToken.getExpirationTime().before(now) ){
                throw new TokenExpiredException();
            }
            return storedToken;

        } catch (TokenNotFoundException e) {
            throw new TokenExpiredException("Invalid token.",e);
        }
    }


    /**
     * Remove token from database in order to invalidate it
     *
     * @param tokenStr the full JWT token. It will be parsed and {@link TokenService#revokeToken(Token)} method will be invoked.
     * @throws TokenNotFoundException if given token does not exist
     */
    public void revokeToken(String tokenStr) throws TokenNotFoundException, TokenExpiredException {
        revokeToken ( parseToken(tokenStr) );
    }

    /**
     * Remove token from database in order to invalidate it
     *
     * @param token a {@link Token} object to be removed from database
     * @throws TokenNotFoundException if given token does not exist
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
     * @return a list with all active tokens or an empty list if none.
     */
    public List<Token> listActiveTokens() {

        try {
            List<Token> tokens = repository.listTokens();
            if( tokens == null ){
                tokens = new ArrayList<>();
            }
            return tokens;
        } catch (Exception e) {
            log.log(Level.WARNING, "Failed to list active tokens.", e);
            return null;
        }
    }

    /**
     * Parse JWT string to a {@link Token} object
     * @param tokenStr a full JWT token to be parsed into a Token object.
     * @return a {@link Token} object
     */
    Token parseToken(String tokenStr) throws TokenExpiredException {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSignatureKey())
                    .build().parseSignedClaims(tokenStr)
                    .getPayload();

            List<String> roles = null;
            if( claims.get(Token.ROLES_KEY) != null ) {
                roles = Arrays.asList(claims.get(Token.ROLES_KEY).toString().split(","));
            }

            return new Token(claims.getId(),tokenStr,claims.getSubject(),roles,claims.getIssuedAt(),claims.getExpiration(), SIGN_KEY);
        } catch (ExpiredJwtException|MalformedJwtException|SecurityException e) {
            log.log(Level.WARNING, "Failed to parse token with the provided string.", e);
            throw new TokenExpiredException( e.getMessage() );
        }
    }
}
