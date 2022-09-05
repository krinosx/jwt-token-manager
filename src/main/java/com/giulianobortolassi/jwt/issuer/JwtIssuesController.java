package com.giulianobortolassi.jwt.issuer;


import com.giulianobortolassi.jwt.token.Token;
import com.giulianobortolassi.jwt.token.TokenExpiredException;
import com.giulianobortolassi.jwt.token.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

@RestController
@RequestMapping("/v1/token")
public class JwtIssuesController {

    @Autowired
    private TokenService tokenService;

    private final int MAX_CREDENTIALS = 10;


    @RequestMapping(method = RequestMethod.POST )
    public ResponseEntity<String> generateToken(String user, String credentials) {
        if( user == null || user.isEmpty() ) {
            return ResponseEntity.badRequest().body( "User is mandatory." );
        }

        List<String> prividedCredentials = Collections.emptyList();
        if(!Objects.isNull(credentials) && !credentials.isEmpty()) {
            prividedCredentials = List.of(credentials.split(",",MAX_CREDENTIALS));
        }

        Token token = tokenService.generateToken(user, prividedCredentials);

        return new ResponseEntity<>(token.getToken(), HttpStatus.OK );
    }

    /**
     * Validate the given token
     *
     * @param token The challenging token.
     * @return a HTTP 200 and the token as the body if the token is valid with. An HTTP 403
     * https://tools.ietf.org/html/rfc7231#section-6.5.3 if token has expired or was not found.
     */
    @RequestMapping(value = "/{token:.+}", method = RequestMethod.GET )
    public ResponseEntity<String> checkToken(@PathVariable(name = "token") String token){
        try {
            Token token1 = tokenService.checkToken(token);
            return ResponseEntity.ok().body( token1.getToken() );
        } catch ( TokenExpiredException e ) {
            e.printStackTrace();
            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .body("Invalid Token.");
        }
    }

}
