package com.giulianobortolassi.jwt.manager;


import com.giulianobortolassi.jwt.token.Token;
import com.giulianobortolassi.jwt.token.TokenExpiredException;
import com.giulianobortolassi.jwt.token.TokenNotFoundException;
import com.giulianobortolassi.jwt.token.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/v1/manager/token")
public class JwtManagerController {

    @Autowired
    private TokenService tokenService;

    @RequestMapping(method = RequestMethod.GET )
    public ResponseEntity<List<Token>> listTokens(String token){
        List<Token> tokens = tokenService.listActiveTokens();

        // TODO: remove token sign keys
        tokens.forEach(token1 -> token1.setSignKey("***"));
        return ResponseEntity.ok().body(tokens);
    }

    @RequestMapping(value = "/{tokenId:.+}", method = RequestMethod.DELETE )
    public ResponseEntity revokeToken(@PathVariable(name = "tokenId") String token){
        try {
            tokenService.revokeToken(token);
        } catch (TokenNotFoundException | TokenExpiredException e) {
            e.printStackTrace();
            // Log trying to expire token
        }
        return ResponseEntity.ok().body("Token expired.");
    }
}
