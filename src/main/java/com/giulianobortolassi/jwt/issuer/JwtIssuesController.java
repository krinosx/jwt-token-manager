package com.giulianobortolassi.jwt.issuer;


import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/v1/token")
public class JwtIssuesController {


    @RequestMapping(value = "/generate", method = RequestMethod.POST )
    public ResponseEntity<String> generateToken(String user, List<String> credentials) {

        return new ResponseEntity<String>("Token", HttpStatus.OK );
    }

    @RequestMapping(value = "/validate", method = RequestMethod.POST )
    public ResponseEntity checkToken(String token){
        return ResponseEntity.ok().body("token");
    }

    @RequestMapping(value = "/revoke", method = RequestMethod.POST )
    public ResponseEntity revokeToken(String token){
        return ResponseEntity.ok().body("token");
    }

}
