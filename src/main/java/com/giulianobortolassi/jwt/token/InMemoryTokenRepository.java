package com.giulianobortolassi.jwt.token;

import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@Repository
public class InMemoryTokenRepository implements TokenRepository {

    private HashMap<String, Token> tokenDatabase = new HashMap<>();

    @Override
    public Token registerToken(Token token) {
        this.tokenDatabase.put(token.getId(), token);
        return token;
    }

    @Override
    public Token removeToken(Token token) throws TokenNotFoundException {
        Token removedToken = this.tokenDatabase.remove(token.getId());
        if( removedToken == null ) {
            throw new TokenNotFoundException();
        }
        return removedToken;
    }

    @Override
    public Token getToken(Token token) throws TokenNotFoundException {
        Token token1 = this.tokenDatabase.get(token.getId());
        if( token1 == null ) {
            throw new TokenNotFoundException();
        }
        return  token1;
    }

    @Override
    public Token getTokenById(String id) throws TokenNotFoundException {
        Token token = this.tokenDatabase.get(id);
        if( token == null ) {
            throw new TokenNotFoundException();
        }
        return token;
    }

    @Override
    public List<Token> listTokens() {
        return new ArrayList<>(this.tokenDatabase.values());
    }
}
