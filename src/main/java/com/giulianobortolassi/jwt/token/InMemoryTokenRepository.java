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
    public Token removeToken(Token token) throws TokenNotFoundExcpetion {
        return this.tokenDatabase.remove(token.getId());
    }

    @Override
    public Token getToken(Token token) throws TokenNotFoundExcpetion {
        Token token1 = this.tokenDatabase.get(token.getId());
        if( token1 == null ) {
            throw new TokenNotFoundExcpetion();
        }
        return  token1;
    }

    @Override
    public Token getTokenById(String id) throws TokenNotFoundExcpetion {
        return this.tokenDatabase.get(id);
    }

    @Override
    public List<Token> listTokens() throws TokenNotFoundExcpetion {
        return new ArrayList<>(this.tokenDatabase.values());
    }
}
