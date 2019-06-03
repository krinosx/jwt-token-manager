package com.giulianobortolassi.jwt.token;

import java.util.List;

public interface TokenRepository {

    Token registerToken(Token token);

    Token removeToken(Token token) throws TokenNotFoundExcpetion;

    Token getToken(Token token) throws TokenNotFoundExcpetion;

    Token getTokenById(String id) throws TokenNotFoundExcpetion;

    // TODO implement filter options
    List<Token> listTokens() throws TokenNotFoundExcpetion;
}
