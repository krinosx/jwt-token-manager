package com.giulianobortolassi.jwt.token;

import java.util.List;

public interface TokenRepository {

    Token registerToken(Token token);

    Token removeToken(Token token) throws TokenNotFoundException;

    Token getToken(Token token) throws TokenNotFoundException;

    Token getTokenById(String id) throws TokenNotFoundException;

    // TODO implement filter options

    /**
     * Return a list with all active tokens.
     * @return a list with all active tokens or a empty list if none.
     */
    List<Token> listTokens();
}
