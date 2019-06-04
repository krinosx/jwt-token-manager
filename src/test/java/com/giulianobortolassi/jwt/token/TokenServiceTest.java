package com.giulianobortolassi.jwt.token;

import io.jsonwebtoken.lang.Collections;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(SpringRunner.class)
@SpringBootTest
public class TokenServiceTest {

    @Autowired
    private TokenService service;

    @MockBean
    TokenRepository tokenRepository;

    /**
     * Points to Check
     *  - Role name generation
     *  - Expiration Time
     *  - call to register token
     *
     */
    @Test
    public void generateToken() {

        // Created a mock to avoid repository logic contamination
        when(tokenRepository.registerToken(any())).thenAnswer(new Answer<Token>() {
            @Override
            public Token answer(InvocationOnMock invocationOnMock) throws Throwable {
                Object[] arguments = invocationOnMock.getArguments();
                return (Token) arguments[0];
            }
        });

        List<String> roles = new ArrayList<>(Collections.arrayToList(new String[]{"ADMIN","AUDIT"}));

        try {
            assertNotNull("Fail to inject TokenService.",service);

            Token my_superuser = service.generateToken("my_superuser", roles);

            assertNotNull(my_superuser);
            verify(tokenRepository).registerToken(any());

            List<String> rolesResult = my_superuser.getRoles();
            assertNotNull(rolesResult);
            assertTrue(rolesResult.size()==2 );
            assertThat( rolesResult, containsInAnyOrder("ADMIN","AUDIT") );

        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail("Unexpected exception");
        }
    }

    /**
     * The check token method need token ID and expiration dates set
     */
    @Test
    public void checkTokenValid() {

        Date issuedTime = new Date(System.currentTimeMillis());
        Date expireTime = new Date(issuedTime.getTime() + 10000 ); // 10 sec to expire

        Token token = new Token();
        token.setToken("Valid token");
        token.setUser("my_user");
        token.setRoles(null);
        token.setId("123-456");
        token.setIssuedTime(issuedTime);
        token.setExpirationTime(expireTime);

        // Created a mock to avoid repository logic contamination
        try {
            when(tokenRepository.getTokenById("123-456")).thenAnswer(new Answer<Token>() {
                @Override
                public Token answer(InvocationOnMock invocationOnMock) throws Throwable {
                    return token;
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

        try {
            Token tokenRetorno = service.checkToken(token);
            assertNotNull(tokenRetorno);

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected Exception");
        }

    }

    /**
     * The check token method need token ID and expiration dates set
     */
    @Test
    public void checkTokenExpired() {

        Date issuedTime = new Date(System.currentTimeMillis() - 10000); // 10 sec in the past
        Date expireTime = new Date(System.currentTimeMillis() - 5000 ); // 5 sec in the past, token expired

        Token token = new Token();
        token.setToken("Valid token");
        token.setUser("my_user");
        token.setRoles(null);
        token.setId("123-456");
        token.setIssuedTime(issuedTime);
        token.setExpirationTime(expireTime);

        // Created a mock to avoid repository logic contamination
        try {
            when(tokenRepository.getTokenById("123-456")).thenAnswer(new Answer<Token>() {
                @Override
                public Token answer(InvocationOnMock invocationOnMock) throws Throwable {
                    return token;
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

        try {
            Token tokenRetorno = service.checkToken(token);
            fail("Expected an exception");
        } catch (TokenExpiredException e) {
            assertNotNull( e );
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected Exception");
        }

    }

    /**
     * The check token method need token ID and expiration dates set
     *
     * This test check the scenario where token is not in database
     *
     */
    @Test
    public void checkTokenNotFound() {

        Date issuedTime = new Date(System.currentTimeMillis()); // 10 sec in the past
        Date expireTime = new Date(System.currentTimeMillis() + 10000 ); // 5 sec in the past, token expired

        Token token = new Token();
        token.setToken("Valid token");
        token.setUser("my_user");
        token.setRoles(null);
        token.setId("123-456");
        token.setIssuedTime(issuedTime);
        token.setExpirationTime(expireTime);

        // Created a mock to avoid repository logic contamination
        try {
            when(tokenRepository.getTokenById("123-456")).thenAnswer(new Answer<Token>() {
                @Override
                public Token answer(InvocationOnMock invocationOnMock) throws Throwable {
                    throw new TokenNotFoundException();
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

        try {
            Token tokenRetorno = service.checkToken(token);
            fail("Expected an exception");
        } catch (TokenExpiredException e) {
            assertNotNull( e );
            assertNotNull(e.getMessage());
            assertTrue(e.getMessage().equalsIgnoreCase("Invalid token.") );
            assertTrue( e.getCause() instanceof TokenNotFoundException);

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected Exception");
        }

    }

    /**
     * Check call to removeToeken with Valid Token
     */
    @Test
    public void revokeTokenValid() {
        Token token = new Token();
        token.setId("123-456");
        token.setToken("Valid token");
        token.setUser("my_user");

        // Created a mock to avoid repository logic contamination
        try {
            when(tokenRepository.getTokenById("123-456")).thenAnswer(new Answer<Token>() {
                @Override
                public Token answer(InvocationOnMock invocationOnMock) {
                    return token;
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

        try {
            service.revokeToken(token);

            verify(tokenRepository, times(1)).removeToken(token);

        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

    }

    /**
     * Check call to removeToeken with NonExistent token
     */
    @Test
    public void revokeTokenInvalid() {
        Token token = new Token();
        token.setId("123-456");
        token.setToken("Valid token");
        token.setUser("my_user");

        // Created a mock to avoid repository logic contamination
        try {
            when(tokenRepository.getTokenById("123-456")).thenAnswer(new Answer<Token>() {
                @Override
                public Token answer(InvocationOnMock invocationOnMock) throws Throwable {
                    throw new TokenNotFoundException();
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

        try {
            service.revokeToken(token);
            fail("Exception expected");
        } catch (TokenNotFoundException e){
            assertNotNull(e);
            assertTrue(e instanceof TokenNotFoundException);

        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void listActiveTokens() {

        String uuid = UUID.randomUUID().toString();

        when(tokenRepository.listTokens()).thenAnswer(new Answer<List<Token>>() {
            @Override
            public List<Token> answer(InvocationOnMock invocationOnMock) throws Throwable {

                List<Token> tokenList = new ArrayList<>();

                Token token = new Token();
                token.setId(uuid);

                tokenList.add(token);
                tokenList.add(token);
                tokenList.add(token);

                return tokenList;

            }
        });

        List<Token> tokens = service.listActiveTokens();

        assertNotNull(tokens);
        assertTrue(tokens.size() == 3);
        for( Token tok : tokens ){
            assertEquals(tok.getId(), uuid);
        }
    }

    /**
     * Check behavior when the list is empty. The service must return an empty list
     * instead of null
     */
    @Test
    public void listActiveTokensEmpty() {

        when(tokenRepository.listTokens()).thenAnswer(new Answer<List<Token>>() {
            @Override
            public List<Token> answer(InvocationOnMock invocationOnMock) throws Throwable {
                return null;
            }
        });

        List<Token> tokens = service.listActiveTokens();
        assertNotNull(tokens);
        assertTrue(tokens.size() == 0);
    }
}