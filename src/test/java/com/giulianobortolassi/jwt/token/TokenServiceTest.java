package com.giulianobortolassi.jwt.token;

import org.assertj.core.api.Assertions;

import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

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
            public Token answer(InvocationOnMock invocationOnMock) {
                Object[] arguments = invocationOnMock.getArguments();
                return (Token) arguments[0];
            }
        });

        List<String> roles =  List.of("ADMIN","AUDIT");

        try {

            assertThat(service).as("Fail to inject TokenService.").isNotNull();

            Token generatedToken = service.generateToken("my_superuser", roles);

            assertThat(generatedToken).isNotNull();
            verify(tokenRepository).registerToken(any());

            List<String> rolesResult = generatedToken.getRoles();
            assertThat(rolesResult).isNotNull();
            assertThat(rolesResult.size()).isEqualTo(2);
            assertThat(generatedToken.getUser().toLowerCase()).isEqualTo("my_superuser");

            assertThat(rolesResult).containsExactlyInAnyOrder("ADMIN","AUDIT");


        } catch (Exception e) {
            e.printStackTrace();
            Assertions.fail("Unexpected exception");
        }
    }

    /**
     * Points to Check
     *  - Role name generation
     *  - Expiration Time
     *  - call to register token
     *
     */
    @Test
    public void generateTokenWithoutRoles() {

        // Created a mock to avoid repository logic contamination
        when(tokenRepository.registerToken(any())).thenAnswer(new Answer<Token>() {
            @Override
            public Token answer(InvocationOnMock invocationOnMock) {
                Object[] arguments = invocationOnMock.getArguments();
                return (Token) arguments[0];
            }
        });



        try {
            assertThat(service).as("Fail to inject TokenService.").isNotNull();

            Token generatedToken = service.generateToken("my_superuser", null);

            assertThat(generatedToken).isNotNull();
            verify(tokenRepository).registerToken(any());

            List<String> rolesResult = generatedToken.getRoles();
            assertThat(rolesResult).isNull();

            assertThat(generatedToken.getUser().toLowerCase()).isEqualTo("my_superuser");

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
                public Token answer(InvocationOnMock invocationOnMock) {
                    return token;
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }

        try {
            Token tokenRetorno = service.checkToken(token);
            assertThat(tokenRetorno).isNotNull();

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
                public Token answer(InvocationOnMock invocationOnMock) {
                    return token;
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }

        try {
            Token ignored = service.checkToken(token);
            fail("Expected an exception");
        } catch (TokenExpiredException e) {
            assertThat( e ).isNotNull();
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected Exception");
        }

    }

    /**
     * The check token method need token ID and expiration dates set
     * <p>
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
            fail( e.getMessage() );
        }

        try {
            Token ignored = service.checkToken(token);
            fail("Expected an exception");
        } catch (TokenExpiredException e) {
            assertThat( e ).isNotNull();
            assertThat( e.getMessage()).isNotNull();
            assertThat( e.getMessage()).isEqualTo("Invalid token.");
            assertThat( e ).hasCauseExactlyInstanceOf(TokenNotFoundException.class);

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected Exception");
        }

    }

    /**
     * Check call to removeToken with Valid Token
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
            fail(e.getMessage());
        }

        try {
            service.revokeToken(token);

            verify(tokenRepository, times(1)).removeToken(token);

        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
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
            fail(e.getMessage());
        }

        try {
            service.revokeToken(token);
            fail("Exception expected");
        } catch (TokenNotFoundException e) {
            assertThat(e).isNotNull();
            assertThat(e).isInstanceOf(TokenNotFoundException.class);

        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void listActiveTokens() {

        String uuid = UUID.randomUUID().toString();

        when(tokenRepository.listTokens()).thenAnswer(new Answer<List<Token>>() {
            @Override
            public List<Token> answer(InvocationOnMock invocationOnMock) {

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

        assertThat(tokens).isNotNull();
        assertThat(tokens.size()).isEqualTo(3);
        for( Token tok : tokens ){
            assertThat(tok.getId()).isEqualTo(uuid);
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
            public List<Token> answer(InvocationOnMock invocationOnMock) {
                return null;
            }
        });

        List<Token> tokens = service.listActiveTokens();
        assertThat(tokens).isNotNull();
        assertThat(tokens.size()).isEqualTo(0);
    }
}