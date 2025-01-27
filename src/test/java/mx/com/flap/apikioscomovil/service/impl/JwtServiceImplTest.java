package mx.com.flap.apikioscomovil.service.impl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.MalformedJwtException;
import lombok.extern.slf4j.Slf4j;
import mx.com.flap.apikioscomovil.entities.Profile;
import mx.com.flap.apikioscomovil.entities.User;
import mx.com.flap.apikioscomovil.repositories.UserRepository;
import mx.com.flap.apikioscomovil.resources.AuthenticationResource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Slf4j
class JwtServiceImplTest {

    @Mock
    private UserRepository userRepository = mock(UserRepository.class);
    @InjectMocks
    private JwtServiceImpl jwtService = new JwtServiceImpl(userRepository);

    UsernamePasswordAuthenticationToken authToken;
    UsernamePasswordAuthenticationToken authToken2;
    UserDetails user;
    User us = new User();
    @BeforeEach
    void init() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        user = new org.springframework.security.core.userdetails.User("admin1", "", authorities);
        us.setUsername("admin1");
        us.setAttempts(0L);
        us.setBlocked(false);
        Profile perfil = new Profile();
        perfil.setNombre("ADMINISTRADOR");
        perfil.setClave("admin");
        us.setPerfil(perfil);
        when(this.userRepository.findByUsername(anyString())).thenAnswer(invocation -> {
            String username = invocation.getArgument(0);
            if ("nullUser".equals(username)) {
                us.setAttempts(null);
            } else if ("lowAttemptsUser".equals(username)) {
                us.setAttempts(5L);
            } else if ("blockUser".equals(username)) {
                us.setAttempts(9L);
            } else {
                us.setAttempts(1L);
            }
            return Optional.of(us);
        });
        authToken = new UsernamePasswordAuthenticationToken(user, "");
    }
    @Test
    void create() {
        UsernamePasswordAuthenticationToken authTokenc = new UsernamePasswordAuthenticationToken(user, "");
        when(this.userRepository.findByUsername(anyString())).thenReturn(Optional.of(us));
        AuthenticationResource resp = this.jwtService.create(authTokenc);
        assertNotNull(resp);
    }
    @Test
    void createDev() {
        ReflectionTestUtils.setField(jwtService, "isDev", true);
        UsernamePasswordAuthenticationToken authTokenb = new UsernamePasswordAuthenticationToken(user, "");
        AuthenticationResource resp = this.jwtService.create(authTokenb);
        assertNotNull(resp);
    }
    @Test
    void validate() {
        UsernamePasswordAuthenticationToken authTokena = new UsernamePasswordAuthenticationToken(user, "");
        AuthenticationResource resp = this.jwtService.create(authTokena);
        Boolean respose = this.jwtService.validate("Bearer " + resp.getToken());
        assertTrue(respose);
    }
    @Test
    void validateInvalidToken() {
        // Simulate invalid token input
        String invalidToken = "Bearer invalid.token.string";
        Boolean result = this.jwtService.validate(invalidToken);

        // Ensure the validation fails
        assertFalse(result);
    }
    @Test
    void validateForExpiredToken() {
        // Set up a potentially expired token
        ReflectionTestUtils.setField(jwtService, "isDev", false);
        String expiredToken = "Bearer expired.token.string.simulating.jwt";

        Boolean result = this.jwtService.validate(expiredToken);

        // Ensure the validation fails
        assertFalse(result);
    }
    @Test
    void validateForEmptyToken() {
        // Test with empty input (# Validate an empty/blank token)
        String emptyToken = "Bearer ";
        Boolean result = this.jwtService.validate(emptyToken);

        // Ensure the validation fails
        assertFalse(result);
    }
    @Test
    void getClaimsInvalidToken() {
        // Simulate an invalid JWT token
        String invalidToken = "Bearer invalid.token.string";

        assertThrows(MalformedJwtException.class, () -> {
            jwtService.getClaims(invalidToken);
        });
    }
    @Test
    void getClaims() {
        AuthenticationResource auth = this.jwtService.create(authToken);
        Claims resp = this.jwtService.getClaims("Bearer " + auth.getToken());
        assertNotNull(resp);
    }
    @Test
    void getClaimsDev() {
        ReflectionTestUtils.setField(jwtService, "isDev", true);
        AuthenticationResource auth = this.jwtService.create(authToken);
        Claims resp = this.jwtService.getClaims("Bearer " + auth.getToken());
        assertNotNull(resp);
    }
    @Test
    void failedAttemptsForNewUser() {
        // Username with no attempts (simulates new user)
        String username = "nullUser";

        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Boolean isBlocked = jwtService.failedAttemps(username);

        assertFalse(isBlocked);
        verify(userRepository).save(us);
        assertEquals(1, us.getAttempts());
    }
    @Test
    void failedAttemptsForLowAttemptsUser() {
        // Username with low attempts
        String username = "lowAttemptsUser";
        User userb = new User();
        userb.setUsername(username);
        userb.setAttempts(3L);
        userb.setBlocked(false);
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(userb));
        when(userRepository.save(userb)).thenReturn(userb);

        Boolean isBlocked = jwtService.failedAttemps(username);

        assertFalse(isBlocked);
        assertEquals(5, us.getAttempts());
    }

    @Test
    void failedAttemptsForUserBlocking() {
        // Username with maximum attempts before blocking
        String username = "blockUser";
        User usera = new User();
        usera.setUsername(username);
        usera.setAttempts(4L);
        usera.setBlocked(true);
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(usera));
        when(userRepository.save(usera)).thenReturn(usera);

        Boolean isBlocked = jwtService.failedAttemps(username);

        assertTrue(isBlocked);
    }

    @Test
    void failedAttemptsForBlockedUser() {
        // Username for a user who is already blocked
        us.setBlocked(true);
        us.setAttempts(5L);

        Boolean isBlocked = jwtService.failedAttemps("blockUser");

        assertTrue(isBlocked);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void getRolesForEmptyToken() {
        String emptyToken = "Bearer ";
        assertThrows(IllegalArgumentException.class, () -> jwtService.getRoles(emptyToken));
    }
}