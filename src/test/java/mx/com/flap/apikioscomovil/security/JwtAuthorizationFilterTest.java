package mx.com.flap.apikioscomovil.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import mx.com.flap.apikioscomovil.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;

import java.io.PrintWriter;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.*;

class JwtAuthorizationFilterTest {

    @Test
    void shouldAuthenticateWhenJwtIsValid() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        JwtService jwtService = mock(JwtService.class);
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

        JwtAuthorizationFilter filter = new JwtAuthorizationFilter(authenticationManager, jwtService);

        when(request.getHeader("Authorization")).thenReturn("Bearer valid.jwt.token");
        when(jwtService.validate("Bearer valid.jwt.token")).thenReturn(true);
        when(jwtService.getUsername("Bearer valid.jwt.token")).thenReturn("testUser");
        when(jwtService.getRoles("Bearer valid.jwt.token")).thenReturn(List.of());

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        verify(response, never()).setStatus(anyInt());
    }
    @Test
    void shouldAuthenticateWhenJwtIsInValid() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        JwtService jwtService = mock(JwtService.class);
        AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

        JwtAuthorizationFilter filter = new JwtAuthorizationFilter(authenticationManager, jwtService);

        when(request.getHeader("Authorization")).thenReturn("Basic aa");
        when(request.getRequestURI()).thenReturn("localhost:8080/api/v1/login");
        when(response.getWriter()).thenReturn(new PrintWriter(System.out));

        filter.doFilterInternal(request, response, chain);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(response).getWriter();
        verify(chain, never()).doFilter(request, response);
    }
}