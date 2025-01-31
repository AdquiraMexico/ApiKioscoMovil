package mx.com.flap.apikioscomovil.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import mx.com.flap.apikioscomovil.handlers.CustomeException;
import mx.com.flap.apikioscomovil.requests.UsuarioRequest;
import mx.com.flap.apikioscomovil.resources.AuthenticationResource;
import mx.com.flap.apikioscomovil.service.JwtService;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.mock.web.DelegatingServletInputStream;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {

    @Mock
    AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

    @Mock
    JwtService jwtService = mock(JwtService.class);

    @InjectMocks
    JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtService);

    @Test
    void JwtAuthenticationFilter() {
        jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtService);
        assertNotNull(jwtAuthenticationFilter);
    }
    @Test
    void attemptAuthentication() throws IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        UsuarioRequest usuarioRequest;

        String json = "{\"username\": \"testUser\", \"password\": \"testPass\", \"kiosco\": \"123\"}";
        ServletInputStream inputStream = new DelegatingServletInputStream(new ByteArrayInputStream(json.getBytes()));

        when(request.getInputStream()).thenReturn(inputStream);
        usuarioRequest = new ObjectMapper().readValue(json, UsuarioRequest.class);
        Authentication authentication = new UsernamePasswordAuthenticationToken(usuarioRequest.getUsername(), usuarioRequest.getPassword());
        when(authenticationManager.authenticate(authentication)).thenReturn(authentication);
        Authentication result = jwtAuthenticationFilter.attemptAuthentication(request, response);
        assertNotNull(result);
    }

    @Test
    void attemptAuthenticationValidAuthorizationHeader() throws IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        String headerValue = "Basic a2lvc2NvbW92aWw6Zkw0cC40ZE0xbg==";
        String json = "{\"username\": \"testUser\", \"password\": \"testPass\"}";

        when(request.getHeader("Authorization")).thenReturn(headerValue);
        when(request.getInputStream()).thenReturn(new DelegatingServletInputStream(new ByteArrayInputStream(json.getBytes())));
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken("testUser", "testPass");
        when(authenticationManager.authenticate(authToken)).thenReturn(authToken);

        Authentication authResult = jwtAuthenticationFilter.attemptAuthentication(request, response);

        assertNotNull(authResult);
        assertEquals("testUser", authResult.getName());
    }

    @Test
    void attemptAuthenticationInvalidAuthorizationHeader() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        String invalidHeaderValue = "Basic invalidHeaderValue";

        when(request.getHeader("Authorization")).thenReturn(invalidHeaderValue);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> jwtAuthenticationFilter.attemptAuthentication(request, response));
        assertNotNull(exception);
    }

    @Test
    void attemptAuthenticationIOException() throws IOException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getInputStream()).thenThrow(new IOException("Stream error"));

        CustomeException exception = assertThrows(CustomeException.class, () -> jwtAuthenticationFilter.attemptAuthentication(request, response));
        assertEquals("Stream error", exception.getMessage());
    }
    @Test
    void successfulAuthenticationAddsAuthorizationHeader() throws IOException, ServletException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        Authentication authResult = mock(Authentication.class);
        AuthenticationResource mockToken = new AuthenticationResource();

        when(jwtService.create(authResult)).thenReturn(mockToken);
        when(response.getWriter()).thenReturn(mock(PrintWriter.class));
        jwtAuthenticationFilter.successfulAuthentication(request, response, filterChain, authResult);

        verify(response).addHeader("Authorization", "Bearer " + mockToken);
        verify(response).setStatus(200);
        verify(response).setContentType("application/json");
        verify(response.getWriter()).write(new ObjectMapper().writeValueAsString(mockToken));
    }

    @Test
    void successfulAuthenticationWritesValidResponseBody() throws IOException, ServletException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        Authentication authResult = mock(Authentication.class);
        AuthenticationResource testToken = new AuthenticationResource();

        when(jwtService.create(authResult)).thenReturn(testToken);
        when(response.getWriter()).thenReturn(mock(PrintWriter.class));
        jwtAuthenticationFilter.successfulAuthentication(request, response, filterChain, authResult);

        verify(response.getWriter()).write(new ObjectMapper().writeValueAsString(testToken));
        verify(response).setStatus(200);
        verify(response).setContentType("application/json");
    }

    @Test
    void unsuccessfulAuthenticationWritesErrorResponse() throws IOException, ServletException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        AuthenticationException failed = mock(AuthenticationException.class);

        when(request.getAttribute("username")).thenReturn("testUser");
        when(failed.getMessage()).thenReturn("Authentication Failed");
        when(response.getWriter()).thenReturn(mock(PrintWriter.class));

        jwtAuthenticationFilter.unsuccessfulAuthentication(request, response, failed);

        verify(response).setContentType("application/json");
        verify(response).setStatus(401);

        Map<String, Object> expectedResponseBody = new HashMap<>();
        expectedResponseBody.put("message", "Error en la autenticación: email o password incorrecto");
        expectedResponseBody.put("error", "Authentication Failed");

        verify(response.getWriter()).write(new ObjectMapper().writeValueAsString(expectedResponseBody));
    }

    @Test
    void unsuccessfulAuthenticationSetsCorrectResponseStatus() throws IOException, ServletException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        AuthenticationException failed = mock(AuthenticationException.class);
        when(response.getWriter()).thenReturn(mock(PrintWriter.class));
        jwtAuthenticationFilter.unsuccessfulAuthentication(request, response, failed);

        verify(response).setStatus(401);
        verify(response).setContentType("application/json");
    }

    @Test
    void unsuccessfulAuthenticationFailsWithUsername() throws IOException, ServletException {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        AuthenticationException failed = mock(AuthenticationException.class);

        when(request.getAttribute("username")).thenReturn("testUser");
        when(response.getWriter()).thenReturn(mock(PrintWriter.class));
        jwtAuthenticationFilter.unsuccessfulAuthentication(request, response, failed);

        verify(jwtService).failedAttemps("testUser");
    }
}