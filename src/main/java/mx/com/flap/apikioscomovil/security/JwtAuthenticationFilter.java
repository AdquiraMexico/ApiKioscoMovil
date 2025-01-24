package mx.com.flap.apikioscomovil.security;

import com.amazonaws.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import mx.com.flap.apikioscomovil.handlers.CustomeException;
import mx.com.flap.apikioscomovil.requests.UsuarioRequest;
import mx.com.flap.apikioscomovil.resources.AuthenticationResource;
import mx.com.flap.apikioscomovil.service.JwtService;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    private JwtService jwtService;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtService jwtService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            String header = request.getHeader("Authorization");

            if (header != null && header.startsWith("Basic")) {
                header = header.replace("Basic ", "");
                String tokenBasic = new String(Base64.decode(header.getBytes()));
                if (!tokenBasic.split(":")[0].equals("kioscomovil") || !tokenBasic.split(":")[1].equals("fL4p.4dM1n"))
                    throw new CustomeException("Cliente no valido");
            }

            UsuarioRequest userEntity = new ObjectMapper().readValue(request.getInputStream(), UsuarioRequest.class);
            String username = userEntity.getUsername();
            String password = userEntity.getPassword();

            request.setAttribute("username",userEntity.getUsername() );

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username,password);

            return authenticationManager.authenticate(authToken);
        } catch (IOException e) {
            log.error("Error {}", e.getMessage());
            throw new CustomeException(e.getMessage());
        }

    }



    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        AuthenticationResource token = jwtService.create(authResult);

        response.addHeader("Authorization", "Bearer " + token);
        response.getWriter().write(new ObjectMapper().writeValueAsString(token));
        response.setStatus(200);
        response.setContentType("application/json");
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        String username = String.valueOf(request.getAttribute("username"));

        log.info("USERNAME : {}", username);
        Map<String, Object> body = new HashMap<>();

        Boolean blocked = jwtService.failedAttemps(username);
        if (Boolean.TRUE == blocked) {
            body.put("message", "Se han detectado varios intentos fallidos de acceso con el mismo usuario, el usuario se ha bloqueado");
            body.put("error", failed.getMessage());
        } else {
            body.put("message", "Error en la autenticación: email o password incorrecto");
            body.put("error", failed.getMessage());
        }


        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(401);
        response.setContentType("application/json");
    }


}
