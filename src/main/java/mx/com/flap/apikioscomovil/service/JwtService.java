package mx.com.flap.apikioscomovil.service;

import io.jsonwebtoken.Claims;
import mx.com.flap.apikioscomovil.resources.AuthenticationResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public interface JwtService {

    AuthenticationResource create(Authentication auth);

    Boolean validate(String token);

    Claims getClaims(String token);

    String getUsername(String token);

    Collection<GrantedAuthority> getRoles(String token);

    String resolve(String token);

    Boolean failedAttemps(String username);
}
