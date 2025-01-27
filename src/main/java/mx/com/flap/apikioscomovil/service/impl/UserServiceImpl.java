package mx.com.flap.apikioscomovil.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.com.flap.apikioscomovil.entities.User;
import mx.com.flap.apikioscomovil.handlers.CustomeException;
import mx.com.flap.apikioscomovil.repositories.UserRepository;
import mx.com.flap.apikioscomovil.service.UserService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = this.userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("El usuario no existe"));
        if (Boolean.TRUE == user.getBlocked()) {
            throw new CustomeException("Unauthorized");
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(() -> user.getPerfil().getNombre());
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }
}
