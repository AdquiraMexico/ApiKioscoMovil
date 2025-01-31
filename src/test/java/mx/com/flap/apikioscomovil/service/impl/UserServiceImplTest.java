package mx.com.flap.apikioscomovil.service.impl;


import mx.com.flap.apikioscomovil.entities.Profile;
import mx.com.flap.apikioscomovil.entities.User;
import mx.com.flap.apikioscomovil.handlers.CustomeException;
import mx.com.flap.apikioscomovil.repositories.UserRepository;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.security.core.userdetails.UserDetails;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;


class UserServiceImplTest {

    @Mock
    UserRepository userRepository = mock(UserRepository.class);

    @InjectMocks
    UserServiceImpl userService = new UserServiceImpl(userRepository);


    @Test
    void loadUserByUsernameTest() {
        User user = new User();
        user.setUsername("admin");
        user.setBlocked(false);
        user.setPassword("password");
        Profile profile = new Profile();
        profile.setNombre("ADMINISTRADOR");
        profile.setClave("admin");
        user.setPerfil(profile);
        when(userRepository.findByUsername("admin")).thenReturn(java.util.Optional.of(user));
        UserDetails userDetails = userService.loadUserByUsername("admin");
        assertNotNull(userDetails);
    }

    @Test
    void loadUserByUsernameTestBlocked() {
        User user = new User();
        user.setUsername("admin");
        user.setBlocked(true);
        user.setPassword("password");
        when(userRepository.findByUsername("admin")).thenReturn(java.util.Optional.of(user));
        assertThrows(CustomeException.class, () -> userService.loadUserByUsername("admin"));
    }


}