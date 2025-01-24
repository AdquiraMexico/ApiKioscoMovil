package mx.com.flap.apikioscomovil.repositories;

import mx.com.flap.apikioscomovil.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepostory extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
}
