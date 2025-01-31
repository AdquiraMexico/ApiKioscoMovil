package mx.com.flap.apikioscomovil.repositories;

import mx.com.flap.apikioscomovil.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Retrieves a user by their username.
     *
     * @param username the username to search for
     * @return an {@code Optional} containing the user if found, or empty if no user exists with the given username
     */
    Optional<User> findByUsername(String username);
}
