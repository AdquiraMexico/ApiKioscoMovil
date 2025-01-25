package mx.com.flap.apikioscomovil.repository;

import mx.com.flap.apikioscomovil.entities.Client;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<Client, Long> {
}
