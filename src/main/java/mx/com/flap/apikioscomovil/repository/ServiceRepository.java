package mx.com.flap.apikioscomovil.repository;

import mx.com.flap.apikioscomovil.entities.Servicio;
import mx.com.flap.apikioscomovil.repository.jpa.ServiceRepositoryJpa;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ServiceRepository extends JpaRepository<Servicio, Long>, ServiceRepositoryJpa {


}
