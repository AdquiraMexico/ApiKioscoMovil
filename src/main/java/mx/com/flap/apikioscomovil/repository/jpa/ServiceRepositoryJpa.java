package mx.com.flap.apikioscomovil.repository.jpa;

import mx.com.flap.apikioscomovil.response.ServiceResponse;

import java.util.List;

public interface ServiceRepositoryJpa  {

    List<ServiceResponse> findAllByClient(Long clientId);
}
