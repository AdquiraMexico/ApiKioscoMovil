package mx.com.flap.apikioscomovil.repository.jpa.impl;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.com.flap.apikioscomovil.entities.Client;
import mx.com.flap.apikioscomovil.entities.Servicio;
import mx.com.flap.apikioscomovil.repository.jpa.ServiceRepositoryJpa;
import mx.com.flap.apikioscomovil.response.ServiceResponse;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
@Slf4j
@RequiredArgsConstructor
public class ServiceRepositoryImpl implements ServiceRepositoryJpa {
    @PersistenceContext
    private EntityManager em;
    @Override
    public List<ServiceResponse> findAllByClient(Long clientId) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery cq = cb.createQuery(ServiceResponse.class);

        Root<Servicio> entity = cq.from(Servicio.class);

        Join<Servicio, Client> servClient = entity.join("client", JoinType.INNER);

        List<Predicate> predicates = new ArrayList<>();

        predicates.add(cb.equal(servClient.get("clientid"), clientId));

        cq.multiselect(entity.get("idService"),
                       entity.get("name"),
                       entity.get("keycode"),
                       entity.get("urlimage")
                        );

        cq.where(predicates.toArray(new Predicate[0]));

        return em.createQuery(cq).getResultList();
    }

}
