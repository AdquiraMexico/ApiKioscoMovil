package mx.com.flap.apikioscomovil.service.impl;



import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.com.flap.apikioscomovil.entities.Client;
import mx.com.flap.apikioscomovil.entities.Servicio;
import mx.com.flap.apikioscomovil.repository.ClientRepository;
import mx.com.flap.apikioscomovil.repository.ServiceRepository;
import mx.com.flap.apikioscomovil.request.ServiceRequest;
import mx.com.flap.apikioscomovil.response.ServiceResponse;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@RequiredArgsConstructor
@Slf4j
@Service
public class ServicioServiceImpl {

    @Autowired
    private  ServiceRepository serviceRepository;
    @Autowired
    private ClientRepository clientRepository;

    @Transactional
    public Servicio saveService(ServiceRequest request){
        Servicio servicio = new Servicio();

        servicio.setName(request.getName());
        servicio.setKeycode(request.getKeycode());
        servicio.setUrlimage(request.getUrlimage());

        Client client = clientRepository.findById(request.getClient()).orElseThrow();

        if(client != null)
            servicio.setClient(client);

        return serviceRepository.save(servicio);
    }

    public Servicio update(ServiceRequest request){
        Servicio servicio = findById(request.getIdService());

        servicio.setName(request.getName());
        servicio.setKeycode(request.getKeycode());
        servicio.setUrlimage(request.getUrlimage());



        return serviceRepository.save(servicio);
    }

    public List<ServiceResponse> findAllByClient(Long idClient){
        return serviceRepository.findAllByClient(idClient);
    }

    public Servicio findById(Long id){
        return serviceRepository.findById(id).orElseThrow();
    }

    public List<ServiceResponse> findAll(){
        List<Servicio> listServices = serviceRepository.findAll();
        List<ServiceResponse> serviceResponseList = new ArrayList<>();
        for (Servicio service : listServices){
            serviceResponseList.add(new ServiceResponse(service));
        }

        return serviceResponseList;
    }

    public void deleteServiceById(Long id){
        serviceRepository.deleteById(id);
    }
}
