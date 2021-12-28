package si.fri.prpo.polnilnepostaje.sporocila.api.v1.viri;

import si.fri.prpo.polnilnepostaje.sporocila.api.v1.dtos.SporociloDTO;
import si.fri.prpo.polnilnepostaje.storitve.odjemalci.QRCodeGeneratorOdjemalec;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

@Path("sporocila")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@ApplicationScoped
public class SporocilaVir {

    @Inject
    private QRCodeGeneratorOdjemalec qrGenerator;

    private Logger log = Logger.getLogger(SporocilaVir.class.getName());

    private List<SporociloDTO> sporocila;

    @PostConstruct
    public void init() {

        sporocila = new ArrayList<>();

        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
        LocalDateTime datetime = LocalDateTime.now();

        sporocila.add(new SporociloDTO("Postaja ima poškodovan kabel za polnjenje.",
                2, datetime.format(dtf)));

        String emailContact = qrGenerator.vrniEmailQR();

        log.info("Vir za Sporocila se je ustvaril.");
    }

    @PreDestroy
    public void destroy() {
        log.info("Vir za Sporocila se je unicil.");
    }

    @GET
    public Response pridobiPorocila() {
        return Response.ok(sporocila).build();
    }

    @POST
    public Response dodajPorocilo(SporociloDTO sporociloDTO) {

        if(sporociloDTO != null) {
            sporocila.add(sporociloDTO);
        }

        log.info("Dodano novo sporocilo.");

        return Response.ok().build();
    }

    @GET
    @Path("/qr")
    public Response pridobiKodo() {
        return Response.ok(qrGenerator.vrniEmailQR()).build();
    }
}
