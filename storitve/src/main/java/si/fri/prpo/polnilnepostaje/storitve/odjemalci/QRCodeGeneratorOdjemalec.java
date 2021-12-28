package si.fri.prpo.polnilnepostaje.storitve.odjemalci;

import si.fri.prpo.polnilnepostaje.storitve.config.PropertiesReader;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.WebApplicationException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.logging.Logger;

@ApplicationScoped
public class QRCodeGeneratorOdjemalec {

    private static Logger log = Logger.getLogger(QRCodeGeneratorOdjemalec.class.getName());

    private String baseUrl;
    private String apiKey;

    @PostConstruct
    private void init() throws IOException {

        log.info("Inicializacija zrna " + QRCodeGeneratorOdjemalec.class.getSimpleName());
        baseUrl = "https://multi-qr-generator.p.rapidapi.com/qrScan/url/";

        apiKey = PropertiesReader.getApiKey();
    }

    public String vrniEmailQR() {

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "MAILTO:prpo@fri.si"))
                    .header("x-rapidapi-host", "multi-qr-generator.p.rapidapi.com")
                    .header("x-rapidapi-key", apiKey)
                    .method("GET", HttpRequest.BodyPublishers.noBody())
                    .build();

            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            return response.body().substring(48, response.body().length()-56);

        } catch (WebApplicationException | ProcessingException | IOException | InterruptedException e) {
            log.severe(e.getMessage());
            throw new InternalServerErrorException(e);
        }
    }
}
