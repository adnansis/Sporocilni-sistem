package si.fri.prpo.polnilnepostaje.storitve.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public final class PropertiesReader {

    public static String getApiKey() throws IOException {

        try {
            return new String(Files.readAllBytes(Paths.get("C:\\Users\\adnan\\Desktop\\Sporocilni-sistem\\apikey.properties")));
        } catch (IOException e) {
            throw new IOException(e);
        }
    }
}