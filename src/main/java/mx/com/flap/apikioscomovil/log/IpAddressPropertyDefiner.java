package mx.com.flap.apikioscomovil.log;

import ch.qos.logback.core.PropertyDefinerBase;
import mx.com.flap.apikioscomovil.handlers.CustomeException;
import org.apache.commons.lang3.StringUtils;

import java.net.*;
import java.util.Enumeration;

public class IpAddressPropertyDefiner extends PropertyDefinerBase {

    @Override
    public String getPropertyValue() {
        try {
            return getIPv4InetAddress().getHostAddress();
        } catch (SocketException | UnknownHostException e) {
            return StringUtils.EMPTY;
        }
    }

    private InetAddress getIPv4InetAddress() throws SocketException, UnknownHostException {

        String os = System.getProperty("os.name").toLowerCase();

        if(os.contains("nix") || os.contains("nux")) {
            NetworkInterface ni = NetworkInterface.getByName("eth0");
            if (ni == null && NetworkInterface.networkInterfaces().findFirst().isPresent()) {
                    ni = NetworkInterface.networkInterfaces().findFirst().orElseThrow(() -> new CustomeException("Interface don't found"));
                }

            assert ni != null;
            Enumeration<InetAddress> ias = ni.getInetAddresses();

            InetAddress iaddress;
            do {
                iaddress = ias.nextElement();
            } while(!(iaddress instanceof Inet4Address));

            return iaddress;
        }

        return InetAddress.getLocalHost();
    }
}
