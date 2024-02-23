import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;

public class RSAClient {
    public static void main(String[] args) throws Exception {
        // Crear el socket del cliente y conectarse al servidor en la dirección IP y puerto especificados
        Socket clientSocket = new Socket("localhost", Integer.parseInt(args[0]));
        System.out.println("Conexión establecida con el servidor en la dirección IP " + clientSocket.getInetAddress().getHostAddress());
        String message = args[1];
        // Crear los flujos de entrada y salida de datos del socket
        DataInputStream input = new DataInputStream(clientSocket.getInputStream());
        DataOutputStream output = new DataOutputStream(clientSocket.getOutputStream());

        // Recibe y almacena la clave pública del servidor
        PublicKey publicKey = getPublicKey(input);

        // Cifrar el mensaje con la clave pública del servidor
        byte[] secretMessage = cypherMessage(publicKey, message);
        String encodedMessage = Base64.getEncoder().encodeToString(secretMessage);
        // Enviar el mensaje cifrado al servidor
        output.writeInt(encodedMessage.length());
        output.write(encodedMessage.getBytes());
        // Cerrar el socket del cliente
        clientSocket.close();
    }

    /**
     * Retrieves the public key from the given input stream.
     *
     * @param  input  the input stream from which to retrieve the public key
     * @return       the public key retrieved from the input stream
     */
    private static PublicKey getPublicKey(DataInputStream input) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        int length = input.readInt();
        byte[] publicKeyBytes = new byte[length];
        input.readFully(publicKeyBytes);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    /**
     * Encrypts a message using the RSA algorithm with the given public key. The message is
     * encrypted using the public key and the result is returned as a byte array.
     *
     * @param  publicKey  the public key used for encryption
     * @param  message    the message to be encrypted
     * @return            the encrypted message as a byte array
     */
    private static byte[] cypherMessage(PublicKey publicKey, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
    //    byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        return encryptCipher.doFinal(message.getBytes());
    }


}