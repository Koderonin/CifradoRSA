import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Base64;

public class RSAServer {
    public static void main(String[] args) throws Exception {
        // Crear el socket del servidor en el puerto 8080
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Servidor escuchando en el puerto 8080...");

        // Aceptar la conexión del cliente
        Socket clientSocket = serverSocket.accept();
        System.out.println("Cliente conectado desde la dirección IP " + clientSocket.getInetAddress().getHostAddress());

        // Crear los flujos de entrada y salida de datos del socket
        DataInputStream input = new DataInputStream(clientSocket.getInputStream());
        DataOutputStream output = new DataOutputStream(clientSocket.getOutputStream());

        // Generar el par de claves RSA
        KeyPair pair = generateRSAKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        // Enviar la clave pública al cliente
        byte[] publicKeyBytes = publicKey.getEncoded();
        output.writeInt(publicKeyBytes.length);
        output.write(publicKeyBytes);

        // Recibo el mensaje del cliente y lo desencripto
        byte[] decryptedMessage = getDecryptedMessage(input, privateKey);
        // Muestro el mensaje original
        System.out.println("Mensaje original: " + new String(decryptedMessage));

        // Cerrar el socket del servidor
        serverSocket.close();
    }
    /**
     * Decrypts a message using the provided DataInputStream and PrivateKey.
     * Useful for streams of data received from the client in primitive Java types.
     *
     * @param  input       the input stream containing the encrypted message
     * @param  privateKey  the private key used for decryption
     * @return             the decrypted message
     */
    private static byte[] getDecryptedMessage(DataInputStream input, PrivateKey privateKey) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        int length = input.readInt();
        byte[] secretMessage64 = new byte[length];
        input.readFully(secretMessage64);
        // Desencriptar el mensaje cifrado con BASE64
        byte[] secretMessage = Base64.getDecoder().decode(secretMessage64);
        // Descifrar el mensaje con la clave privada
        return decryptMessage(privateKey, secretMessage);
    }

    /**
     * Decrypts a secret message using the provided private key.
     *
     * @param  privateKey     the private key used for decryption
     * @param  secretMessage  the encrypted message to be decrypted
     * @return                the decrypted message
     */
    private static byte[] decryptMessage(PrivateKey privateKey, byte[] secretMessage) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decryptCipher.doFinal(secretMessage);
    }

    /**
     * Método para generar el par de claves RSA
     * @return el par de claves RSA generado
     * @throws Exception si ocurre un error durante la generación de claves
     */
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}