package io.github.realguystuff.ChattServer;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Scanner;

public class Client {
    private final Socket socket;
    private BufferedReader buffReader;
    private BufferedWriter buffWriter;
    private final String username;
    private static final String version = "1.0.0";

    public Client(Socket socket, String username) {
        try {
            this.socket = socket;
            this.buffWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.buffReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.username = username;
        } catch (IOException e) {
            System.err.println("Error CL1");
            closeAll(socket, buffReader, buffWriter);
            throw new RuntimeException(e);
        }
    }

    public void sendMessage() {
        try {
            buffWriter.write(username);
            buffWriter.newLine();
            buffWriter.flush();

            Scanner sc = new Scanner(System.in);

            while (socket.isConnected()) {
                String messageToSend = sc.nextLine();
                if (Objects.equals(messageToSend, "/help") || Objects.equals(messageToSend, "/?")) {
                    System.out.println("[CLIENT]: Here are a list of commands and what they do:");
                    System.out.println("[CLIENT]: ---------------------------------------------");
                    System.out.println("[CLIENT]: | /help     | Gives this list. Aliases: /?  |");
                    System.out.println("[CLIENT]: | /ip       | Tells you what IP are you on. |");
                    System.out.println("[CLIENT]: | /whoami   | Tells you your username.      |");
                    System.out.println("[CLIENT]: | /rickroll | Gives rickroll links.         |");
                    System.out.println("[CLIENT]: | /version  | Gives the current version.    |");
                    System.out.println("[CLIENT]: ---------------------------------------------");
                } else if (Objects.equals(messageToSend, "/whoami")) {
                    System.out.println("[CLIENT]: You are \""+username+"\".");
                } else if (Objects.equals(messageToSend, "/rickroll")) {
                    System.out.println("[CLIENT]: Use it wisely (don't use this if they're smart; they can also use /rickroll):");
                    System.out.println("[CLIENT]: Official Music Video: https://www.youtube.com/watch?v=dQw4w9WgXcQ");
                    System.out.println("[CLIENT]: Different link #1: https://www.youtube.com/watch?v=iik25wqIuFo");
                    System.out.println("[CLIENT]: Different link #2: https://www.youtube.com/watch?v=xvFZjo5PgG0");
                    System.out.println("[CLIENT]: Different link #3: ttps://www.youtube.com/watch?v=8ybW48rKBME");
                    System.out.println("[CLIENT]: Different link #4: https://www.youtube.com/watch?v=p7YXXieghto");
                    System.out.println("[CLIENT]: Different link #5: https://www.youtube.com/watch?v=QB7ACr7pUuE");
                } else if (Objects.equals(messageToSend, "/version")) {
                    System.out.println("[CLIENT]: You are running client version "+version);
                } else {
                    buffWriter.write(username + ": " + messageToSend);
                    buffWriter.newLine();
                    buffWriter.flush();
                }
            }
        } catch (IOException e) {
            System.err.println("Error CL2");
            closeAll(socket, buffReader, buffWriter);
            throw new RuntimeException(e);
        }
    }

    public void readMessage() {
        new Thread(() -> {
            String msgFromGroupChat;
            while (socket.isConnected()) {
                try {
                    msgFromGroupChat = buffReader.readLine();
                    System.out.println(msgFromGroupChat);
                } catch (IOException e) {
                    System.err.println("Error CL3");
                    closeAll(socket, buffReader, buffWriter);
                    throw new RuntimeException(e);
                }
            }
        }).start();
    }

    public void closeAll(Socket socket, BufferedReader buffReader, BufferedWriter buffWriter) {
        try {
            if (buffReader != null) {
                buffReader.close();
            }
            if (buffWriter != null) {
                buffWriter.close();
            }
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            System.err.println("Error CL4");
            closeAll(socket, buffReader, buffWriter);
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, SQLException, ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
        System.out.println("Running client version "+version);
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter your username:");
        String username = sc.nextLine();
        System.out.println("Enter your password:");
        String password = sc.nextLine();

        // Hash the password using SHA-512 algorithm
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        String hashedPasswordStr = Arrays.toString(md.digest(password.getBytes()));

        // Perform the database check using the username and hashed password
        boolean isValidUser = checkCredentials(username, hashedPasswordStr);

        if (isValidUser) {
            System.out.println("Authentication successful!");
            System.out.println("Enter the IP address you want to join (do not add :5000 to the end of the IP):");
            String ip = sc.nextLine();

            try {
                System.out.println("Connecting you to " + ip + ":5000 as " + username + "...");
                Socket socket = new Socket(ip, 5000);
                Client client = new Client(socket, username);
                System.out.println("Connection successful!");
                client.readMessage();
                client.sendMessage();
            } catch (UnknownHostException e) {
                System.err.println("Error CL5: UnknownHostException");
                e.printStackTrace();
                System.out.println("hint: CL5 usually means that you have typed in the IP wrong (maybe you added \":5000\").");
                main(args);
            }
        } else {
            System.out.println("Error CL6: AuthenticationException");
            System.out.println("hint: CL6 usually means that you have typed in your username or password wrong, or the username doesn't exist in the database (try signing UP on the website)");
        }
    }

    public static boolean checkCredentials(String username, String hashedPassword) throws SQLException, ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
        Database database = new Database();
        ResultSet resultSet = database.call("SELECT * FROM users WHERE username = '" + username + "' AND pw = '" + hashedPassword + "'");
        return resultSet.next();
    }
}
